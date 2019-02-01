/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2013  Marek Marczykowski-Górecki  <marmarek@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <libvchan.h>
#include <assert.h>
#include <limits.h>

#include "qrexec.h"
#include "libqrexec-utils.h"
#include "qrexec-agent.h"

#define VCHAN_BUFFER_SIZE 65536

#define QREXEC_DATA_MIN_VERSION QREXEC_PROTOCOL_V2

static volatile int child_exited;
static volatile sig_atomic_t stdio_socket_requested;
int stdout_msg_type = MSG_DATA_STDOUT;
pid_t child_process_pid;
int remote_process_status = 0;

/* whether qrexec-client should replace problematic bytes with _ before printing the output;
 * positive value will enable the feature
 */
int replace_chars_stdout = -1;
int replace_chars_stderr = -1;

void do_replace_chars(char *buf, int len) {
    int i;
    unsigned char c;

    for (i = 0; i < len; i++) {
        c = buf[i];
        if ((c < '\040' || c > '\176') &&  /* not printable ASCII */
            (c != '\t') &&                 /* not tab */
            (c != '\n') &&                 /* not newline */
            (c != '\r') &&                 /* not return */
            (c != '\b') &&                 /* not backspace */
            (c != '\a'))                   /* not bell */
            buf[i] = '_';
    }
}

static void sigchld_handler(int __attribute__((__unused__))x)
{
    child_exited = 1;
}

static void sigusr1_handler(int __attribute__((__unused__))x)
{
    stdio_socket_requested = 1;
    signal(SIGUSR1, SIG_IGN);
}

void prepare_child_env() {
    char pid_s[10];

    signal(SIGCHLD, sigchld_handler);
    signal(SIGUSR1, sigusr1_handler);
    int res = snprintf(pid_s, sizeof(pid_s), "%d", getpid());
    if (res < 0) abort();
    if (res >= (int)sizeof(pid_s)) abort();
    if (setenv("QREXEC_AGENT_PID", pid_s, 1)) abort();
}

int handle_handshake(libvchan_t *ctrl)
{
    struct msg_header hdr;
    struct peer_info info;
    int actual_version;

    /* send own HELLO */
    hdr.type = MSG_HELLO;
    hdr.len = sizeof(info);
    info.version = QREXEC_PROTOCOL_VERSION;

    if (libvchan_send(ctrl, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr, "Failed to send HELLO hdr to agent\n");
        return -1;
    }

    if (libvchan_send(ctrl, &info, sizeof(info)) != sizeof(info)) {
        fprintf(stderr, "Failed to send HELLO hdr to agent\n");
        return -1;
    }

    /* receive MSG_HELLO from remote */
    if (libvchan_recv(ctrl, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr, "Failed to read agent HELLO hdr\n");
        return -1;
    }

    if (hdr.type != MSG_HELLO || hdr.len != sizeof(info)) {
        fprintf(stderr, "Invalid HELLO packet received: type %d, len %d\n", hdr.type, hdr.len);
        return -1;
    }

    if (libvchan_recv(ctrl, &info, sizeof(info)) != sizeof(info)) {
        fprintf(stderr, "Failed to read agent HELLO body\n");
        return -1;
    }

    actual_version = info.version < QREXEC_PROTOCOL_VERSION ? info.version : QREXEC_PROTOCOL_VERSION;

    if (actual_version < QREXEC_DATA_MIN_VERSION) {
        fprintf(stderr, "Incompatible agent protocol version (remote %d, local %d)\n", info.version, QREXEC_PROTOCOL_VERSION);
        return -1;
    }

    return actual_version;
}


static int handle_just_exec(char *cmdline)
{
    int fdn, pid;

    switch (pid = fork()) {
        case -1:
            perror("fork");
            return -1;
        case 0:
            fdn = open("/dev/null", O_RDWR);
            fix_fds(fdn, fdn, fdn);
            do_exec(cmdline);
        default:;
    }
    fprintf(stderr, "executed (nowait) %s pid %d\n", cmdline, pid);
    return 0;
}

static void send_exit_code(libvchan_t *data_vchan, int status)
{
    struct msg_header hdr;
    hdr.type = MSG_DATA_EXIT_CODE;
    hdr.len = sizeof(status);
    if (libvchan_send(data_vchan, &hdr, sizeof(hdr)) < 0)
        handle_vchan_error("write hdr");
    if (libvchan_send(data_vchan, &status, sizeof(status)) < 0)
        handle_vchan_error("write status");
    fprintf(stderr, "send exit code %d\n", status);
}

/* handle data from specified FD and send over vchan link
 * Return:
 *  -1 - vchan error occurred
 *  0 - EOF received, do not attempt to access this FD again
 *  1 - some data processed, call it again when buffer space and more data
 *      available
 */
static int handle_input(libvchan_t *vchan, int fd, int msg_type, int data_protocol_version)
{
    const size_t max_len = max_data_chunk_size(data_protocol_version);
    char *buf;
    ssize_t len;
    struct msg_header hdr;
    int rc = -1;

    buf = malloc(max_len);
    if (!buf) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    static_assert(SSIZE_MAX >= INT_MAX, "can't happen on Linux");
    hdr.type = msg_type;
    while (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
        len = libvchan_buffer_space(vchan)-sizeof(struct msg_header);
        if ((size_t)len > max_len)
            len = max_len;
        len = read(fd, buf, len);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                rc = 1;
            /* otherwise keep rc = -1 */
            goto out;
        }
        hdr.len = (uint32_t)len;
        if (libvchan_send(vchan, &hdr, sizeof(hdr)) < 0)
            goto out;

        if (len && !write_vchan_all(vchan, buf, len))
            goto out;

        if (len == 0) {
            /* restore flags */
            if (stdio_socket_requested < 2)
                set_block(fd);
            if (shutdown(fd, SHUT_RD) < 0) {
                if (errno == ENOTSOCK)
                    close(fd);
            }
            rc = 0;
            goto out;
        }
    }
    rc = 1;
out:
    free(buf);
    return rc;
}

/* handle data from vchan and send it to specified FD
 * Return:
 *  -2 - remote process terminated, do not send more data to it
 *       in this case "status" will be set
 *  -1 - vchan error occurred
 *  0 - EOF received, do not attempt to access this FD again
 *  1 - maybe some data processed, call it again when buffer space and more data
 *      available
 */

static int handle_remote_data(libvchan_t *data_vchan, int stdin_fd, int *status,
        struct buffer *stdin_buf, int data_protocol_version)
{
    struct msg_header hdr;
    const size_t max_len = max_data_chunk_size(data_protocol_version);
    char *buf;
    int rc = -1;

    /* do not receive any data if we have something already buffered */
    switch (flush_client_data(stdin_fd, stdin_buf)) {
        case WRITE_STDIN_OK:
            break;
        case WRITE_STDIN_BUFFERED:
            return 1;
        case WRITE_STDIN_ERROR:
            perror("write");
            return 0;
    }

    buf = malloc(max_len);
    if (!buf) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    while (libvchan_data_ready(data_vchan) > 0) {
        if (libvchan_recv(data_vchan, &hdr, sizeof(hdr)) < 0)
            goto out;
        if (hdr.len > max_len) {
            fprintf(stderr, "Too big data chunk received: %" PRIu32 " > %zu\n",
                    hdr.len, max_len);
            goto out;
        }
        if (!read_vchan_all(data_vchan, buf, hdr.len))
            goto out;

        switch (hdr.type) {
            /* handle both directions because this can be either server or client
             * of VM-VM connection */
            case MSG_DATA_STDIN:
            case MSG_DATA_STDOUT:
                if (stdin_fd < 0)
                    /* discard the data */
                    continue;
                if (hdr.len == 0) {
                    /* restore flags */
                    set_block(stdin_fd);
                    if (!child_process_pid || stdin_fd == 1 ||
                            (shutdown(stdin_fd, SHUT_WR) == -1 &&
                             errno == ENOTSOCK)) {
                        close(stdin_fd);
                    }
                    stdin_fd = -1;
                    rc = 0;
                    goto out;
                } else {
                    if (replace_chars_stdout > 0)
                        do_replace_chars(buf, hdr.len);
                    switch (write_stdin(stdin_fd, buf, hdr.len, stdin_buf)) {
                        case WRITE_STDIN_OK:
                            break;
                        case WRITE_STDIN_BUFFERED:
                            rc = 1;
                            goto out;
                        case WRITE_STDIN_ERROR:
                            if (errno == EPIPE || errno == ECONNRESET) {
                                if (!child_process_pid || stdin_fd == 1 ||
                                        (shutdown(stdin_fd, SHUT_WR) == -1 &&
                                         errno == ENOTSOCK)) {
                                    close(stdin_fd);
                                }
                                stdin_fd = -1;
                            } else {
                                perror("write");
                            }
                            rc = 0;
                            goto out;
                    }
                }
                break;
            case MSG_DATA_STDERR:
                if (replace_chars_stderr > 0)
                    do_replace_chars(buf, hdr.len);
                /* stderr of remote service, log locally */
                if (!write_all(2, buf, hdr.len)) {
                    perror("write");
                    /* only log the error */
                }
                break;
            case MSG_DATA_EXIT_CODE:
                /* remote process exited, so there is no sense to send any data
                 * to it */
                if (hdr.len < sizeof(*status))
                    *status = 255;
                else
                    memcpy(status, buf, sizeof(*status));
                rc = -2;
                goto out;
        }
    }
    rc = 1;
out:
    free(buf);
    return rc;
}

static int process_child_io(libvchan_t *data_vchan,
        int stdin_fd, int stdout_fd, int stderr_fd,
        int data_protocol_version)
{
    fd_set rdset, wrset;
    int vchan_fd;
    sigset_t selectmask;
    int child_process_status = child_process_pid ? -1 : 0;
    int remote_process_status = -1;
    int ret, max_fd;
    struct timespec zero_timeout = { 0, 0 };
    struct timespec normal_timeout = { 10, 0 };
    struct buffer stdin_buf;

    sigemptyset(&selectmask);
    sigaddset(&selectmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &selectmask, NULL);
    sigemptyset(&selectmask);

    set_nonblock(stdin_fd);
    if (stdout_fd != stdin_fd)
        set_nonblock(stdout_fd);
    else if ((stdout_fd = fcntl(stdin_fd, F_DUPFD_CLOEXEC, 3)) < 0)
        abort(); // not worth handling running out of file descriptors
    if (stderr_fd >= 0)
        set_nonblock(stderr_fd);

    buffer_init(&stdin_buf);
    while (1) {
        if (child_exited) {
            int status;
            if (child_process_pid &&
                    waitpid(child_process_pid, &status, WNOHANG) > 0) {
                if (WIFSIGNALED(status))
                    child_process_status = 128 + WTERMSIG(status);
                else
                    child_process_status = WEXITSTATUS(status);
                if (stdin_fd >= 0) {
                    /* restore flags */
                    set_block(stdin_fd);
                    if (!child_process_pid || stdin_fd == 1 ||
                            (shutdown(stdin_fd, SHUT_WR) == -1 &&
                             errno == ENOTSOCK)) {
                        close(stdin_fd);
                    }
                    stdin_fd = -1;
                }
            }
            child_exited = 0;
        }

        /* if all done, exit the loop */
        if ((!child_process_pid || child_process_status > -1) &&
                (child_process_pid || remote_process_status > -1) &&
                stdin_fd == -1 && stdout_fd == -1 && stderr_fd == -1) {
            if (child_process_status > -1) {
                send_exit_code(data_vchan, child_process_status);
            }
            break;
        }
        /* also if vchan is disconnected (and we processed all the data), there
         * is no sense of processing further data */
        if (!libvchan_data_ready(data_vchan) &&
                !libvchan_is_open(data_vchan) &&
                !buffer_len(&stdin_buf)) {
            break;
        }
        /* child signaled desire to use single socket for both stdin and stdout */
        if (stdio_socket_requested == 1) {
            if (stdout_fd != -1) {
                do
                    errno = 0;
                while (dup3(stdin_fd, stdout_fd, O_CLOEXEC) &&
                       (errno == EINTR || errno == EBUSY));
                // other errors are fatal
                if (errno) {
                    fputs("Fatal error from dup3()\n", stderr);
                    abort();
                }
            } else {
                stdout_fd = fcntl(stdin_fd, F_DUPFD_CLOEXEC, 3);
                // all errors are fatal
                if (stdout_fd < 3)
                    abort();
            }
            stdio_socket_requested = 2;
        }
        /* otherwise handle the events */

        FD_ZERO(&rdset);
        FD_ZERO(&wrset);
        max_fd = -1;
        vchan_fd = libvchan_fd_for_select(data_vchan);
        if (libvchan_buffer_space(data_vchan) > (int)sizeof(struct msg_header)) {
            if (stdout_fd >= 0) {
                FD_SET(stdout_fd, &rdset);
                if (stdout_fd > max_fd)
                    max_fd = stdout_fd;
            }
            if (stderr_fd >= 0) {
                FD_SET(stderr_fd, &rdset);
                if (stderr_fd > max_fd)
                    max_fd = stderr_fd;
            }
        }
        FD_SET(vchan_fd, &rdset);
        if (vchan_fd > max_fd)
            max_fd = vchan_fd;
        /* if we have something buffered for the child process, wake also on
         * writable stdin */
        if (stdin_fd > -1 && buffer_len(&stdin_buf)) {
            FD_SET(stdin_fd, &wrset);
            if (stdin_fd > max_fd)
                max_fd = stdin_fd;
        }

        if (!buffer_len(&stdin_buf) && libvchan_data_ready(data_vchan) > 0) {
            /* check for other FDs, but exit immediately */
            ret = pselect(max_fd + 1, &rdset, &wrset, NULL, &zero_timeout, &selectmask);
        } else
            ret = pselect(max_fd + 1, &rdset, &wrset, NULL, &normal_timeout, &selectmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            else {
                perror("pselect");
                /* TODO */
                break;
            }
        }

        /* clear event pending flag */
        if (FD_ISSET(vchan_fd, &rdset)) {
            if (libvchan_wait(data_vchan) < 0)
                handle_vchan_error("wait");
        }

        /* handle_remote_data will check if any data is available */
        switch (handle_remote_data(data_vchan, stdin_fd,
                    &remote_process_status,
                    &stdin_buf,
                    data_protocol_version)) {
            case -1:
                handle_vchan_error("read");
                break;
            case 0:
                stdin_fd = -1;
                break;
            case -2:
                /* remote process exited, no sense in sending more data to it;
                 * be careful to not shutdown socket inherited from parent */
                if (!child_process_pid || stdout_fd == 0 ||
                        (shutdown(stdout_fd, SHUT_RD) == -1 &&
                         errno == ENOTSOCK)) {
                    close(stdout_fd);
                }
                stdout_fd = -1;
                close(stderr_fd);
                stderr_fd = -1;
                /* if we do not care for any local process, return remote process code */
                if (child_process_pid == 0)
                    return remote_process_status;
                break;
        }
        if (stdout_fd >= 0 && FD_ISSET(stdout_fd, &rdset)) {
            switch (handle_input(data_vchan, stdout_fd, stdout_msg_type,
                        data_protocol_version)) {
                case -1:
                    handle_vchan_error("send");
                    break;
                case 0:
                    stdout_fd = -1;
                    break;
            }
        }
        if (stderr_fd >= 0 && FD_ISSET(stderr_fd, &rdset)) {
            switch (handle_input(data_vchan, stderr_fd, MSG_DATA_STDERR,
                        data_protocol_version)) {
                case -1:
                    handle_vchan_error("send");
                    break;
                case 0:
                    stderr_fd = -1;
                    break;
            }
        }
    }
    /* make sure that all the pipes/sockets are closed, so the child process
     * (if any) will know that the connection is terminated */
    if (stdout_fd != -1) {
        /* restore flags */
        set_block(stdout_fd);
        /* be careful to not shutdown socket inherited from parent */
        if (!child_process_pid || stdout_fd == 0 ||
                (shutdown(stdout_fd, SHUT_RD) == -1 && errno == ENOTSOCK)) {
            close(stdout_fd);
        }
        stdout_fd = -1;
    }
    if (stdin_fd != -1) {
        /* restore flags */
        set_block(stdin_fd);
        /* be careful to not shutdown socket inherited from parent */
        if (!child_process_pid || stdin_fd == 1 ||
                (shutdown(stdin_fd, SHUT_WR) == -1 && errno == ENOTSOCK)) {
            close(stdin_fd);
        }
        stdin_fd = -1;
    }
    if (stderr_fd != -1) {
        /* restore flags */
        set_block(stderr_fd);
        close(stderr_fd);
        stderr_fd = -1;
    }
    if (child_process_pid == 0)
        return remote_process_status;
    return child_process_status;
}

/* Behaviour depends on type parameter:
 *  MSG_SERVICE_CONNECT - create vchan server, pass the data to/from given FDs
 *    (stdin_fd, stdout_fd, stderr_fd), then return remote process exit code
 *  MSG_JUST_EXEC - connect to vchan server, fork+exec process given by cmdline
 *    parameter, send artificial exit code "0" (local process can still be
 *    running), then return 0
 *  MSG_EXEC_CMDLINE - connect to vchan server, fork+exec process given by
 *    cmdline parameter, pass the data to/from that process, then return local
 *    process exit code
 *
 *  buffer_size is about vchan buffer allocated (only for vchan server cases),
 *  use 0 to use built-in default (64k); needs to be power of 2
 */
static int handle_new_process_common(int type, int connect_domain, int connect_port,
                char *cmdline, size_t cmdline_len, /* MSG_JUST_EXEC and MSG_EXEC_CMDLINE */
                int stdin_fd, int stdout_fd, int stderr_fd /* MSG_SERVICE_CONNECT */,
                int buffer_size)
{
    libvchan_t *data_vchan;
    int exit_code = 0;
    pid_t pid;
    int data_protocol_version;

    if (type != MSG_SERVICE_CONNECT) {
        assert(cmdline != NULL);
        cmdline[cmdline_len-1] = 0;
    }

    if (buffer_size == 0)
        buffer_size = VCHAN_BUFFER_SIZE;

    if (type == MSG_SERVICE_CONNECT) {
        data_vchan = libvchan_server_init(connect_domain, connect_port,
                buffer_size, buffer_size);
        if (data_vchan)
            libvchan_wait(data_vchan);
    } else {
        data_vchan = libvchan_client_init(connect_domain, connect_port);
    }
    if (!data_vchan) {
        fprintf(stderr, "Data vchan connection failed\n");
        exit(1);
    }
    data_protocol_version = handle_handshake(data_vchan);

    prepare_child_env();
    /* TODO: use setresuid to allow child process to actually send the signal? */

    switch (type) {
        case MSG_JUST_EXEC:
            send_exit_code(data_vchan, handle_just_exec(cmdline));
            break;
        case MSG_EXEC_CMDLINE:
            do_fork_exec(cmdline, &pid, &stdin_fd, &stdout_fd, &stderr_fd);
            fprintf(stderr, "executed %s pid %d\n", cmdline, pid);
            child_process_pid = pid;
            exit_code = process_child_io(
                    data_vchan, stdin_fd, stdout_fd, stderr_fd,
                    data_protocol_version);
            fprintf(stderr, "pid %d exited with %d\n", pid, exit_code);
            break;
        case MSG_SERVICE_CONNECT:
            child_process_pid = 0;
            stdout_msg_type = MSG_DATA_STDIN;
            exit_code = process_child_io(
                    data_vchan, stdin_fd, stdout_fd, stderr_fd,
                    data_protocol_version);
            break;
    }
    libvchan_close(data_vchan);
    return exit_code;
}

/* Returns PID of data processing process */
pid_t handle_new_process(int type, int connect_domain, int connect_port,
        char *cmdline, size_t cmdline_len)
{
    int exit_code;
    pid_t pid;
    assert(type != MSG_SERVICE_CONNECT);

    switch (pid=fork()){
        case -1:
            perror("fork");
            return -1;
        case 0:
            break;
        default:
            return pid;
    }

    /* child process */
    exit_code = handle_new_process_common(type, connect_domain, connect_port,
            cmdline, cmdline_len,
            -1, -1, -1, 0);

    exit(exit_code);
    /* suppress warning */
    return 0;
}

/* Returns exit code of remote process */
int handle_data_client(int type, int connect_domain, int connect_port,
                int stdin_fd, int stdout_fd, int stderr_fd, int buffer_size)
{
    int exit_code;

    assert(type == MSG_SERVICE_CONNECT);

    exit_code = handle_new_process_common(type, connect_domain, connect_port,
            NULL, 0, stdin_fd, stdout_fd, stderr_fd, buffer_size);
    return exit_code;
}
