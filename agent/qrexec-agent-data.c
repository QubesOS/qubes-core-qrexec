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

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE 1
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <libvchan.h>

#include "qrexec.h"
#include "libqrexec-utils.h"
#include "qrexec-agent.h"

#define VCHAN_BUFFER_SIZE 65536

static volatile int child_exited;
static volatile int stdio_socket_requested;
int stdout_msg_type = MSG_DATA_STDOUT;
pid_t child_process_pid;
int remote_process_status = 0;

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

    if (info.version != QREXEC_PROTOCOL_VERSION) {
        fprintf(stderr, "Incompatible agent protocol version (remote %d, local %d)\n", info.version, QREXEC_PROTOCOL_VERSION);
        return -1;
    }


    return 0;
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
static int handle_input(libvchan_t *vchan, int fd, int msg_type)
{
    char buf[MAX_DATA_CHUNK];
    ssize_t len;
    struct msg_header hdr;

    static_assert(SSIZE_MAX >= INT_MAX, "can't happen on Linux");
    hdr.type = msg_type;
    while (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
        len = libvchan_buffer_space(vchan)-sizeof(struct msg_header);
        static_assert(sizeof(buf) <= SSIZE_MAX, "impossible");
        static_assert(sizeof(buf) <= INT_MAX, "impossible");
        static_assert(sizeof(buf) <= UINT32_MAX, "impossible");
        if (len > (int)sizeof(buf))
            len = sizeof(buf);
        len = read(fd, buf, len);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1;
            else
                return -1;
        }
        hdr.len = (uint32_t)len;
        if (libvchan_send(vchan, &hdr, sizeof(hdr)) < 0)
            return -1;

        if (len && !write_vchan_all(vchan, buf, len))
            return -1;

        if (len == 0) {
            /* restore flags */
            set_block(fd);
            if (shutdown(fd, SHUT_RD) < 0) {
                if (errno == ENOTSOCK)
                    close(fd);
            }
            return 0;
        }
    }
    return 1;
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
        struct buffer *stdin_buf)
{
    struct msg_header hdr;
    char buf[MAX_DATA_CHUNK];

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

    while (libvchan_data_ready(data_vchan) > 0) {
        if (libvchan_recv(data_vchan, &hdr, sizeof(hdr)) < 0)
            return -1;
        if (hdr.len > MAX_DATA_CHUNK) {
            fprintf(stderr, "Too big data chunk received: %d > %d\n",
                    hdr.len, MAX_DATA_CHUNK);
            return -1;
        }
        if (!read_vchan_all(data_vchan, buf, hdr.len))
            return -1;

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
                    return 0;
                } else {
                    switch (write_stdin(stdin_fd, buf, hdr.len, stdin_buf)) {
                        case WRITE_STDIN_OK:
                            break;
                        case WRITE_STDIN_BUFFERED:
                            return 1;
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
                            return 0;
                    }
                }
                break;
            case MSG_DATA_STDERR:
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
                return -2;
        }
    }
    return 1;
}

static int process_child_io(libvchan_t *data_vchan,
        int stdin_fd, int stdout_fd, int stderr_fd)
{
    fd_set rdset, wrset;
    int vchan_fd;
    sigset_t selectmask;
    int child_process_status = child_process_pid ? -1 : 0;
    int remote_process_status = -1;
    int ret, max_fd;
    struct timespec zero_timeout = { 0, 0 };
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
        if (stdio_socket_requested) {
            if (stdout_fd != -1) {
                do
                    errno = 0;
                while (dup3(stdin_fd, stdout_fd, O_CLOEXEC) &&
                       (errno == EINTR || errno == EBUSY));
                // other errors are fatal
                assert(!errno);
            } else {
                stdout_fd = fcntl(stdin_fd, F_DUPFD_CLOEXEC, 3);
                // all errors are fatal
                assert(stdout_fd >= 3);
            }
            stdio_socket_requested = 0;
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
            ret = pselect(max_fd + 1, &rdset, &wrset, NULL, NULL, &selectmask);
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
        switch (handle_remote_data(data_vchan, stdin_fd, &remote_process_status, &stdin_buf)) {
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
            switch (handle_input(data_vchan, stdout_fd, stdout_msg_type)) {
                case -1:
                    handle_vchan_error("send");
                    break;
                case 0:
                    stdout_fd = -1;
                    break;
            }
        }
        if (stderr_fd >= 0 && FD_ISSET(stderr_fd, &rdset)) {
            switch (handle_input(data_vchan, stderr_fd, MSG_DATA_STDERR)) {
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

#define QUBES_MAX_SERVICE_NAME_LEN 32ULL
#define QUBES_MAX_SERVICE_ARG_LEN 32ULL
#define QUBES_MAX_SERVICE_DESCRIPTOR_LEN \
    (QUBES_MAX_SERVICE_NAME_LEN + QUBES_MAX_SERVICE_ARG_LEN + 1ULL)
#define QUBES_SOCKADDR_UN_MAX_PATH_LEN  \
    (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#define MAKE_STRUCT(x) \
    x("/usr/local/etc/qubes-rpc/") \
    x("/etc/qubes-rpc/")
static const struct Q {
    const char *const string;
    size_t const length;
} paths[] = {
#define S(z) { .string = z, .length = sizeof(z) - 1 },
    MAKE_STRUCT(S)
#undef S
};
static_assert(sizeof("/etc/qubes-rpc/") == 16, "impossible");
static_assert(sizeof("/usr/local/etc/qubes-rpc/") == 26, "impossible");
static_assert(QUBES_MAX_SERVICE_DESCRIPTOR_LEN == 65,
        "bad macro definition");
#define S(z) \
    static_assert(sizeof(z) + QUBES_MAX_SERVICE_DESCRIPTOR_LEN <= QUBES_SOCKADDR_UN_MAX_PATH_LEN, \
            "Path too long: " #z);
MAKE_STRUCT(S)
#undef S
#undef MAKE_STRUCT

#if QUBES_MAX_SERVICE_DESCRIPTOR_LEN > PTRDIFF_MAX
#error impossible
#endif

static char *parse_qrexec_argument_from_commandline(char *cmdline) {
    char *end_user;
    uintptr_t user_len;
    if (!qrexec_is_fork_server) {
        end_user = strchr(cmdline, ':');
        if (!end_user) {
            fputs("Bad command from dom0: no colon\n", stderr);
            abort();
        }
        end_user++;
    } else {
        end_user = cmdline;
    }

    user_len = (uintptr_t)end_user - (uintptr_t)cmdline;
    if (user_len > PTRDIFF_MAX) {
        fputs("absurd user length\n", stderr);
        abort();
    }

    if (strncmp(end_user, RPC_REQUEST_COMMAND " ", RPC_REQUEST_COMMAND_LEN + 1) != 0)
        return NULL;
    return end_user + RPC_REQUEST_COMMAND_LEN + 1;
}


static int execute_qubes_rpc_command(char *cmdline, int *pid, int *stdin_fd, int *stdout_fd, int *stderr_fd) {
    int s = -1;
    struct sockaddr_un remote = { .sun_family = AF_UNIX };
    char *realcmd, *remote_domain;
    size_t path_length;
    static_assert(sizeof remote.sun_path == QUBES_SOCKADDR_UN_MAX_PATH_LEN,
                  "I screwed up my math");
#ifndef NDEBUG
    fprintf(stderr, "%s\n", cmdline);
#endif
    realcmd = parse_qrexec_argument_from_commandline(cmdline);
#ifndef NDEBUG
    fprintf(stderr, "%s\n", realcmd);
#endif
    if (!realcmd) {
        do_fork_exec(cmdline, pid, stdin_fd, stdout_fd, stderr_fd);
        return 0;
    }
    remote_domain = strchr(realcmd, ' ');
    if (!remote_domain) {
        fputs("Bad command from dom0: no remote domain\n", stderr);
        abort();
    }
    *remote_domain++ = '\0';
    path_length = strlen(realcmd);
    if (path_length > QUBES_MAX_SERVICE_DESCRIPTOR_LEN) {
        fputs("Absurdly long command\n", stderr);
        return -1;
    }
    char const *const delimiter = memchr(realcmd, '+', path_length);
    size_t const service_length = delimiter ?
        (size_t)(delimiter - realcmd) : path_length;
    size_t const argument_length = delimiter ?
        path_length - service_length - 1 : (size_t)-1;
#define FAIL(msg, err) do { \
    fputs((msg "\n"), stderr); \
    errno = (0 ? ((void)(msg), 0) : (err)); \
    return -1; \
} while (0)

    if (argument_length + 1 > QUBES_MAX_SERVICE_ARG_LEN + 1) {
        FAIL("Service argument too long", E2BIG);
    } else if (!service_length) {
        FAIL("Service path empty", EINVAL);
    } else if (service_length > QUBES_MAX_SERVICE_NAME_LEN) {
        FAIL("Service path too long", ENAMETOOLONG);
    } else if (path_length > QUBES_MAX_SERVICE_DESCRIPTOR_LEN) {
        assert(false && "impossible");
        abort();
    }
#undef FAIL

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    for (int use_bare_path = 0; use_bare_path < 2; ++use_bare_path) {
        for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
            size_t const directory_length = paths[i].length;
            assert(sizeof remote.sun_path > path_length + directory_length);

            // The total size of the path (not including NUL terminator).
            size_t const total_path_length = directory_length +
                (use_bare_path ? service_length : path_length);
            memcpy(remote.sun_path, paths[i].string, directory_length);
            memcpy(remote.sun_path + directory_length, realcmd, path_length);
            remote.sun_path[total_path_length] = '\0';
            socklen_t socket_len = (socklen_t)(
                offsetof(struct sockaddr_un, sun_path) + total_path_length + 1);
            if (!connect(s, (struct sockaddr *) &remote, socket_len)) {
                *stdout_fd = *stdin_fd = s;
                *stderr_fd = -1;
                *pid = 0;
                set_nonblock(s);
                return 0;
            }
            switch (errno) {
            // These cannot happen
            case EFAULT:       // all of our parameters are in valid memory
            case EINVAL:       // we passed valid parameters
            case ENOTSOCK:     // ditto
            case ENETUNREACH:  // cannot happen for AF_UNIX
            case EADDRNOTAVAIL:// cannot happen for AF_UNIX
            case EINPROGRESS:  // this socket is blocking
            case EBADF:        // `s` was created by a call to `socket()`
            case EAFNOSUPPORT: // the kernel supports AF_UNIX
            case EALREADY:     // ditto
                abort();
            // These should not happen
            case EAGAIN:       // ditto
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:  // ditto
#endif
                // Probably a misbehaving FUSE filesystem
                break;
            case EINTR:
                // Interrupted by a signal - retry
                --i; // to retry loop iteration
                continue;
            case ENOENT:
            case EISDIR:
            case ENOTDIR:
            case EIO:
                // These errors could also happen with `execve()`
                break;
            case EPROTOTYPE:
            case ETIMEDOUT:
                // Socket server problem.  Fail the whole connection.
                // (We do not want to fall back because the user may have
                // overriden behavior for security reasons, and because
                // fail-fast is much easier to debug).
                goto fail;
            case EACCES:
            case EPERM:
            case ECONNREFUSED:
                remote_domain[-1] = ' ';
                fprintf(stderr, "Executing command as normal: '%s'\n", cmdline);
                close(s);
                do_fork_exec(cmdline, pid, stdin_fd, stdout_fd, stderr_fd);
                return 0;
            default:
                /* Unexpected error */
                break;
            }
        }
    }
fail:
    if (s > 0)
        close(s);
    return -1;
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

    if (type != MSG_SERVICE_CONNECT) {
        assert(cmdline != NULL);
        assert(cmdline_len > 0);
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
    handle_handshake(data_vchan);

    prepare_child_env();
    /* TODO: use setresuid to allow child process to actually send the signal? */

    switch (type) {
        case MSG_JUST_EXEC:
            send_exit_code(data_vchan, handle_just_exec(cmdline));
            break;
        case MSG_EXEC_CMDLINE:
            if (execute_qubes_rpc_command(cmdline, &pid, &stdin_fd, &stdout_fd, &stderr_fd) < 0)
                fputs("failed to spawn process\n", stderr);
            fprintf(stderr, "executed %s pid %d\n", cmdline, pid);
            child_process_pid = pid;
            exit_code = process_child_io(data_vchan, stdin_fd, stdout_fd, stderr_fd);
            fprintf(stderr, "pid %d exited with %d\n", pid, exit_code);
            break;
        case MSG_SERVICE_CONNECT:
            child_process_pid = 0;
            stdout_msg_type = MSG_DATA_STDIN;
            exit_code = process_child_io(data_vchan, stdin_fd, stdout_fd, stderr_fd);
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

/* Local Variables: */
/* mode: c */
/* indent-tabs-mode: nil */
/* c-basic-offset: 4 */
/* coding: utf-8-unix */
/* End: */
