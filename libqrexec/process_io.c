/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2020 Paweł Marczewski <pawel@invisiblethingslab.com>
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

#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libqrexec-utils.h"

static _Noreturn void handle_vchan_error(const char *op)
{
    LOG(ERROR, "Error while vchan %s, exiting", op);
    exit(1);
}

/*
 * Closing the file descriptors:
 *
 * - Use shutdown(), except if this is a FD inherited from parent (detected by
 *   FD number)
 * - Restore blocking status, unless this is a duplicated stdio socket for
 *   stdout/stderr (in which case we can't restore it just for one FD, but we
 *   don't care, because we created it)
 */

static void close_stdin(int fd, bool restore_block) {
    if (fd == -1)
        return;

    if (restore_block)
        set_block(fd);

    if (fd == 1) {
        close(fd);
    } else if (shutdown(fd, SHUT_WR) == -1) {
        if (errno == ENOTSOCK)
            close(fd);
        else
            PERROR("shutdown close_stdin");
    }
}

static void close_stdout(int fd, bool restore_block) {
    if (fd == -1)
        return;

    if (restore_block)
        set_block(fd);

    if (fd == 0) {
        close(fd);
    } else if (shutdown(fd, SHUT_RD) == -1) {
        if (errno == ENOTSOCK)
            close(fd);
        else
            PERROR("shutdown close_stdout");
    }
}

static void close_stderr(int fd) {
    if (fd == -1)
        return;

    set_block(fd);
    close(fd);
}

enum {
    FD_STDIN = 0,
    FD_STDOUT,
    FD_STDERR,
    FD_VCHAN,
    FD_NUM
};

int process_io(const struct process_io_request *req) {
    libvchan_t *vchan = req->vchan;
    int stdin_fd = req->stdin_fd;
    int stdout_fd = req->stdout_fd;
    int stderr_fd = req->stderr_fd;
    struct buffer *stdin_buf = req->stdin_buf;

    bool is_service = req->is_service;
    bool replace_chars_stdout = req->replace_chars_stdout;
    bool replace_chars_stderr = req->replace_chars_stderr;
    int data_protocol_version = req->data_protocol_version;

    pid_t local_pid = req->local_pid;
    volatile sig_atomic_t *sigchld = req->sigchld;
    volatile sig_atomic_t *sigusr1 = req->sigusr1;

    pid_t local_status = -1;
    pid_t remote_status = -1;
    int stdout_msg_type = is_service ? MSG_DATA_STDOUT : MSG_DATA_STDIN;
    bool use_stdio_socket = false;

    int ret;
    struct pollfd fds[FD_NUM];
    sigset_t pollmask;
    struct timespec zero_timeout = { 0, 0 };
    struct timespec normal_timeout = { 10, 0 };

    sigemptyset(&pollmask);
    sigaddset(&pollmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &pollmask, NULL);
    sigemptyset(&pollmask);

    set_nonblock(stdin_fd);
    if (stdout_fd != stdin_fd)
        set_nonblock(stdout_fd);
    else if ((stdout_fd = fcntl(stdin_fd, F_DUPFD_CLOEXEC, 3)) < 0)
        abort(); // not worth handling running out of file descriptors
    if (stderr_fd >= 0)
        set_nonblock(stderr_fd);

    while(1) {
        /* React to SIGCHLD */
        if (*sigchld) {
            int status;
            if (local_pid > 0 && waitpid(local_pid, &status, WNOHANG) > 0) {
                if (WIFSIGNALED(status))
                    local_status = 128 + WTERMSIG(status);
                else
                    local_status = WEXITSTATUS(status);
                if (stdin_fd >= 0) {
                    close_stdin(stdin_fd, !use_stdio_socket);
                    stdin_fd = -1;
                }
            }
            *sigchld = 0;
        }

        /* if all done, exit the loop */
        if (stdin_fd == -1 && stdout_fd == -1 && stderr_fd == -1) {
            if (is_service) {
                /* wait for local process, send exit code */
                if (!local_pid || local_status >= 0) {
                    if (send_exit_code(vchan, local_pid ? local_status : 0) < 0)
                        handle_vchan_error("exit code");
                    break;
                }
            } else {
                /* wait for both local and remote process */
                if ((!local_pid || local_status >= 0) && remote_status >= 0)
                    break;
            }
        }

        /* also if vchan is disconnected (and we processed all the data), there
         * is no sense of processing further data */
        if (!libvchan_data_ready(vchan) &&
                !libvchan_is_open(vchan) &&
                !buffer_len(stdin_buf)) {
            break;
        }

        /* child signaled desire to use single socket for both stdin and stdout */
        if (sigusr1 && *sigusr1) {
            if (stdout_fd != -1) {
                do
                    errno = 0;
                while (dup3(stdin_fd, stdout_fd, O_CLOEXEC) &&
                       (errno == EINTR || errno == EBUSY));
                // other errors are fatal
                if (errno) {
                    PERROR("dup3");
                    abort();
                }
            } else {
                stdout_fd = fcntl(stdin_fd, F_DUPFD_CLOEXEC, 3);
                // all errors are fatal
                if (stdout_fd < 3)
                    abort();
            }
            use_stdio_socket = true;
            *sigusr1 = 0;
        }

        /* otherwise handle the events */
        fds[FD_STDIN].fd = -1;
        if (stdin_fd >= 0) {
            fds[FD_STDIN].fd = stdin_fd;
            if (buffer_len(stdin_buf) > 0)
                fds[FD_STDIN].events = POLLOUT;
            else
                /* if no data to be written, still monitor for stdin close
                 * (POLLHUP) */
                fds[FD_STDIN].events = 0;
        }

        fds[FD_STDOUT].fd = -1;
        fds[FD_STDERR].fd = -1;
        if (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
            if (stdout_fd >= 0) {
                fds[FD_STDOUT].fd = stdout_fd;
                fds[FD_STDOUT].events = POLLIN;
            }
            if (stderr_fd >= 0) {
                fds[FD_STDERR].fd = stderr_fd;
                fds[FD_STDERR].events = POLLIN;
            }
        }

        fds[FD_VCHAN].fd = libvchan_fd_for_select(vchan);
        fds[FD_VCHAN].events = POLLIN;

        if (!buffer_len(stdin_buf) && libvchan_data_ready(vchan) > 0)
            /* check for other FDs, but exit immediately */
            ret = ppoll(fds, FD_NUM, &zero_timeout, &pollmask);
        else
            ret = ppoll(fds, FD_NUM, &normal_timeout, &pollmask);

        if (ret < 0) {
            if (errno == EINTR)
                continue;
            else {
                PERROR("poll");
                /* TODO */
                break;
            }
        }

        /* clear event pending flag */
        if (fds[FD_VCHAN].revents)
            if (libvchan_wait(vchan) < 0)
                handle_vchan_error("wait");

        if (stdin_fd >= 0 && fds[FD_STDIN].revents & POLLHUP) {
            close_stdin(stdin_fd, !use_stdio_socket);
            stdin_fd = -1;
        }

        /* handle_remote_data will check if any data is available */
        switch (handle_remote_data(
                    vchan, stdin_fd,
                    &remote_status,
                    stdin_buf,
                    data_protocol_version,
                    replace_chars_stdout > 0,
                    replace_chars_stderr > 0)) {
            case REMOTE_ERROR:
                handle_vchan_error("read");
                break;
            case REMOTE_EOF:
                close_stdin(stdin_fd, !use_stdio_socket);
                stdin_fd = -1;
                break;
            case REMOTE_EXITED:
                /* Remote process exited, we don't need any more data from
                 * local FDs. However, don't exit yet, because there might
                 * still be some data in stdin_buf waiting to be flushed.
                 */
                close_stdout(stdout_fd, !use_stdio_socket);
                stdout_fd = -1;
                close_stderr(stderr_fd);
                stderr_fd = -1;
                break;
        }
        if (stdout_fd >= 0 && fds[FD_STDOUT].revents) {
            switch (handle_input(
                        vchan, stdout_fd, stdout_msg_type,
                        data_protocol_version)) {
                case REMOTE_ERROR:
                    handle_vchan_error("send(handle_input stdout)");
                    break;
                case REMOTE_EOF:
                    close_stdout(stdout_fd, !use_stdio_socket);
                    stdout_fd = -1;
                    break;
            }
        }
        if (stderr_fd >= 0 && fds[FD_STDERR].revents) {
            switch (handle_input(
                        vchan, stderr_fd, MSG_DATA_STDERR,
                        data_protocol_version)) {
                case REMOTE_ERROR:
                    handle_vchan_error("send(handle_input stderr)");
                    break;
                case REMOTE_EOF:
                    close_stderr(stderr_fd);
                    stderr_fd = -1;
                    break;
            }
        }
    }
    /* make sure that all the pipes/sockets are closed, so the child process
     * (if any) will know that the connection is terminated */
    close_stdin(stdin_fd, true);
    close_stdout(stdout_fd, true);
    close_stderr(stderr_fd);

    /* wait for local process, in case we exited early */
    if (local_pid && local_status < 0) {
        int status;
        if (waitpid(local_pid, &status, 0) > 0) {
            if (WIFSIGNALED(status))
                local_status = 128 + WTERMSIG(status);
            else
                local_status = WEXITSTATUS(status);
        } else
            PERROR("waitpid");
    }

    if (!is_service)
        return remote_status;
    return local_pid ? local_status : 0;
}
