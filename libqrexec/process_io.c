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

#include <assert.h>
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
#include "remote.h"
#include "private.h"

static _Noreturn void handle_vchan_error(const char *op)
{
    LOG(ERROR, "Error while vchan %s, exiting", op);
    exit(1);
}

/*
 * Closing the file descriptors:
 *
 * - If this file descriptor was inherited _and_ is not used for both stdin
 *   and stdout, restore the blocking status of the FD and then close it.
 * - Otherwise, call shutdown() to indicate that no more data will be sent or
 *   received in the given direction.
 */
static bool close_stdio(int fd, int direction, bool single_socket) {
    if (fd == -1)
        return false;
    if (single_socket || fd > 2) {
        if (shutdown(fd, direction) == -1) {
            if (errno == ENOTSOCK && !single_socket) {
                close(fd);
                return true;
            } else if (errno != ENOTCONN) {
                // ENOTCONN can happen with TCP and is harmless
                PERROR("shutdown");
            }
        }
        return false;
    } else {
        /* Close the file descriptor */
        set_block(fd);
        close(fd);
        return true;
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
    return qrexec_process_io(req, NULL);
}

int qrexec_process_io(const struct process_io_request *req,
                      const struct qrexec_parsed_command *cmd) {
    libvchan_t *vchan = req->vchan;
    int stdin_fd = req->stdin_fd;
    int stdout_fd = req->stdout_fd;
    int stderr_fd = req->stderr_fd;
    int dup_fd = req->logger_fd;
    struct buffer *stdin_buf = req->stdin_buf;

    bool const is_service = req->is_service;
    assert(is_service == (cmd != NULL));
    bool replace_chars_stdout = req->replace_chars_stdout;
    bool replace_chars_stderr = req->replace_chars_stderr;
    bool const exit_on_stdin_eof = cmd != NULL && cmd->exit_on_stdin_eof;
    bool const exit_on_stdout_eof = cmd != NULL && cmd->exit_on_stdout_eof;
    const int data_protocol_version = req->data_protocol_version;
    const size_t max_chunk_size = max_data_chunk_size(data_protocol_version);
    pid_t local_pid = req->local_pid;
    volatile sig_atomic_t *sigchld = req->sigchld;
    volatile sig_atomic_t *sigusr1 = req->sigusr1;

    pid_t local_status = -1;
    pid_t remote_status = -1;
    /* Saved version of stdin_fd.  If we get SIGHUP,
     * this replaces stdout_fd.  Set to -1 only if stdin_fd
     * is closed, not merely shut down. */
    int saved_stdin_fd = stdin_fd;
    int stdout_msg_type = is_service ? MSG_DATA_STDOUT : MSG_DATA_STDIN;
    int ret;
    struct pollfd fds[FD_NUM];
    sigset_t pollmask;
    struct timespec zero_timeout = { 0, 0 };
    struct timespec normal_timeout = { 10, 0 };
    struct prefix_data empty = { 0, 0 }, prefix = req->prefix_data;

    if (is_service && stderr_fd == -1) {
        struct msg_header hdr = { .type = MSG_DATA_STDERR, .len = 0 };
        libvchan_send(vchan, &hdr, (int)sizeof(hdr));
    }

    struct buffer remote_buffer = {
        .data = malloc(max_chunk_size),
        .buflen = max_chunk_size,
    };
    if (remote_buffer.data == NULL)
        handle_vchan_error("remote buffer alloc");

    sigemptyset(&pollmask);
    sigaddset(&pollmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &pollmask, NULL);
    sigemptyset(&pollmask);

    /* Invariants:
     *
     * - if stdin_fd == stdout_fd, then use_stdio_socket is true.
     * - if use_stdio_socket is true, then either:
     *   - stdin_fd == stdout_fd right now.
     *   - stdin_fd == stdout_fd at some point in the past,
     *     and one of them is currently -1.
     */
    bool use_stdio_socket = stdin_fd == stdout_fd;
    set_nonblock(stdin_fd);
    if (!use_stdio_socket)
        set_nonblock(stdout_fd);
    if (is_service && local_pid == 0) {
        assert(stdin_fd == stdout_fd);
        assert(stderr_fd == -1);
    }
    if (stderr_fd >= 0) {
        assert(is_service); // if this is a client, stderr_fd is *always* -1
        set_nonblock(stderr_fd);
    }
    if (exit_on_stdin_eof || exit_on_stdout_eof) {
        assert(is_service); // only valid for socket services
        assert(local_pid == 0); // ditto
    }

    /* Convenience macros that eliminate a ton of error-prone boilerplate */
#define close_stdin() do {                                      \
    if (exit_on_stdin_eof) {                                    \
        /* If stdout is still open, send EOF */                 \
        if (stdout_fd != -1) {                                  \
            const struct msg_header hdr = {                     \
                .type = stdout_msg_type,                        \
                .len = 0,                                       \
            };                                                  \
            libvchan_send(vchan, &hdr, sizeof(hdr));            \
        };                                                      \
        /* Set stdin_fd and stdout_fd to -1.                    \
         * No need to close them as the process                 \
         * will soon exit. */                                   \
        stdin_fd = stdout_fd = -1;                              \
    } else {                                                    \
        /* if stdin_fd was actually closed, set saved_stdin_fd  \
         * to -1 to avoid use-after-close */                    \
        if (close_stdio(stdin_fd, SHUT_WR, use_stdio_socket))   \
            saved_stdin_fd = -1;                                \
        stdin_fd = -1;                                          \
    }                                                           \
} while (0)
#define close_stdout() do {                                     \
    if (exit_on_stdout_eof) {                                   \
        /* Set stdin_fd and stdout_fd to -1.                    \
         * No need to close them as the process                 \
         * will soon exit. */                                   \
        stdin_fd = stdout_fd = -1;                              \
    } else {                                                    \
        close_stdio(stdout_fd, SHUT_RD, use_stdio_socket);      \
        stdout_fd = -1;                                         \
    }                                                           \
} while (0)
#pragma GCC poison close_stdio

    while(1) {
        /* React to SIGCHLD */
        if (*sigchld) {
            int status;
            if (local_pid > 0 && waitpid(local_pid, &status, WNOHANG) > 0) {
                if (WIFSIGNALED(status))
                    local_status = 128 + WTERMSIG(status);
                else
                    local_status = WEXITSTATUS(status);
                close_stdin();
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

        /* Exit the loop if vchan is disconnected (and we processed all
         * incoming data).
         * Check libvchan_is_open() before libvchan_data_ready() to avoid a
         * race condition.
         *
         * TODO: Refactor this exit logic (including "if all done" above, and
         * waitpid() below); it's pretty confusing and it's not clear what is
         * expected behaviour and what is an error.
         */
        if (!libvchan_is_open(vchan) &&
                !libvchan_data_ready(vchan) &&
                !buffer_len(stdin_buf)) {
            bool all_closed = stdin_fd == -1 && stdout_fd == -1 && stderr_fd == -1;
            if (is_service || !(all_closed && remote_status >= 0)) {
                LOG(ERROR,
                    "vchan connection closed early (fds: %d %d %d, status: %d %d)",
                    stdin_fd, stdout_fd, stderr_fd, local_status, remote_status);
            }
            break;
        }

        /* child signaled desire to use single socket for both stdin and stdout */
        if (sigusr1 && *sigusr1 && !use_stdio_socket) {
            close_stdout();
            stdout_fd = saved_stdin_fd;
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
                 * (POLLHUP or POLLERR) */
                fds[FD_STDIN].events = 0;
        }

        fds[FD_STDOUT].fd = -1;
        fds[FD_STDERR].fd = -1;
        if (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
            if (prefix.len == 0 && stdout_fd >= 0) {
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

        if (fds[FD_STDIN].revents & (POLLHUP | POLLERR))
            close_stdin();

        /* handle_remote_data will check if any data is available */
        switch (handle_remote_data_v2(
                    vchan, stdin_fd,
                    &remote_status,
                    stdin_buf,
                    replace_chars_stdout > 0,
                    replace_chars_stderr > 0,
                    is_service,
                    &remote_buffer)) {
            case REMOTE_ERROR:
                handle_vchan_error("read");
                break;
            case REMOTE_EOF:
                close_stdin();
                break;
            case REMOTE_EXITED:
                /* Remote process exited, we don't need any more data from
                 * local FDs. However, don't exit yet, because there might
                 * still be some data in stdin_buf waiting to be flushed.
                 */
                if (stdout_fd != -1) {
                    /* Send EOF */
                    struct msg_header hdr = { .type = stdout_msg_type, .len = 0, };
                    libvchan_send(vchan, &hdr, (int)sizeof(hdr));
                }
                close_stdout();
                break;
        }
        if (prefix.len > 0 || (stdout_fd >= 0 && fds[FD_STDOUT].revents)) {
            switch (handle_input_v2(
                        vchan, stdout_fd, stdout_msg_type,
                        &prefix, &remote_buffer, -1)) {
                case REMOTE_ERROR:
                    if (!is_service && remote_status == -1) {
                        /* Even if sending fails, still try to read remaining
                         * data, if any - especially the exit code. But don't
                         * send anything anymore.
                         */
                        LOG(ERROR, "Error while vchan send (handle_input stdout), reading remaining data");
                        close_stdout();
                    } else {
                        handle_vchan_error("send(handle_input stdout)");
                    }
                    break;
                case REMOTE_EOF:
                    close_stdout();
                    break;
            }
        }
        if (stderr_fd >= 0 && fds[FD_STDERR].revents) {
            switch (handle_input_v2(
                        vchan, stderr_fd, MSG_DATA_STDERR,
                        &empty, &remote_buffer, dup_fd)) {
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
    close_stdin();
    close_stdout();
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

    free(remote_buffer.data);

    if (!is_service && remote_status)
        return remote_status;
    return local_pid ? local_status : 0;
}
