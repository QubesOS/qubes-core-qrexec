/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include "qrexec.h"
#include "libqrexec-utils.h"

static do_exec_t *exec_func = NULL;
void register_exec_func(do_exec_t *func) {
    exec_func = func;
}

void exec_qubes_rpc_if_requested(char *prog, char *const envp[]) {
    /* avoid calling qubes-rpc-multiplexer through shell */
    if (strncmp(prog, RPC_REQUEST_COMMAND, RPC_REQUEST_COMMAND_LEN) == 0) {
        char *tok, *saveptr;
        char *argv[16]; // right now 6 are used, but allow future extensions
        size_t i = 0;
        tok=strtok_r(prog, " ", &saveptr);
        do {
            if (i >= sizeof(argv)/sizeof(argv[0])-1) {
                fprintf(stderr, "To many arguments to %s\n", RPC_REQUEST_COMMAND);
                exit(1);
            }
            argv[i++] = tok;
        } while ((tok=strtok_r(NULL, " ", &saveptr)));
        argv[i] = NULL;
        argv[0] = QUBES_RPC_MULTIPLEXER_PATH;
        execve(QUBES_RPC_MULTIPLEXER_PATH, argv, envp);
        perror("exec qubes-rpc-multiplexer");
        _exit(126);
    }
}

void fix_fds(int fdin, int fdout, int fderr)
{
    int i;
    for (i = 3; i < 256; i++)
        if (i != fdin && i != fdout && i != fderr)
            close(i);
    if (dup2(fdin, 0) == -1 || dup2(fdout, 1) == -1 || dup2(fderr, 2) == -1 ||
        close(fdin) || close(fdout) || (fderr != 2 && close(fderr))) {
        abort();
    }
}

int do_fork_exec(char *cmdline,
                 int *pid,
                 int *stdin_fd,
                 int *stdout_fd,
                 int *stderr_fd)
{
    int inpipe[2], outpipe[2], errpipe[2], statuspipe[2], retval;
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, inpipe) || 
            socketpair(AF_UNIX, SOCK_STREAM, 0, outpipe) || 
            (stderr_fd && socketpair(AF_UNIX, SOCK_STREAM, 0, errpipe)) ||
            socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, statuspipe)) {
        perror("socketpair");
        exit(1);
    }
    switch (*pid = fork()) {
        case -1:
            perror("fork");
            exit(-1);
        case 0: {
            int status;
            if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
                abort();
            if (stderr_fd) {
                fix_fds(inpipe[0], outpipe[1], errpipe[1]);
            } else
                fix_fds(inpipe[0], outpipe[1], 2);

            close(statuspipe[0]);
#if !SOCK_CLOEXEC
            status = fcntl(statuspipe[1], F_GETFD);
            fcntl(statuspipe[1], F_SETFD, status | FD_CLOEXEC);
#endif
            if (exec_func != NULL)
                exec_func(cmdline);
            else
                abort();
            status = errno;
            while (write(statuspipe[1], &status, sizeof status) <= 0) {}
            exit(-1);
        }
        default: {
            close(statuspipe[1]);
            if (read(statuspipe[0], &retval, sizeof retval) == sizeof retval) {
                siginfo_t siginfo;
                memset(&siginfo, 0, sizeof siginfo);
                waitid(P_PID, *pid, &siginfo, WEXITED); // discard result
            } else {
                retval = 0;
            }
        }
    }
    close(inpipe[0]);
    close(outpipe[1]);
    *stdin_fd = inpipe[1];
    *stdout_fd = outpipe[0];
    if (stderr_fd) {
        close(errpipe[1]);
        *stderr_fd = errpipe[0];
    }
    return retval;
}

#define QUBES_MAX_SERVICE_NAME_LEN 31ULL
#define QUBES_MAX_SERVICE_ARG_LEN 63ULL
#define QUBES_MAX_SERVICE_DESCRIPTOR_LEN \
    (QUBES_MAX_SERVICE_NAME_LEN + QUBES_MAX_SERVICE_ARG_LEN + 1ULL)
#define QUBES_SOCKADDR_UN_MAX_PATH_LEN 1024

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
// static_assert(QUBES_MAX_SERVICE_DESCRIPTOR_LEN == 95,
//         "bad macro definition");
#define S(z) \
    static_assert(sizeof(z) + QUBES_MAX_SERVICE_DESCRIPTOR_LEN <= QUBES_SOCKADDR_UN_MAX_PATH_LEN, \
            "Path too long: " #z);
MAKE_STRUCT(S)
#undef S
#undef MAKE_STRUCT

#if QUBES_MAX_SERVICE_DESCRIPTOR_LEN > PTRDIFF_MAX
#error impossible
#endif

static char *parse_qrexec_argument_from_commandline(char *cmdline, int strip_user_name) {
    char *end_user;
    uintptr_t user_len;
    if (strip_user_name) {
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

static int qubes_connect(int s, const char *buffer, const size_t total_path_length) {
    // Avoiding an extra copy is NOT worth it!
#define QUBES_TMP_DIRECTORY "/tmp/qrexec-XXXXXX"
    char buf[] = QUBES_TMP_DIRECTORY "\0qrexec-socket";
    struct sockaddr_un remote = { .sun_family = AF_UNIX, .sun_path = { 0 } };
    static_assert(sizeof buf <= sizeof remote.sun_path,
                  "maximum path length of AF_UNIX sockets too small");
    static const size_t path_separator_offset = sizeof QUBES_TMP_DIRECTORY - 1;
    int result = -1, dummy_errno = -1;
    socklen_t socket_len;
    if (total_path_length != strlen(buffer))
        abort();
    if (sizeof remote.sun_path <= total_path_length) {
        // sockaddr_un too small :(
        if (NULL == mkdtemp(buf))
            return -1;
        buf[path_separator_offset] = '/';
        if (symlink(buffer, buf)) {
           dummy_errno = errno;
           goto fail;
        }
        memcpy(remote.sun_path, buf, sizeof buf);
        socket_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + sizeof buf);
    } else {
        memcpy(remote.sun_path, buffer, total_path_length);
        remote.sun_path[total_path_length] = '\0';
        socket_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + total_path_length + 1);
    }

    result = connect(s, (struct sockaddr *) &remote, socket_len);
    dummy_errno = errno;
    unlink(buf);
fail:
    buf[path_separator_offset] = '\0';
    rmdir(buf);
    errno = dummy_errno;
    return result;
}

int execute_qubes_rpc_command(char *cmdline, int *pid, int *stdin_fd, int *stdout_fd, int *stderr_fd, int cmdline_has_user_name) {
    int s = -1;
    char *realcmd, *remote_domain;
    size_t path_length;
    realcmd = parse_qrexec_argument_from_commandline(cmdline, cmdline_has_user_name);
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
        assert(0 && "impossible");
        abort();
    }
#undef FAIL

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    for (unsigned use_bare_path = 0; use_bare_path < 2; ++use_bare_path) {
        for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
            char buffer[QUBES_SOCKADDR_UN_MAX_PATH_LEN];
            size_t const directory_length = paths[i].length;
            assert(sizeof buffer > path_length);
            assert(sizeof buffer - path_length > directory_length);

            // The total size of the path (not including NUL terminator).
            size_t const total_path_length = directory_length +
                (use_bare_path ? service_length : path_length);
            memcpy(buffer, paths[i].string, directory_length);
            memcpy(buffer + directory_length, realcmd, path_length);
            buffer[total_path_length] = '\0';

            if (!qubes_connect(s, buffer, total_path_length)) {
                *stdout_fd = *stdin_fd = s;
                if (stderr_fd != NULL)
                    *stderr_fd = -1;
                *pid = -1;
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
            case EINTR:
                // Interrupted by a signal - retry
                --i; // to retry loop iteration
                continue;
            case ENOENT:
            case ENOTDIR:
                // These errors could also happen with `execve()`
                break;
            case EPROTOTYPE:
            case ETIMEDOUT:
            case EPERM:
            case EIO:
            case EISDIR:
            case EAGAIN:       // ditto
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:  // ditto
#endif
                // Socket server problem and/or misconfiguration.  Fail the whole connection.
                // (We do not want to fall back because the user may have
                // overriden behavior for security reasons, and because
                // fail-fast is much easier to debug).
                goto fail;
            case ECONNREFUSED:
            case EACCES:
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
