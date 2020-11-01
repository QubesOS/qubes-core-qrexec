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
#include <limits.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include "qrexec.h"
#include "libqrexec-utils.h"

static do_exec_t *exec_func = NULL;
void register_exec_func(do_exec_t *func) {
    if (exec_func != NULL)
        abort();
    exec_func = func;
}

void exec_qubes_rpc_if_requested(const char *prog, char *const envp[]) {
    /* avoid calling qubes-rpc-multiplexer through shell */
    if (strncmp(prog, RPC_REQUEST_COMMAND, RPC_REQUEST_COMMAND_LEN) == 0) {
        char *prog_copy;
        char *tok, *savetok;
        char *argv[16]; // right now 6 are used, but allow future extensions
        size_t i = 0;

        prog_copy = strdup(prog);
        if (!prog_copy) {
            PERROR("strdup");
            _exit(1);
        }

        tok=strtok_r(prog_copy, " ", &savetok);
        do {
            if (i >= sizeof(argv)/sizeof(argv[0])-1) {
                LOG(ERROR, "To many arguments to %s", RPC_REQUEST_COMMAND);
                exit(1);
            }
            argv[i++] = tok;
        } while ((tok=strtok_r(NULL, " ", &savetok)));
        argv[i] = NULL;

        argv[0] = getenv("QREXEC_MULTIPLEXER_PATH");
        if (!argv[0])
            argv[0] = QUBES_RPC_MULTIPLEXER_PATH;
        execve(argv[0], argv, envp);
        PERROR("exec qubes-rpc-multiplexer");
        _exit(126);
    }
}

void fix_fds(int fdin, int fdout, int fderr)
{
    int i;
    for (i = 3; i < 256; i++)
        if (i != fdin && i != fdout && i != fderr)
            close(i);
    if (dup2(fdin, 0) < 0 || dup2(fdout, 1) < 0 || dup2(fderr, 2) < 0) {
        PERROR("dup2");
        abort();
    }

    if (close(fdin) || (fdin != fdout && close(fdout)) ||
        (fdin != fderr && fdout != fderr && fderr != 2 && close(fderr))) {
        PERROR("close");
        abort();
    }
}

static int do_fork_exec(const char *user,
        const char *cmdline,
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
        PERROR("socketpair");
        exit(1);
    }
    switch (*pid = fork()) {
        case -1:
            PERROR("fork");
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
                exec_func(cmdline, user);
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

#define QUBES_SOCKADDR_UN_MAX_PATH_LEN 1024

static int qubes_connect(int s, const char *connect_path, const size_t total_path_length) {
    // Avoiding an extra copy is NOT worth it!
#define QUBES_TMP_DIRECTORY "/tmp/qrexec-XXXXXX"
    char buf[] = QUBES_TMP_DIRECTORY "\0qrexec-socket";
    struct sockaddr_un remote = { .sun_family = AF_UNIX, .sun_path = { '\0' } };
    static_assert(sizeof buf <= sizeof remote.sun_path,
                  "maximum path length of AF_UNIX sockets too small");
    static const size_t path_separator_offset = sizeof QUBES_TMP_DIRECTORY - 1;
    int result = -1, dummy_errno = -1;
    socklen_t socket_len;
    if (sizeof remote.sun_path <= total_path_length) {
        // sockaddr_un too small :(
        if (NULL == mkdtemp(buf))
            return -1;
        buf[path_separator_offset] = '/';
        if (symlink(connect_path, buf)) {
           dummy_errno = errno;
           goto out;
        }
        memcpy(remote.sun_path, buf, sizeof buf);
        socket_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + sizeof buf);
    } else {
        memcpy(remote.sun_path, connect_path, total_path_length);
        remote.sun_path[total_path_length] = '\0';
        socket_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + total_path_length + 1);
    }

    do
       result = connect(s, (struct sockaddr *) &remote, socket_len);
    while (result < 0 && (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN));
    dummy_errno = errno;
out:
    if (buf[path_separator_offset] == '/') {
        unlink(buf);
        buf[path_separator_offset] = '\0';
        rmdir(buf);
    }
    errno = dummy_errno;
    return result;
}

static int execute_parsed_qubes_rpc_command(
    const struct qrexec_parsed_command *cmd,
    int *pid, int *stdin_fd, int *stdout_fd, int *stderr_fd,
    struct buffer *stdin_buffer);

/*
  Find a file in the ':'-delimited list of paths given in path_list.
  Returns 0 on success, -1 on failure.
  On success, fills buffer and statbuf (unless statbuf is NULL).
 */
static int find_file(
    const char *path_list,
    const char *name,
    char *buffer,
    size_t buffer_size,
    struct stat *statbuf) {

    struct stat dummy_buf;
    const char *path_start = path_list;
    size_t name_length = strlen(name);

    if (!statbuf)
        statbuf = &dummy_buf;

    while (*path_start) {
        /* Find next path (up to ':') */
        const char *path_end = strchrnul(path_start, ':');
        size_t path_length = (size_t)(path_end - path_start);

        if (path_length + name_length + 1 >= buffer_size) {
            LOG(ERROR, "find_qrexec_service_file: buffer too small for file path");
            return -1;
        }

        memcpy(buffer, path_start, path_length);
        buffer[path_length] = '/';
        strcpy(buffer + path_length + 1, name);
        //LOG(INFO, "stat(%s)", buffer);
        if (stat(buffer, statbuf) == 0)
            return 0;

        path_start = path_end;
        while (*path_start == ':')
            path_start++;
    }
    return -1;
}

int load_service_config(const struct qrexec_parsed_command *cmd,
                        int *wait_for_session) {
    assert(cmd->service_descriptor);

    const char *config_path = getenv("QUBES_RPC_CONFIG_PATH");
    if (!config_path)
        config_path = QUBES_RPC_CONFIG_PATH;

    char config_full_path[256];

    int ret = find_file(config_path, cmd->service_descriptor,
                        config_full_path, sizeof(config_full_path), NULL);
    if (ret < 0 && strcmp(cmd->service_descriptor, cmd->service_name) != 0)
        ret = find_file(config_path, cmd->service_name,
                        config_full_path, sizeof(config_full_path), NULL);
    if (ret < 0)
        return 0;

    char config[MAX_CONFIG_SIZE];
    char *config_iter = config;
    FILE *config_file;
    size_t read_count;
    char *current_line;

    config_file = fopen(config_full_path, "re");
    if (!config_file) {
        PERROR("Failed to load %s", config_full_path);
        return -1;
    }

    read_count = fread(config, 1, sizeof(config)-1, config_file);

    if (ferror(config_file)) {
        fclose(config_file);
        return -1;
    }

    // config is a text file, should not have \0 inside; but when it has, part
    // after it will be ignored
    config[read_count] = 0;

    while ((current_line = strsep(&config_iter, "\n"))) {
        // ignore comments
        if (current_line[0] == '#')
            continue;
        sscanf(current_line, "wait-for-session=%d", wait_for_session);
    }

    fclose(config_file);
    return 1;
}

struct qrexec_parsed_command *parse_qubes_rpc_command(
    const char *cmdline, bool strip_username) {

    struct qrexec_parsed_command *cmd;

    if (!(cmd = malloc(sizeof(*cmd)))) {
        PERROR("malloc");
        return NULL;
    }

    memset(cmd, 0, sizeof(*cmd));
    cmd->cmdline = cmdline;

    if (strip_username) {
        const char *colon = strchr(cmdline, ':');
        if (!colon) {
            LOG(ERROR, "Bad command from dom0 (%s): no colon", cmdline);
            goto err;
        }
        cmd->username = strndup(cmdline, (size_t)(colon - cmdline));
        if (!cmd->username) {
            PERROR("strndup");
            goto err;
        }
        cmd->command = colon + 1;
    } else
        cmd->command = cmdline;

    if (strncmp(cmd->command, NOGUI_CMD_PREFIX, NOGUI_CMD_PREFIX_LEN) == 0) {
        cmd->nogui = true;
        cmd->command += NOGUI_CMD_PREFIX_LEN;
    } else
        cmd->nogui = false;

    /* If the command starts with "QUBESRPC ", parse service descriptor */
    if (strncmp(cmd->command, RPC_REQUEST_COMMAND " ",
                RPC_REQUEST_COMMAND_LEN + 1) == 0) {
        const char *start, *end;

        /* Parse service descriptor ("qubes.Service+arg") */

        start = cmd->command + RPC_REQUEST_COMMAND_LEN + 1;
        end = strchr(start, ' ');
        if (!end) {
            LOG(ERROR, "No space found after service descriptor");
            goto err;
        }

        if (end - start > MAX_SERVICE_NAME_LEN) {
            LOG(ERROR, "Command too long (length %zu)",
                end - start);
            goto err;
        }

        cmd->service_descriptor = strndup(start, end - start);
        if (!cmd->service_descriptor) {
            PERROR("strndup");
            goto err;
        }

        /* Parse service name ("qubes.Service") */

        const char *plus = memchr(start, '+', end - start);
        if (plus) {
            if (plus - start == 0) {
                LOG(ERROR, "Service name empty");
                goto err;
            }
            if (plus - start > NAME_MAX) {
                LOG(ERROR, "Service name too long to execute (length %zu)",
                    plus - start);
                goto err;
            }
            cmd->service_name = strndup(start, plus - start);
            if (!cmd->service_name) {
                PERROR("strndup");
                goto err;
            }
        } else {
            cmd->service_name = strndup(start, end - start);
            if (!cmd->service_name) {
                PERROR("strdup");
                goto err;
            }
        }

        /* Parse source domain */

        start = end + 1; /* after the space */
        end = strchrnul(start, ' ');
        cmd->source_domain = strndup(start, end - start);
        if (!cmd->source_domain) {
            PERROR("strndup");
            goto err;
        }
    }

    return cmd;

err:
    destroy_qrexec_parsed_command(cmd);
    return NULL;
}

void destroy_qrexec_parsed_command(struct qrexec_parsed_command *cmd) {
    if (cmd->username)
        free(cmd->username);
    if (cmd->service_descriptor)
        free(cmd->service_descriptor);
    if (cmd->service_name)
        free(cmd->service_name);
    if (cmd->source_domain)
        free(cmd->source_domain);
    free(cmd);
}

int execute_qubes_rpc_command(const char *cmdline, int *pid, int *stdin_fd,
        int *stdout_fd, int *stderr_fd, bool strip_username, struct buffer *stdin_buffer) {

    struct qrexec_parsed_command *cmd;
    int ret;

    if (!(cmd = parse_qubes_rpc_command(cmdline, strip_username))) {
        LOG(ERROR, "Could not parse command line: %s", cmdline);
        return -1;
    }

    if (cmd->service_descriptor) {
        // Proper Qubes RPC call
        ret = execute_parsed_qubes_rpc_command(
            cmd, pid, stdin_fd, stdout_fd, stderr_fd, stdin_buffer);
    } else {
        // Legacy qrexec behavior: spawn shell directly
        ret = do_fork_exec(cmd->username, cmd->command,
                           pid, stdin_fd, stdout_fd, stderr_fd);
    }

    destroy_qrexec_parsed_command(cmd);
    return ret;
}

static int execute_parsed_qubes_rpc_command(
        const struct qrexec_parsed_command *cmd,
        int *pid, int *stdin_fd, int *stdout_fd, int *stderr_fd,
        struct buffer *stdin_buffer) {

    assert(cmd->service_descriptor);

    const char *qrexec_service_path = getenv("QREXEC_SERVICE_PATH");
    if (!qrexec_service_path)
        qrexec_service_path = QREXEC_SERVICE_PATH;

    char service_full_path[QUBES_SOCKADDR_UN_MAX_PATH_LEN];
    struct stat statbuf;

    int ret = find_file(qrexec_service_path, cmd->service_descriptor,
                        service_full_path, sizeof(service_full_path),
                        &statbuf);
    if (ret < 0 && strcmp(cmd->service_descriptor, cmd->service_name) != 0)
        ret = find_file(qrexec_service_path, cmd->service_name,
                        service_full_path, sizeof(service_full_path),
                        &statbuf);
    if (ret < 0) {
        LOG(ERROR, "Service not found: %s",
            cmd->service_descriptor);
        return -1;
    }

    if (S_ISSOCK(statbuf.st_mode)) {
        /* Socket-based service. */
        int s;
        if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            PERROR("socket");
            return -1;
        }
        if (qubes_connect(s, service_full_path, strlen(service_full_path))) {
            PERROR("qubes_connect");
            close(s);
            return -1;
        }

        *stdout_fd = *stdin_fd = s;
        if (stderr_fd)
            *stderr_fd = -1;
        *pid = 0;
        set_nonblock(s);

        /* send part after "QUBESRPC ", including trailing NUL */
        const char *desc = cmd->command + RPC_REQUEST_COMMAND_LEN + 1;
        buffer_append(stdin_buffer, desc, strlen(desc) + 1);
        return 0;
    }

    if (euidaccess(service_full_path, X_OK) == 0) {
        /*
          Executable-based service.

          Note that this delegates to qubes-rpc-multiplexer, which, for the
          moment, searches for the right file again.
        */
        return do_fork_exec(cmd->username, cmd->command,
                            pid, stdin_fd, stdout_fd, stderr_fd);
    }

    LOG(ERROR, "Unknown service type (not executable, not a socket): %s",
        service_full_path);
    return -1;
}

int exec_wait_for_session(const char *source_domain) {
    const char *qrexec_service_path = getenv("QREXEC_SERVICE_PATH");
    if (!qrexec_service_path)
        qrexec_service_path = QREXEC_SERVICE_PATH;

    const char *service_name = "qubes.WaitForSession";

    char service_full_path[256];

    int ret = find_file(qrexec_service_path, service_name,
                        service_full_path, sizeof(service_full_path), NULL);
    if (ret < 0) {
        LOG(ERROR, "Service not found: %s", service_name);
        return -1;
    }

    setenv("QREXEC_REMOTE_DOMAIN", source_domain, 1);
    return execl(service_full_path, service_name, NULL);
}
// vim: set sw=4 ts=4 sts=4 et:
