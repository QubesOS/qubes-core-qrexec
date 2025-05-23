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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include "qrexec.h"
#include "libqrexec-utils.h"
#include "private.h"

static do_exec_t *exec_func = NULL;
void register_exec_func(do_exec_t *func) {
    if (exec_func != NULL)
        abort();
    exec_func = func;
}

#define STR_LITERAL_SIZE(a) (sizeof("" a) - 1)
#define STARTS_WITH_LITERAL(a, b) (strncmp(a, b, STR_LITERAL_SIZE(b)) == 0)

static bool should_strip_env_var(const char *var)
{
    if (!STARTS_WITH_LITERAL(var, "QREXEC"))
        return false;
    const char *rest = var + STR_LITERAL_SIZE("QREXEC");
    return !STARTS_WITH_LITERAL(rest, "_SERVICE_PATH=") &&
           !STARTS_WITH_LITERAL(rest, "_AGENT_PID=");
}

void exec_qubes_rpc2(const char *program, const char *cmd, char *const envp[],
                     bool use_shell) {
    assert(cmd);
    /* avoid calling RPC service through shell */
    char *prog_copy;
    char *tok, *savetok;
    const char *argv[10];
    size_t i = 0;
#define MAX_ADDED_ENV_VARS 5
    size_t const extra_env_vars = MAX_ADDED_ENV_VARS;
    size_t env_amount = extra_env_vars;

    for (char *const *env = envp; *env; ++env) {
        // Set this 0 to 1 if adding new variable settings below,
        // to ensure that MAX_ADDED_ENV_VARS is correct.
        if (0 && should_strip_env_var(*env))
            continue;
        env_amount++;
    }
#define EXTEND(...)                                         \
    do {                                                    \
        if (iterator >= env_amount)                         \
            abort();                                        \
        if (asprintf(&buf[iterator++], __VA_ARGS__) < 0)    \
            goto bad_asprintf;                              \
    } while (0)
#define EXTEND_RAW(arg)                                     \
    do {                                                    \
        if (iterator >= env_amount)                         \
            abort();                                        \
        buf[iterator++] = (arg);                            \
    } while (0)

    char **buf = calloc(env_amount + 1, sizeof(char *));
    if (buf == NULL) {
        LOG(ERROR, "calloc(%zu, %zu) failed: %m", env_amount, sizeof(char *));
        _exit(QREXEC_EXIT_PROBLEM);
    }
    size_t iterator = 0;
    for (char *const *env = envp; *env; ++env) {
        if (!should_strip_env_var(*env)) {
            EXTEND_RAW(*env);
        }
    }

    prog_copy = strdup(cmd);
    if (!prog_copy) {
        PERROR("strdup");
        _exit(QREXEC_EXIT_PROBLEM);
    }

    argv[i++] = program;
    tok=strtok_r(prog_copy, " ", &savetok);
    while (tok != NULL) {
        if (i >= sizeof(argv)/sizeof(argv[0])) {
            LOG(ERROR, "Too many arguments to %s", RPC_REQUEST_COMMAND);
            _exit(QREXEC_EXIT_PROBLEM);
        }
        argv[i++] = tok;
        tok = strtok_r(NULL, " ", &savetok);
    }

    if (program[0] != '/') {
        LOG(ERROR, "Program to execute not absolute path");
        _exit(QREXEC_EXIT_PROBLEM);
    }
    if (i != 3 && i != 5) {
        LOG(ERROR, "invalid number of arguments: %zu", i);
        _exit(QREXEC_EXIT_PROBLEM);
    }
    const char *full_name = argv[1];
    const char *remote_domain = argv[2];
    const char *p = strchr(argv[1], '+');

    // Change the 1 to a 0 to test the shell script generator.
    if (!use_shell && 1) {
        if (i == 5) {
            EXTEND("QREXEC_REQUESTED_TARGET_TYPE=%s", argv[3]);
            if (strcmp(argv[3], "name") == 0) {
                EXTEND("QREXEC_REQUESTED_TARGET=%s", argv[4]);
            } else if (strcmp(argv[3], "keyword") == 0) {
                EXTEND("QREXEC_REQUESTED_TARGET_KEYWORD=%s", argv[4]);
            } else {
                // requested target type unknown or not given, ignore
            }
        } else {
            EXTEND_RAW("QREXEC_REQUESTED_TARGET_TYPE=");
        }
        EXTEND("QREXEC_SERVICE_FULL_NAME=%s", full_name);
        EXTEND("QREXEC_REMOTE_DOMAIN=%s", remote_domain);
        argv[1] = NULL;
        if (p != NULL) {
            EXTEND("QREXEC_SERVICE_ARGUMENT=%s", p + 1);
            if (p[1] != '\0') {
                argv[1] = p + 1;
                argv[2] = NULL;
            }
        }
        assert(iterator <= env_amount);
        buf[iterator] = NULL;
        execve(program, (char *const *)argv, buf);
        if (errno != ENOENT) {
            PERROR("execve");
            _exit(QREXEC_EXIT_PROBLEM);
        }
        _exit(QREXEC_EXIT_SERVICE_NOT_FOUND);
    }

    // Generate a shell command and call it with the correct arguments.
    // Note that is_name and is_keyword are mutually exclusive.
    bool is_name = i == 5 && strcmp(argv[3], "name") == 0;
    bool is_keyword = i == 5 && strcmp(argv[3], "keyword") == 0;
    const char *requested_target = i == 5 ? argv[4] : NULL;
    argv[0] = "/bin/sh";
    argv[1] = "-lc";
    // Build a shell script that emulates the old multiplexer.
    // The shell script is only built from string literals,
    // never data from the provided command.  Reviewers are
    // invited to check that the produced script is always
    // valid no matter what the inputs are.  To improve
    // readability and maintainability, separating whitespace
    // is included in the format string, so the arguments do
    // not need to include it.  This means that the produced
    // script might have unnecessary whitespace, but this is
    // harmless.
    if (asprintf((char **)(argv + 2),
                // Unset the variables in case the user's shell init code did something weird,
                // like mark them read-only or make them an array.
                // Use set -e in case there is a problem.  Note that sh -el does not work
                // because the startup files are not compatible with -e.
                "set -e\n"
                "unset QREXEC_SERVICE_FULL_NAME QREXEC_REMOTE_DOMAIN QREXEC_REQUESTED_TARGET_TYPE "
                "QREXEC_SERVICE_ARGUMENT QREXEC_REQUESTED_TARGET QREXEC_REQUESTED_TARGET_KEYWORD\n"
                "export \"QREXEC_SERVICE_FULL_NAME=$2\" \"QREXEC_REMOTE_DOMAIN=$3\" QREXEC_REQUESTED_TARGET_TYPE=%s %s\n"
                // This could just be written as ${4:+"$4"}, which works just as well.
                // I decided to make the C code more complicated so the shell has less work
                // to do.
                "exec \"$1\" %s",
                is_keyword ? "keyword QREXEC_REQUESTED_TARGET_KEYWORD=\"$5\"" :
                (is_name ? "name QREXEC_REQUESTED_TARGET=\"$5\"" : ""),
                p == NULL ? "" : "\"QREXEC_SERVICE_ARGUMENT=$4\"",
                (p != NULL && p[1] != '\0') ? "\"$4\"" : "") < 0)
        goto bad_asprintf;
    argv[3] = "sh";
    argv[4] = program;
    argv[5] = full_name;
    argv[6] = remote_domain;
    argv[7] = p ? p + 1 : "";
    argv[8] = requested_target;
    argv[9] = NULL;
    execve("/bin/sh", (char *const *)argv, buf);
    /* /bin/sh should always exist */
    PERROR("execve /bin/sh");
    _exit(QREXEC_EXIT_PROBLEM);
bad_asprintf:
    PERROR("asprintf");
    _exit(QREXEC_EXIT_PROBLEM);
}

void fix_fds(int fdin, int fdout, int fderr)
{
    if (fdin < 0 || fdout < 1 || fderr < 2) {
        LOG(ERROR, "fix_fds: bad FD numbers: fdin %d, fdout %d, fderr %d",
            fdin, fdout, fderr);
        _exit(125);
    }
    if ((fdin != 0 && dup2(fdin, 0) < 0) ||
        (fdout != 1 && dup2(fdout, 1) < 0) ||
        (fderr != 2 && dup2(fderr, 2) < 0)) {
        PERROR("dup2");
        abort();
    }
#ifdef SYS_close_range
    int close_range_res = syscall(SYS_close_range, 3, ~0U, 0);
    if (close_range_res == 0)
        return;
    assert(close_range_res == -1);
    if (errno != ENOSYS) {
        PERROR("close_range");
        abort();
    }
#endif
    for (int i = 3; i < 256; ++i)
        close(i);
}

static int do_fork_exec(const char *prog,
        const char *user,
        const char *cmdline,
        int *pid,
        int *stdin_fd,
        int *stdout_fd,
        int *stderr_fd)
{
    int inpipe[2], outpipe[2], errpipe[2], retval;
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, inpipe) ||
            socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, outpipe)) {
        PERROR("socketpair");
        /* FD leaks do not matter, we exit soon anyway */
        return -2;
    }
    if (stderr_fd != NULL && pipe2(errpipe, O_CLOEXEC) != 0) {
        PERROR("socketpair");
        /* FD leaks do not matter, we exit soon anyway */
        return -2;
    }
    switch (*pid = fork()) {
        case -1:
            PERROR("fork");
            /* ditto */
            return -2;
        case 0:
            if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
                abort();
            if (stderr_fd) {
                fix_fds(inpipe[0], outpipe[1], errpipe[1]);
            } else
                fix_fds(inpipe[0], outpipe[1], 2);

            if (exec_func != NULL)
                exec_func(prog, cmdline, user);
            abort();
        default:
            retval = 0;
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

/*
  Find a file in the ':'-delimited list of paths given in path_list.
  Returns 0 on success, -1 if the file is definitely absent in all of the
  paths, and -2 on error (broken symlink, I/O error, path too long, out
  of memory, etc).
  On success, fills buffer and statbuf (unless statbuf is NULL).  buffer
  will contain the path to the file, while statbuf will contain metadata
  about the file as reported by stat(2).
  If statbuf is not NULL, buffer may be filled with string starting
  with "/dev/tcp/", which corresponds to the target of the symbolic link.
  In this case, statbuf will contain the metadata for the symlink itself,
  not its (hopefully nonexistent) target.
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
    char *buf = NULL;
    int res;
    int rc;

    if (name_length > NAME_MAX)
        return -1; /* cannot possibly exist */

    if (!statbuf) {
        statbuf = &dummy_buf;
    } else {
        buf = malloc(buffer_size);
        if (buf == NULL) {
            LOG(ERROR, "Cannot allocate %zu bytes", buffer_size);
            return -2;
        }
    }

    while (*path_start) {
        /* Find next path (up to ':') */
        const char *path_end = strchrnul(path_start, ':');
        size_t path_length = (size_t)(path_end - path_start);

        if (path_length + name_length + 1 >= buffer_size) {
            LOG(ERROR, "find_qrexec_service_file: buffer too small for file path");
            rc = -2;
            goto done;
        }

        memcpy(buffer, path_start, path_length);
        buffer[path_length] = '/';
        strcpy(buffer + path_length + 1, name);
        //LOG(INFO, "stat(%s)", buffer);
        res = lstat(buffer, statbuf);
        if (res == 0 && S_ISLNK(statbuf->st_mode)) {
            if (buf != NULL) {
                ssize_t res = readlink(buffer, buf, buffer_size);
                if (res < 0) {
                    /* readlink(2) failed */
                    LOG(ERROR, "readlink(2) failed: %m");
                    rc = -2;
                    goto done;
                }
                size_t target_len = (size_t)res;
                if ((target_len >= sizeof("/dev/tcp") && memcmp(buf, "/dev/tcp/", sizeof("/dev/tcp")) == 0) ||
                    (target_len == sizeof("/dev/tcp") - 1 && memcmp(buf, "/dev/tcp/", sizeof("/dev/tcp") - 1) == 0))
                {
                    if (target_len >= buffer_size) {
                        /* buffer too small */
                        LOG(ERROR, "Buffer size %zu too small for target length %zu", buffer_size, target_len);
                        rc = -2;
                    } else if (target_len == sizeof("/dev/tcp")) {
                        LOG(ERROR, "/dev/tcp/ not followed by host");
                        rc = -2;
                    } else {
                        memcpy(buffer, buf, target_len);
                        buffer[target_len] = '\0';
                        rc = 0;
                    }
                    goto done;
                }
            }
            /* check if the symlink is valid */
            res = stat(buffer, statbuf);
            assert(res == -1 || !S_ISLNK(statbuf->st_mode));
        }
        if (res == 0) {
            rc = 0;
            goto done;
        } else {
            assert(res == -1);
            if (errno != ENOENT) {
                LOG(ERROR, "stat/lstat(%s): %m", buffer);
                rc = -2;
                goto done;
            }
        }

        path_start = path_end;
        while (*path_start == ':')
            path_start++;
    }
    rc = -1;
done:
    free(buf);
    return rc;
}

static int load_service_config_raw(struct qrexec_parsed_command *cmd,
                                   char **user)
{
    const char *config_path = getenv("QUBES_RPC_CONFIG_PATH");
    if (!config_path)
        config_path = QUBES_RPC_CONFIG_PATH;

    char config_full_path[QUBES_SOCKADDR_UN_MAX_PATH_LEN];

    int ret = find_file(config_path, cmd->service_descriptor,
                        config_full_path, sizeof(config_full_path), NULL);
    if (ret == -1)
        ret = find_file(config_path, cmd->service_name,
                        config_full_path, sizeof(config_full_path), NULL);
    if (ret == -1)
        return 0;
    if (ret != 0)
        return ret;
    return qubes_toml_config_parse(config_full_path, &cmd->wait_for_session, user,
                                   &cmd->send_service_descriptor,
                                   &cmd->exit_on_stdout_eof,
                                   &cmd->exit_on_stdin_eof);
}

bool qrexec_cmd_use_fork_server(const struct qrexec_parsed_command *cmd) {
    if (cmd == NULL)
        return false;
    return !cmd->nogui && cmd->send_service_descriptor && !cmd->exit_on_stdin_eof &&
           !cmd->exit_on_stdout_eof;
}

int load_service_config_v2(struct qrexec_parsed_command *cmd) {
    assert(cmd->service_descriptor);
    char *tmp_user = NULL;
    int res = load_service_config_raw(cmd, &tmp_user);
    if (res >= 0 && tmp_user != NULL) {
        if (!cmd->send_service_descriptor) {
            LOG(ERROR, "service %s: Cannot set explicit username if "
                "skip-service-descriptor=true", cmd->service_descriptor);
            return -1;
        }
        if (cmd->exit_on_stdin_eof) {
            LOG(ERROR, "service %s: Cannot set explicit username if "
                "exit-on-client-eof=true", cmd->service_descriptor);
            return -1;
        }
        if (cmd->exit_on_stdout_eof) {
            LOG(ERROR, "service %s: Cannot set explicit username if "
                "exit-on-service-eof=true", cmd->service_descriptor);
            return -1;
        }
        free(cmd->username);
        cmd->username = tmp_user;
    }
    return res;
}

int load_service_config(struct qrexec_parsed_command *cmd,
                        int *wait_for_session, char **user) {
    int rc = load_service_config_raw(cmd, user);
    if (rc >= 0) {
        *wait_for_session = cmd->wait_for_session;
        free(user);
    }
    return rc;
}

/* Duplicates a buffer and adds a NUL terminator.
 * Same as strndup(), except that it logs on failure (with PERROR())
 * and always copies exactly "len" bytes, even if some of them are NUL
 * bytes.  This guarantees that the output buffer is of the expected
 * length and saves an unneeded call to strnlen(). */
static char* memdupnul(const char *ptr, size_t len) {
    char *buf = malloc(len + 1);
    if (buf == NULL) {
        PERROR("malloc");
        return NULL;
    }
    memcpy(buf, ptr, len);
    buf[len] = '\0';
    return buf;
}

struct qrexec_parsed_command *parse_qubes_rpc_command(
    const char *cmdline, bool strip_username) {

    struct qrexec_parsed_command *cmd;

    if (!(cmd = calloc(1, sizeof(*cmd)))) {
        PERROR("calloc");
        return NULL;
    }

    cmd->send_service_descriptor = true;
    cmd->cmdline = cmdline;

    if (strip_username) {
        const char *colon = strchr(cmdline, ':');
        if (!colon) {
            LOG(ERROR, "Bad command from dom0 (%s): no colon", cmdline);
            goto err;
        }
        cmd->username = memdupnul(cmdline, (size_t)(colon - cmdline));
        if (!cmd->username)
            goto err;
        cmd->command = colon + 1;
    } else
        cmd->command = cmdline;

    if (strncmp(cmd->command, NOGUI_CMD_PREFIX, NOGUI_CMD_PREFIX_LEN) == 0) {
        cmd->nogui = true;
        cmd->command += NOGUI_CMD_PREFIX_LEN;
    } else
        cmd->nogui = false;

    /* If the command starts with "QUBESRPC", parse service descriptor */
    if (strncmp(cmd->command, RPC_REQUEST_COMMAND,
                RPC_REQUEST_COMMAND_LEN) == 0) {
        const char *start, *end;

        /* Check for space after "QUBESRPC" */
        if (cmd->command[RPC_REQUEST_COMMAND_LEN] != ' ') {
            LOG(ERROR, "\"" RPC_REQUEST_COMMAND "\" not followed by space");
            goto err;
        }

        /* Parse service descriptor ("qubes.Service+arg") */
        cmd->command += RPC_REQUEST_COMMAND_LEN + 1;

        start = cmd->command;
        end = strchr(start, ' ');
        if (!end) {
            LOG(ERROR, "No space found after service descriptor");
            goto err;
        }

        if (end <= start) {
            LOG(ERROR, "Service descriptor is empty (too many spaces after QUBESRPC?)");
            goto err;
        }

        size_t const descriptor_len = cmd->service_descriptor_len = (size_t)(end - start);
        if (descriptor_len > MAX_SERVICE_NAME_LEN) {
            LOG(ERROR, "Command too long (length %zu)", descriptor_len);
            goto err;
        }

        /* Parse service name ("qubes.Service") */

        char *const plus = memchr(start, '+', descriptor_len);
        size_t const name_len = plus != NULL ? (size_t)(plus - start) : descriptor_len;
        if (name_len > NAME_MAX) {
            LOG(ERROR, "Service name too long to execute (length %zu)", name_len);
            goto err;
        }
        if (name_len < 1) {
            LOG(ERROR, "Service name empty");
            goto err;
        }
        cmd->service_name = memdupnul(start, name_len);
        if (!cmd->service_name)
            goto err;

        /* If there is no service argument, add a trailing "+" to the descriptor */
        cmd->service_descriptor = memdupnul(start, descriptor_len + (plus == NULL));
        if (!cmd->service_descriptor)
            goto err;
        if (plus == NULL)
            cmd->service_descriptor[descriptor_len] = '+';
        else
            cmd->arg = cmd->service_descriptor + (plus + 1 - start);

        /* Parse source domain */

        start = end + 1; /* after the space */
        end = strchrnul(start, ' ');
        if (end <= start) {
            LOG(ERROR, "Source domain is empty (too many spaces after service descriptor?)");
            goto err;
        }
        cmd->source_domain = memdupnul(start, (size_t)(end - start));
        if (!cmd->source_domain)
            goto err;
    }

    return cmd;

err:
    destroy_qrexec_parsed_command(cmd);
    return NULL;
}

void destroy_qrexec_parsed_command(struct qrexec_parsed_command *cmd) {
    if (cmd == NULL)
        return;
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

    ret = execute_parsed_qubes_rpc_command(cmd, pid, stdin_fd,
                                           stdout_fd, stderr_fd, stdin_buffer);

    destroy_qrexec_parsed_command(cmd);
    return ret;
}

int execute_parsed_qubes_rpc_command(
        struct qrexec_parsed_command *cmd, int *pid, int *stdin_fd,
        int *stdout_fd, int *stderr_fd, struct buffer *stdin_buffer) {
    if (cmd->service_descriptor) {
        // Proper Qubes RPC call
        char file_path[QUBES_SOCKADDR_UN_MAX_PATH_LEN];
        struct buffer buf = { .data = file_path, .buflen = (int)sizeof(file_path) };
        int find_res = find_qrexec_service(cmd, stdin_fd, stdin_buffer, &buf);
        if (find_res != 0) {
            assert(find_res < 0);
            return find_res;
        }
        if (*stdin_fd > -1) {
            *stdout_fd = *stdin_fd;
            if (stderr_fd)
                *stderr_fd = -1;
            *pid = 0;
            return 0;
        }
        return do_fork_exec(buf.data, cmd->username, cmd->command,
                            pid, stdin_fd, stdout_fd, stderr_fd);
    } else {
        // Legacy qrexec behavior: spawn shell directly
        return do_fork_exec(NULL, cmd->username, cmd->command,
                            pid, stdin_fd, stdout_fd, stderr_fd);
    }
}
static bool validate_port(const char *port) {
#define MAXPORT "65535"
#define MAXPORTLEN (sizeof MAXPORT - 1)
    if (*port < '1' || *port > '9')
        return false;
    const char *p = port + 1;
    for (; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9')
            return false;
    }
    if (p - port > (ptrdiff_t)MAXPORTLEN)
        return false;
    if (p - port < (ptrdiff_t)MAXPORTLEN)
        return true;
    return memcmp(port, MAXPORT, MAXPORTLEN) <= 0;
#undef MAXPORT
#undef MAXPORTLEN
}

static int qubes_tcp_connect(const char *host, const char *port)
{
    // Work around a glibc bug: overly-large port numbers not rejected
    if (!validate_port(port)) {
        LOG(ERROR, "Invalid port number %s", port);
        return -1;
    }
    /* If there is ':' or '%' in the host, then this must be an IPv6 address, not IPv4. */
    bool const must_be_ipv6_addr = strchr(host, ':') != NULL || strchr(host, '%') != NULL;
    LOG(DEBUG, "Connecting to %s%s%s:%s",
               must_be_ipv6_addr ? "[" : "",
               host,
               must_be_ipv6_addr ? "]" : "",
               port);
    struct addrinfo hints = {
        .ai_flags = AI_NUMERICSERV | AI_NUMERICHOST,
        .ai_family = must_be_ipv6_addr ? AF_INET6 : AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    }, *addrs;
    int rc = getaddrinfo(host, port, &hints, &addrs);
    if (rc != 0) {
        /* data comes from symlink or from qrexec service argument, which has already
         * been sanitized */
        LOG(ERROR, "getaddrinfo(%s, %s) failed: %s", host, port, gai_strerror(rc));
        return -1;
    }
    rc = -1;
    assert(addrs != NULL && "getaddrinfo() returned zero addresses");
    assert(addrs->ai_next == NULL &&
           "getaddrinfo() returned multiple addresses despite AI_NUMERICHOST | AI_NUMERICSERV");
    int sockfd = socket(addrs->ai_family,
                        addrs->ai_socktype | SOCK_CLOEXEC,
                        addrs->ai_protocol);
    if (sockfd < 0)
        goto freeaddrs;
    {
        int one = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0)
            abort();
    }
    int res = connect(sockfd, addrs->ai_addr, addrs->ai_addrlen);
    if (res != 0) {
        PERROR("connect");
        close(sockfd);
    } else {
        rc = sockfd;
    }
freeaddrs:
    freeaddrinfo(addrs);
    return rc;
}

int find_qrexec_service(
        struct qrexec_parsed_command *cmd,
        int *socket_fd, struct buffer *stdin_buffer,
        struct buffer *path_buffer) {
    assert(cmd->service_descriptor);
    assert(path_buffer->buflen > NAME_MAX);

    const char *qrexec_service_path = getenv("QREXEC_SERVICE_PATH");
    if (!qrexec_service_path)
        qrexec_service_path = QREXEC_SERVICE_PATH;
    if (socket_fd != NULL) {
        *socket_fd = -1;
    }

    struct stat statbuf;

    int ret = find_file(qrexec_service_path, cmd->service_descriptor,
                        path_buffer->data, (size_t)path_buffer->buflen,
                        &statbuf);
    if (ret == -1)
        ret = find_file(qrexec_service_path, cmd->service_name,
                        path_buffer->data, (size_t)path_buffer->buflen,
                        &statbuf);
    if (ret < 0) {
        if (ret == -1)
            LOG(ERROR, "Service not found: %s", cmd->service_descriptor);
        else
            LOG(ERROR, "Error finding service: %s", cmd->service_descriptor);
        return ret;
    }

    if (S_ISSOCK(statbuf.st_mode)) {
        /* Socket-based service. */
        if (socket_fd == NULL) {
            goto bad_socket_service;
        }
        int s;
        if ((s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1) {
            PERROR("socket");
            return -2;
        }
        if (qubes_connect(s, path_buffer->data, strlen(path_buffer->data))) {
            PERROR("qubes_connect");
            close(s);
            return -2;
        }

        if (cmd->send_service_descriptor) {
            /* send part after "QUBESRPC ", including trailing NUL */
            const char *desc = cmd->command;
            buffer_append(stdin_buffer, desc, strlen(desc) + 1);
        }

        *socket_fd = s;
        return 0;
    } else if (S_ISLNK(statbuf.st_mode)) {
        if (socket_fd == NULL) {
            goto bad_socket_service;
        }
        /* TCP-based service */
        assert(path_buffer->buflen >= (int)sizeof("/dev/tcp") - 1);
        assert(memcmp(path_buffer->data, "/dev/tcp", sizeof("/dev/tcp") - 1) == 0);
        char *address = path_buffer->data + (sizeof("/dev/tcp") - 1);
        char *host = NULL, *port = NULL;
        if (*address == '/') {
            host = address + 1;
            char *slash = strchr(host, '/');
            if (slash != NULL) {
                *slash = '\0';
                port = slash + 1;
            }
        } else {
            assert(*address == '\0');
        }
        if (port == NULL) {
            if (cmd->arg == NULL || *cmd->arg == '\0') {
                LOG(ERROR, "No or empty argument provided, cannot connect to %s",
                    path_buffer->data);
                return -2;
            }
            if (host == NULL) {
                /* Get both host and port from service arguments */
                host = cmd->arg;
                port = strrchr(cmd->arg, '+');
                if (port == NULL) {
                    LOG(ERROR, "No port provided, cannot connect to %s", cmd->arg);
                    return -2;
                }
                *port = '\0';
                for (char *p = host; p < port; ++p) {
                    if (*p == '_') {
                        LOG(ERROR, "Underscore not allowed in hostname %s", host);
                        return -2;
                    }
                    if (*p == '+')
                        *p = ':';
                }
                port++;
            } else {
                /* Get just port from service arguments */
                port = cmd->arg;
            }
        } else {
            if (cmd->arg != NULL && *cmd->arg != '\0') {
                LOG(ERROR, "Unexpected argument %s to service %s", cmd->arg,
                    path_buffer->data);
                return -2;
            }
        }

        if (cmd->send_service_descriptor) {
            /* send part after "QUBESRPC ", including trailing NUL */
            const char *desc = cmd->command;
            buffer_append(stdin_buffer, desc, strlen(desc) + 1);
        }

        int res = qubes_tcp_connect(host, port);
        if (res == -1)
            return -2;
        *socket_fd = res;
        return 0;
    }

    if (euidaccess(path_buffer->data, X_OK) == 0) {
        /* Executable-based service. */
        if (!cmd->send_service_descriptor) {
            LOG(WARNING, "Warning: ignoring skip-service-descriptor=true "
                         "for execute executable service %s",
                path_buffer->data);
        }
        if (cmd->exit_on_stdout_eof) {
            LOG(WARNING, "Warning: ignoring exit-on-service-eof=true "
                         "for executable service %s",
                path_buffer->data);
            cmd->exit_on_stdout_eof = false;
        }
        if (cmd->exit_on_stdin_eof) {
            LOG(WARNING, "Warning: ignoring exit-on-client-eof=true "
                         "for executable service %s",
                path_buffer->data);
            cmd->exit_on_stdin_eof = false;
        }
        return 0;
    }

    LOG(ERROR, "Unknown service type (not executable, not a socket): %.*s",
        path_buffer->buflen, path_buffer->data);
    return -2;
bad_socket_service:
    LOG(ERROR, "Service %.*s is a socket or /dev/tcp symlink, but this is not "
               "supported for dom0 -> dom0 calls",
        path_buffer->buflen, path_buffer->data);
    return -2;
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
