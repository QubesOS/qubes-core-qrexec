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

#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <poll.h>
#include <errno.h>
#include <assert.h>
#include "qrexec.h"
#include <fcntl.h>
#include <err.h>
#include <time.h>

#include "libqrexec-utils.h"
#include "qrexec-daemon-common.h"

#define VCHAN_BUFFER_SIZE 65536

extern char **environ;

static char *xstrdup(const char *arg) {
    char *retval = strdup(arg);
    if (!retval) {
        LOG(ERROR, "Out of memory in xstrdup()");
        abort();
    }
    return retval;
}

static void set_remote_domain(const char *src_domain_name) {
    if (setenv("QREXEC_REMOTE_DOMAIN", src_domain_name, 1)) {
        LOG(ERROR, "Cannot set QREXEC_REMOTE_DOMAIN");
        abort();
    }
}

/* called from do_fork_exec */
static _Noreturn void do_exec(const char *prog,
                              const char *cmdline,
                              const char *username __attribute__((unused)))
{
    /* avoid calling RPC service through shell */
    if (prog) {
        /* qrexec-client is always in a login session. */
        exec_qubes_rpc2(prog, cmdline, environ, false);
    }

    /* if above haven't executed RPC service, pass it to shell */
    execl("/bin/bash", "bash", "-c", cmdline, NULL);
    PERROR("exec bash");
    exit(1);
}
enum {
    opt_socket_dir = 'd'+128,
    opt_use_stdin_socket = 'u'+128,
};

static struct option longopts[] = {
    { "help", no_argument, 0, 'h' },
    { "socket-dir", required_argument, 0, opt_socket_dir },
    { "no-exit-code", no_argument, 0, 'E' },
    { "use-stdin-socket", no_argument, 0, opt_use_stdin_socket },
    { NULL, 0, 0, 0 },
};

_Noreturn static void usage(const char *const name, int status)
{
    FILE *stream = status ? stderr : stdout;
    fprintf(stream,
            "usage: %s [options] -d domain_name ["
            "-l local_prog|"
            "-c request_id,src_domain_name,src_domain_id|"
            "-e] user:remote_cmdline\n"
            "Options:\n"
            "  -h, --help - display usage\n"
            "  -e - exit after sending cmd\n"
            "  -E, --no-exit-code - always exit with 0 after command exits\n"
            "  -t - enables replacing problematic bytes with '_' in command output, -T is the same for stderr\n"
            "  -W - waits for connection end even in case of VM-VM (-c)\n"
            "  -c - connect to existing process (response to trigger service call)\n"
            "  -w timeout - override default connection timeout of 5s (set 0 for no timeout)\n"
            "  -k - kill the domain right before exiting\n"
            "  --socket-dir=PATH -  directory for qrexec socket, default: %s\n"
            "  --use-stdin-socket - use fd 0 (which must be socket) for both stdin and stdout\n",
            name ? name : "qrexec-client", QREXEC_DAEMON_SOCKET_DIR);
    exit(status);
}

static int parse_int(const char *str, const char *msg) {
    long value;
    char *end = (char *)str;

    if (str[0] < '0' || str[0] > '9')
        errx(1, "%s '%s' does not start with an ASCII digit", msg, str);
    errno = 0;
    value = strtol(str, &end, 0);
    if (*end != '\0')
        errx(1, "trailing junk '%s' after %s", end, msg);
    if (errno == 0 && (value < 0 || value > INT_MAX))
        errno = ERANGE;
    if (errno)
        err(1, "invalid %s '%s': strtol", msg, str);
    return (int)value;
}

static void parse_connect(char *str, char **request_id,
        char **src_domain_name, int *src_domain_id)
{
    char *token;

    token = strchr(str, ',');
    if (token == NULL)
        goto bad_c_param;
    if ((size_t)(token - str) >= sizeof(struct service_params))
        errx(1, "Invalid -c parameter (request_id too long, max %zu)",
             sizeof(struct service_params)-1);
    *token = 0;
    *request_id = str;
    *src_domain_name = token + 1;
    token = strchr(*src_domain_name, ',');
    if (token == NULL)
        goto bad_c_param;
    *token = 0;
    *src_domain_id = parse_int(token + 1, "source domain ID");
    return;
bad_c_param:
    fprintf(stderr, "Invalid -c parameter (should be: \"-c request_id,src_domain_name,src_domain_id\")\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int opt;
    char *domname = NULL;
    libvchan_t *data_vchan = NULL;
    int data_port;
    int data_domain;
    int s;
    bool just_exec = false;
    char *local_cmdline = NULL;
    char *remote_cmdline = NULL;
    char *request_id = NULL;
    char *src_domain_name = NULL;
    int src_domain_id = 0; /* if not -c given, the process is run in dom0 */
    int connection_timeout = 5;
    struct service_params svc_params;
    int prepare_ret;
    bool kill = false;
    bool replace_chars_stdout = false;
    bool replace_chars_stderr = false;
    bool wait_connection_end = false;
    bool exit_with_code = true;
    int rc = QREXEC_EXIT_PROBLEM;

    setup_logging("qrexec-client");

    while ((opt = getopt_long(argc, argv, "hd:l:eEc:tTw:Wk", longopts, NULL)) != -1) {
        switch (opt) {
            case 'd':
                domname = xstrdup(optarg);
                break;
            case 'l':
                local_cmdline = xstrdup(optarg);
                break;
            case 'e':
                just_exec = true;
                break;
            case 'E':
                exit_with_code = false;
                break;
            case 'c':
                if (request_id != NULL) {
                    warnx("ERROR: -c passed more than once");
                    usage(argv[0], 1);
                }
                parse_connect(optarg, &request_id, &src_domain_name, &src_domain_id);
                if (target_refers_to_dom0(src_domain_name) || src_domain_id == 0) {
                    warnx("ERROR: -c cannot be used for requests to dom0");
                    usage(argv[0], 1);
                }
                break;
            case 't':
                replace_chars_stdout = true;
                break;
            case 'T':
                replace_chars_stderr = true;
                break;
            case 'w':
                connection_timeout = parse_int(optarg, "connection timeout");
                break;
            case 'W':
                wait_connection_end = true;
                break;
            case opt_socket_dir:
                socket_dir = strdup(optarg);
                break;
            case opt_use_stdin_socket:
                {
                    int type;
                    if (local_stdin_fd != 1)
                        errx(2, "--use-stdin-socket passed twice");
                    socklen_t len = sizeof(type);
                    if (getsockopt(0, SOL_SOCKET, SO_TYPE, &type, &len)) {
                        if (errno == ENOTSOCK)
                            errx(2, "--use-stdin-socket passed, but stdin not a socket");
                        err(2, "getsockopt(0, SOL_SOCKET, SO_TYPE)");
                    }
                    assert(len == sizeof(type) && "wrong socket option length?");
                    if (type != SOCK_STREAM)
                        errx(2, "stdin was a socket of type %d, not SOCK_STREAM (%d)", type, SOCK_STREAM);
                    local_stdin_fd = 0;
                }
                break;
            case 'k':
                kill = true;
                break;
            case 'h':
            default:
                usage(argv[0], 0);
        }
    }
    if (optind >= argc || !domname)
        usage(argv[0], 1);
    remote_cmdline = argv[optind];

    signal(SIGPIPE, SIG_IGN);

    register_exec_func(&do_exec);

    if (just_exec + (request_id != NULL) + (local_cmdline != NULL) > 1) {
        fprintf(stderr, "ERROR: only one of -e, -l, -c can be specified\n");
        usage(argv[0], 1);
    }

    if ((local_cmdline != NULL) && (local_stdin_fd != 1)) {
        fprintf(stderr, "ERROR: at most one of -l and --use-stdin-socket can be specified\n");
        usage(argv[0], 1);
    }

    if (target_refers_to_dom0(domname)) {
        if (request_id != NULL) {
            if (request_id[0] == '\0') {
                warnx("ERROR: request ID cannot be empty");
                usage(argv[0], 1);
            }
            strncpy(svc_params.ident, request_id, sizeof(svc_params.ident) - 1);
            svc_params.ident[sizeof(svc_params.ident) - 1] = '\0';
            if (src_domain_name == NULL) {
                LOG(ERROR, "internal error: src_domain_name should not be NULL here");
                abort();
            }
            rc = run_qrexec_to_dom0(&svc_params,
                                    src_domain_id,
                                    src_domain_name,
                                    remote_cmdline,
                                    connection_timeout,
                                    exit_with_code);
        } else {
            /* dom0 -> dom0 fake service call */
            assert(src_domain_id == 0);
            if (local_cmdline != NULL) {
                warnx("dom0 -> dom0 qrexec calls with LOCAL_COMMAND not yet implemented");
                errx(QREXEC_EXIT_PROBLEM, "please file an issue if you need this");
            }
            /*
             * Normally calls to dom0 omit the username, but in this case
             * that would require the caller to pass the user if and only if the target is _not_
             * dom0, and that's annoying.  In the past, qrexec-client was called by qrexec-daemon
             * which got it right, but now the main caller of qrexec-client is Python scripts
             * that don't have access to the C target_refers_to_dom0() function.
             * Therefore, parse the username and fail if it is not "DEFAULT".
             */
#define DEFAULT_USER "DEFAULT"
            if (strncmp(remote_cmdline, DEFAULT_USER ":", sizeof(DEFAULT_USER)) != 0) {
                errx(QREXEC_EXIT_PROBLEM, "dom0 -> dom0 commands must be prefixed with " DEFAULT_USER ":");
            }
            remote_cmdline += sizeof(DEFAULT_USER);
            struct qrexec_parsed_command *command = parse_qubes_rpc_command(remote_cmdline, false);
            int prepare_ret;
            char file_path[QUBES_SOCKADDR_UN_MAX_PATH_LEN];
            struct buffer buf = { .data = file_path, .buflen = (int)sizeof(file_path) };
            if (command == NULL) {
                prepare_ret = -2;
            } else if (command->service_descriptor == NULL) {
                LOG(ERROR, "For dom0 -> dom0 commands, only proper qrexec calls are allowed");
                prepare_ret = -2;
            } else if (!wait_for_session_maybe(command)) {
                LOG(ERROR, "Cannot load service configuration, or forking process failed");
                prepare_ret = -2;
            } else {
                prepare_ret = find_qrexec_service(command, NULL, NULL, &buf);
            }
            switch (prepare_ret) {
            case -2:
                rc = QREXEC_EXIT_PROBLEM;
                break;
            case -1:
                rc = QREXEC_EXIT_SERVICE_NOT_FOUND;
                break;
            case 0:
                assert(command->username == NULL);
                assert(command->command);
                /* qrexec-client is always in a login session. */
                exec_qubes_rpc2(buf.data, command->command, environ, false);
                /* not reached */
            default:
                assert(false);
                rc = QREXEC_EXIT_PROBLEM;
                break;
            }
        }
    } else {
        if (request_id) {
            bool const use_uuid = strncmp(domname, "uuid:", 5) == 0;
            rc = qrexec_execute_vm(domname, false, src_domain_id,
                                   remote_cmdline, strlen(remote_cmdline) + 1,
                                   request_id, just_exec,
                                   wait_connection_end, use_uuid) ? 0 : 137;
        } else {
            s = connect_unix_socket(domname);
            if (!negotiate_connection_params(s,
                        src_domain_id,
                        just_exec ? MSG_JUST_EXEC : MSG_EXEC_CMDLINE,
                        remote_cmdline,
                        strlen(remote_cmdline) + 1,
                        &data_domain,
                        &data_port)) {
                goto cleanup;
            }
            set_remote_domain(domname);
            struct buffer stdin_buffer;
            buffer_init(&stdin_buffer);
            if (local_cmdline != NULL) {
                struct qrexec_parsed_command *command =
                    parse_qubes_rpc_command(local_cmdline, false);
                if (!command)
                    prepare_ret = QREXEC_EXIT_PROBLEM;
                else {
                    prepare_ret = prepare_local_fds(command, &stdin_buffer);
                    /* Don't pass this to handshake_and_go() as this is not
                     * a service call to dom0. */
                    destroy_qrexec_parsed_command(command);
                }
            } else {
                prepare_ret = 0;
            }

            data_vchan = libvchan_server_init(data_domain, data_port,
                    VCHAN_BUFFER_SIZE, VCHAN_BUFFER_SIZE);
            if (!data_vchan) {
                LOG(ERROR, "Failed to start data vchan server");
                rc = QREXEC_EXIT_PROBLEM;
                goto cleanup;
            }
            int fd = libvchan_fd_for_select(data_vchan);
            if (qubes_wait_for_vchan_connection_with_timeout(
                        data_vchan, fd, true, connection_timeout) < 0) {
                LOG(ERROR, "qrexec connection timeout");
                libvchan_close(data_vchan);
                rc = QREXEC_EXIT_PROBLEM;
                goto cleanup;
            }
            struct handshake_params params = {
                .data_vchan = data_vchan,
                .stdin_buffer = &stdin_buffer,
                .remote_send_first = false,
                .prepare_ret = prepare_ret,
                .exit_with_code = exit_with_code,
                .replace_chars_stdout = replace_chars_stdout,
                .replace_chars_stderr = replace_chars_stderr,
            };
            rc = handshake_and_go(&params, NULL);
cleanup:
            if (kill && domname) {
                size_t l;
                qubesd_call(domname, "admin.vm.Kill", "", &l);
            }
        }
    }

    return rc;
}

// vim:ts=4:sw=4:et:
