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
#include <assert.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include "libqrexec-utils.h"
#include "qrexec.h"
#include "qrexec-agent.h"
#include <err.h>

const bool qrexec_is_fork_server = false;

_Noreturn void handle_vchan_error(const char *op)
{
    LOG(ERROR, "Error while vchan %s, exiting", op);
    exit(1);
}

_Noreturn void do_exec(const char *cmd __attribute__((unused)), char const* user __attribute__((__unused__))) {
    LOG(ERROR, "BUG: do_exec function shouldn't be called!");
    abort();
}

static int connect_unix_socket(const char *path)
{
    int s;
    size_t len;
    struct sockaddr_un remote;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        PERROR("socket");
        return -1;
    }

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, path,
            sizeof(remote.sun_path) - 1);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *) &remote, (socklen_t)len) == -1) {
        PERROR("connect");
        exit(1);
    }
    return s;
}

static char *get_program_name(char *prog)
{
    char *basename = rindex(prog, '/');
    if (basename)
        return basename + 1;
    else
        return prog;
}

/* Target specification with keyword have changed from $... to @... . Convert
 * the argument appropriately, to avoid breaking user tools.
 */
static void convert_target_name_keyword(char *target)
{
    size_t i;
    size_t len = strlen(target);

    for (i = 0; i < len; i++)
        if (target[i] == '$')
            target[i] = '@';
}

enum {
    opt_no_filter_stdout = 't'+128,
    opt_no_filter_stderr = 'T'+128,
    opt_use_stdin_socket = 'u'+128,
};

static struct option longopts[] = {
    { "buffer-size", required_argument, 0,  'b' },
    { "filter-escape-chars-stdout", no_argument, 0, 't'},
    { "filter-escape-chars-stderr", no_argument, 0, 'T'},
    { "no-filter-escape-chars-stdout", no_argument, 0, opt_no_filter_stdout},
    { "no-filter-escape-chars-stderr", no_argument, 0, opt_no_filter_stderr},
    { "agent-socket", required_argument, 0, 'a'},
    { "prefix-data", required_argument, 0, 'p' },
    { "use-stdin-socket", no_argument, 0, opt_use_stdin_socket },
    { "help", no_argument, 0, 'h' },
    { NULL, 0, 0, 0},
};

_Noreturn static void usage(const char *argv0, int status) {
    fprintf(stderr,
            "usage: %s [options] target_vmname program_ident [local_program [local program arguments]]\n",
            argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --buffer-size=BUFFER_SIZE - minimum vchan buffer size (default: 64k)\n");
    fprintf(stderr, "  -t, --filter-escape-chars-stdout - filter non-ASCII and control characters on stdout (default if stdout is a terminal)\n");
    fprintf(stderr, "  -T, --filter-escape-chars-stderr - filter non-ASCII and control characters on stderr (default if stderr is a terminal)\n");
    fprintf(stderr, "  --no-filter-escape-chars-stdout - opposite to --filter-escape-chars-stdout\n");
    fprintf(stderr, "  --no-filter-escape-chars-stderr - opposite to --filter-escape-chars-stderr\n");
    fprintf(stderr, "  --agent-socket=PATH - path to connect to, default: %s\n",
            QREXEC_AGENT_TRIGGER_PATH);
    fprintf(stderr, "  -h, --help - print this message\n");
    fprintf(stderr, "  -p PREFIX-DATA, --prefix-data=PREFIX-DATA - send the given data before the provided stdin (can only be used once)\n");
    exit(status);
}

int main(int argc, char **argv)
{
    int trigger_fd;
    struct msg_header hdr;
    struct trigger_service_params3 params;
    struct exec_params exec_params;
    size_t service_name_len;
    char *service_name, *endptr;
    ssize_t ret;
    int i;
    int start_local_process = 0;
    char *abs_exec_path;
    pid_t child_pid = 0;
    int inpipe[2], outpipe[2];
    int buffer_size = 0;
    int opt;
    int stdout_fd = 1;
    const char *agent_trigger_path = QREXEC_AGENT_TRIGGER_PATH, *prefix_data = NULL;

    setup_logging("qrexec-client-vm");

    // TODO: this should be in qrexec_process_io
    signal(SIGPIPE, SIG_IGN);

    while (1) {
        opt = getopt_long(argc, argv, "+tTa:hp:", longopts, NULL);
        if (opt == -1)
            break;
        switch (opt) {
            case 'b': {
                if (*optarg < '0' || *optarg > '9') {
                    fputs("Bad buffer size: does not begin with a number\n", stderr);
                    exit(1);
                }
                errno = 0;
                unsigned long res = strtoul(optarg, &endptr, 0);
                if (res > INT_MAX)
                    errno = ERANGE;
                if (errno) {
                    PERROR("strtoul");
                    exit(1);
                }
                if (*endptr) {
                    fputs("Bad buffer size: trailing junk\n", stderr);
                    exit(1);
                }
                buffer_size = (int)res;
                break;
            }
            case 't':
                replace_chars_stdout = 1;
                break;
            case 'T':
                replace_chars_stderr = 1;
                break;
            case 'h':
                usage(argv[0], 0);
            case 'p':
                if (prefix_data)
                    usage(argv[0], 2);
                prefix_data = optarg;
                break;
            case opt_no_filter_stdout:
                replace_chars_stdout = 0;
                break;
            case opt_no_filter_stderr:
                replace_chars_stderr = 0;
                break;
            case 'a':
                if ((agent_trigger_path = strdup(optarg)) == NULL) {
                    PERROR("strdup");
                    exit(1);
                }
                break;
            case opt_use_stdin_socket:
                {
                    int type;
                    if (stdout_fd == 0)
                        errx(2, "--use-stdin-socket passed twice");
                    socklen_t len = sizeof(type);
                    if (getsockopt(0, SOL_SOCKET, SO_TYPE, &type, &len)) {
                        if (errno == ENOTSOCK)
                            errx(2, "--use-stdin-socket passed, but stdin not a socket");
                        err(2, "getsockopt(0, SOL_SOCKET, SO_TYPE)");
                    }
                    assert(len == sizeof(type));
                    if (type != SOCK_STREAM)
                        errx(2, "stdin was a socket of type %d, not SOCK_STREAM (%d)", type, SOCK_STREAM);
                    stdout_fd = 0;
                }
                break;
            case '?':
                usage(argv[0], 2);
        }
    }

    if (argc - optind < 2) {
        usage(argv[0], 2);
    }
    if (argc - optind > 2) {
        start_local_process = 1;
    }
    if (start_local_process && stdout_fd != 1) {
        fprintf(stderr, "cannot spawn a local process with --use-stdin-socket\n");
        usage(argv[0], 2);
    }

    if (!start_local_process) {
        if (replace_chars_stdout == -1 && isatty(1))
            replace_chars_stdout = 1;
    }
    if (replace_chars_stderr == -1 && isatty(2))
        replace_chars_stderr = 1;

    service_name = argv[optind + 1];

    service_name_len = strlen(service_name) + 1;

    trigger_fd = connect_unix_socket(agent_trigger_path);

    hdr.type = MSG_TRIGGER_SERVICE3;
    hdr.len = sizeof(params) + service_name_len;

    memset(&params, 0, sizeof(params));

    convert_target_name_keyword(argv[optind]);
    strncpy(params.target_domain, argv[optind],
            sizeof(params.target_domain) - 1);

    memcpy(params.request_id.ident, "SOCKET", sizeof("SOCKET"));

    if (!write_all(trigger_fd, &hdr, sizeof(hdr))) {
        PERROR("write(hdr) to agent");
        exit(1);
    }
    if (!write_all(trigger_fd, &params, sizeof(params))) {
        PERROR("write(params) to agent");
        exit(1);
    }
    if (!write_all(trigger_fd, service_name, service_name_len)) {
        PERROR("write(command) to agent");
        exit(1);
    }
    ret = read(trigger_fd, &exec_params, sizeof(exec_params));
    if (ret == 0) {
        fprintf(stderr, "Request refused\n");
        exit(QREXEC_EXIT_REQUEST_REFUSED);
    }
    if (ret < 0 || ret != sizeof(exec_params)) {
        PERROR("read");
        exit(1);
    }

    if (start_local_process) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, inpipe) ||
                socketpair(AF_UNIX, SOCK_STREAM, 0, outpipe)) {
            PERROR("socketpair");
            exit(1);
        }
        prepare_child_env();

        switch (child_pid = fork()) {
            case -1:
                PERROR("fork");
                exit(-1);
            case 0:
                close(inpipe[1]);
                close(outpipe[0]);
                close(trigger_fd);
                for (i = 0; i < 3; i++) {
                    if (i != 2 || getenv("PASS_LOCAL_STDERR")) {
                        char *env;
                        int dup_fd = dup(i);
                        if (dup_fd < 0 || asprintf(&env, "SAVED_FD_%d=%d", i, dup_fd) < 0 || putenv(env)) {
                            PERROR("prepare SAVED_FD_");
                            exit(1);
                        }
                    }
                }

                if (dup2(inpipe[0], 0) != 0 || dup2(outpipe[1], 1) != 1)
                    err(1, "dup2()");
                if (close(inpipe[0]) || close(outpipe[1]))
                    err(1, "close()");

                abs_exec_path = strdup(argv[optind + 2]);
                argv[optind + 2] = get_program_name(argv[optind + 2]);
                execv(abs_exec_path, argv + optind + 2);
                PERROR("execv");
                exit(-1);
        }
        close(inpipe[0]);
        close(outpipe[1]);

        ret = handle_data_client(MSG_SERVICE_CONNECT,
                exec_params.connect_domain, exec_params.connect_port,
                inpipe[1], outpipe[0], buffer_size, child_pid, prefix_data);
    } else {
        ret = handle_data_client(MSG_SERVICE_CONNECT,
                exec_params.connect_domain, exec_params.connect_port,
                stdout_fd, 0, buffer_size, 0, prefix_data);
    }

    close(trigger_fd);
    return (int)ret;
}
