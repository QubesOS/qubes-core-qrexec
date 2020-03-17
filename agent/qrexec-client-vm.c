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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include "libqrexec-utils.h"
#include "qrexec.h"
#include "qrexec-agent.h"

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
};

static struct option longopts[] = {
    { "buffer-size", required_argument, 0,  'b' },
    { "filter-escape-chars-stdout", no_argument, 0, 't'},
    { "filter-escape-chars-stderr", no_argument, 0, 'T'},
    { "no-filter-escape-chars-stdout", no_argument, 0, opt_no_filter_stdout},
    { "no-filter-escape-chars-stderr", no_argument, 0, opt_no_filter_stderr},
    { "agent-socket", required_argument, 0, 'a'},
    { NULL, 0, 0, 0},
};

_Noreturn static void usage(const char *argv0) {
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
    exit(2);
}

int main(int argc, char **argv)
{
    int trigger_fd;
    struct msg_header hdr;
    struct trigger_service_params3 params;
    struct exec_params exec_params;
    size_t service_name_len;
    char *service_name;
    ssize_t ret;
    int i;
    int start_local_process = 0;
    char *abs_exec_path;
    pid_t child_pid = 0;
    int inpipe[2], outpipe[2];
    int buffer_size = 0;
    int opt;
    const char *agent_trigger_path = QREXEC_AGENT_TRIGGER_PATH;

    setup_logging("qrexec-client-vm");

    // TODO: this should be in process_io
    signal(SIGPIPE, SIG_IGN);

    while (1) {
        opt = getopt_long(argc, argv, "+tTa:", longopts, NULL);
        if (opt == -1)
            break;
        switch (opt) {
            case 'b':
                buffer_size = atoi(optarg);
                break;
            case 't':
                replace_chars_stdout = 1;
                break;
            case 'T':
                replace_chars_stderr = 1;
                break;
            case opt_no_filter_stdout:
                replace_chars_stdout = 0;
                break;
            case opt_no_filter_stderr:
                replace_chars_stderr = 0;
                break;
            case 'a':
                agent_trigger_path = strdup(optarg);
                break;
            case '?':
                usage(argv[0]);
        }
    }

    if (argc - optind < 2) {
        usage(argv[0]);
    }
    if (argc - optind > 2) {
        start_local_process = 1;
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

    snprintf(params.request_id.ident,
            sizeof(params.request_id.ident), "SOCKET");

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
        exit(126);
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
                        if (asprintf(&env, "SAVED_FD_%d=%d", i, dup(i)) < 0) {
                            PERROR("prepare SAVED_FD_");
                            exit(1);
                        }
                        putenv(env);
                    }
                }

                dup2(inpipe[0], 0);
                dup2(outpipe[1], 1);
                close(inpipe[0]);
                close(outpipe[1]);

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
                inpipe[1], outpipe[0], -1, buffer_size, child_pid);
    } else {
        ret = handle_data_client(MSG_SERVICE_CONNECT,
                exec_params.connect_domain, exec_params.connect_port,
                1, 0, -1, buffer_size, 0);
    }

    close(trigger_fd);
    return (int)ret;
}
