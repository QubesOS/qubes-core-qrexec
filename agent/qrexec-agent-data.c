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
#include <inttypes.h>
#include <string.h>
#include <stddef.h>
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

#define QREXEC_DATA_MIN_VERSION QREXEC_PROTOCOL_V2

static volatile sig_atomic_t sigchld = 0;
static volatile sig_atomic_t sigusr1 = 0;

/* whether qrexec-client should replace problematic bytes with _ before printing the output;
 * positive value will enable the feature
 */
int replace_chars_stdout = -1;
int replace_chars_stderr = -1;

static void sigchld_handler(int __attribute__((__unused__))x)
{
    sigchld = 1;
}

static void sigusr1_handler(int __attribute__((__unused__))x)
{
    sigusr1 = 1;
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
        LOG(ERROR, "Failed to send HELLO hdr to agent");
        return -1;
    }

    if (libvchan_send(ctrl, &info, sizeof(info)) != sizeof(info)) {
        LOG(ERROR, "Failed to send HELLO hdr to agent");
        return -1;
    }

    /* receive MSG_HELLO from remote */
    if (libvchan_recv(ctrl, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        LOG(ERROR, "Failed to read agent HELLO hdr");
        return -1;
    }

    if (hdr.type != MSG_HELLO || hdr.len != sizeof(info)) {
        LOG(ERROR, "Invalid HELLO packet received: type %d, len %d", hdr.type, hdr.len);
        return -1;
    }

    if (libvchan_recv(ctrl, &info, sizeof(info)) != sizeof(info)) {
        LOG(ERROR, "Failed to read agent HELLO body");
        return -1;
    }

    actual_version = info.version < QREXEC_PROTOCOL_VERSION ? info.version : QREXEC_PROTOCOL_VERSION;

    if (actual_version < QREXEC_DATA_MIN_VERSION) {
        LOG(ERROR, "Incompatible agent protocol version (remote %d, local %d)", info.version, QREXEC_PROTOCOL_VERSION);
        return -1;
    }

    return actual_version;
}


static int handle_just_exec(char *cmdline)
{
    int fdn, pid;

    char *end_username = strchr(cmdline, ':');
    if (!end_username) {
        LOG(ERROR, "No colon in command from dom0");
        return -1;
    }
    *end_username++ = '\0';
    switch (pid = fork()) {
        case -1:
            PERROR("fork");
            return -1;
        case 0:
            fdn = open("/dev/null", O_RDWR);
            fix_fds(fdn, fdn, fdn);
            do_exec(end_username, cmdline);
        default:;
    }
    LOG(INFO, "executed (nowait): %s (pid %d)", cmdline, pid);
    return 0;
}

/* Behaviour depends on type parameter:
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
static int handle_new_process_common(
    int type, int connect_domain, int connect_port,
    char *cmdline, size_t cmdline_len,
    int buffer_size)
{
    libvchan_t *data_vchan;
    int exit_code;
    int data_protocol_version;
    struct buffer stdin_buf;
    struct process_io_request req;
    int stdin_fd, stdout_fd, stderr_fd;
    pid_t pid;

    assert(type != MSG_SERVICE_CONNECT);

    if (buffer_size == 0)
        buffer_size = VCHAN_BUFFER_SIZE;

    if (cmdline == NULL) {
        LOG(ERROR, "internal qrexec error: NULL cmdline passed to a non-MSG_SERVICE_CONNECT call");
        abort();
    } else if (cmdline_len == 0) {
        LOG(ERROR, "internal qrexec error: zero-length command line passed to a non-MSG_SERVICE_CONNECT call");
        abort();
    } else if (cmdline_len > MAX_QREXEC_CMD_LEN) {
        /* This is arbitrary, but it helps reduce the risk of overflows in other code */
        LOG(ERROR, "Bad command from dom0: command line too long: length %zu", cmdline_len);
        abort();
    }
    cmdline[cmdline_len-1] = 0;
    data_vchan = libvchan_client_init(connect_domain, connect_port);
    if (!data_vchan) {
        LOG(ERROR, "Data vchan connection failed");
        exit(1);
    }
    data_protocol_version = handle_handshake(data_vchan);
    if (data_protocol_version < 0) {
        exit(1);
    }

    prepare_child_env();
    /* TODO: use setresuid to allow child process to actually send the signal? */

    switch (type) {
        case MSG_JUST_EXEC:
            if (send_exit_code(data_vchan, handle_just_exec(cmdline)) < 0)
                handle_vchan_error("just_exec");
            libvchan_close(data_vchan);
            return 0;
        case MSG_EXEC_CMDLINE:
            buffer_init(&stdin_buf);
            if (execute_qubes_rpc_command(cmdline, &pid, &stdin_fd, &stdout_fd, &stderr_fd, !qrexec_is_fork_server, &stdin_buf) < 0) {
                struct msg_header hdr = {
                    .type = MSG_DATA_STDOUT,
                    .len = 0,
                };
                LOG(ERROR, "failed to spawn process");
                /* Send stdout+stderr EOF first, since the service is expected to send
                 * one before exit code in case of MSG_EXEC_CMDLINE. Ignore
                 * libvchan_send error if any, as we're going to terminate soon
                 * anyway.
                 */
                libvchan_send(data_vchan, &hdr, sizeof(hdr));
                hdr.type = MSG_DATA_STDERR;
                libvchan_send(data_vchan, &hdr, sizeof(hdr));
                exit_code = 127;
                send_exit_code(data_vchan, exit_code);
                libvchan_close(data_vchan);
                return exit_code;
            }
            LOG(INFO, "executed: %s (pid %d)", cmdline, pid);
            break;
        default:
            LOG(ERROR, "unknown request type: %d", type);
            libvchan_close(data_vchan);
            return 0;
    }

    req.vchan = data_vchan;
    req.stdin_buf = &stdin_buf;

    req.stdin_fd = stdin_fd;
    req.stdout_fd = stdout_fd;
    req.stderr_fd = stderr_fd;
    req.local_pid = pid;

    req.is_service = true;

    req.replace_chars_stdout = replace_chars_stdout > 0;
    req.replace_chars_stderr = replace_chars_stderr > 0;
    req.data_protocol_version = data_protocol_version;

    req.sigchld = &sigchld;
    req.sigusr1 = &sigusr1;

    exit_code = process_io(&req);

    if (type == MSG_EXEC_CMDLINE)
        LOG(INFO, "pid %d exited with %d", pid, exit_code);

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
            PERROR("fork");
            return -1;
        case 0:
            break;
        default:
            return pid;
    }

    /* child process */
    exit_code = handle_new_process_common(type, connect_domain, connect_port,
                                          cmdline, cmdline_len, 0);

    exit(exit_code);
}

/* Returns exit code of remote process */
int handle_data_client(
    int type, int connect_domain, int connect_port,
    int stdin_fd, int stdout_fd, int stderr_fd, int buffer_size, pid_t pid)
{
    int exit_code;
    int data_protocol_version;
    libvchan_t *data_vchan;
    struct process_io_request req;
    struct buffer stdin_buf;

    assert(type == MSG_SERVICE_CONNECT);
    if (buffer_size == 0)
        buffer_size = VCHAN_BUFFER_SIZE;

    data_vchan = libvchan_server_init(connect_domain, connect_port,
                                      buffer_size, buffer_size);
    if (!data_vchan) {
        LOG(ERROR, "Data vchan connection failed");
        exit(1);
    }
    libvchan_wait(data_vchan);
    data_protocol_version = handle_handshake(data_vchan);
    if (data_protocol_version < 0) {
        exit(1);
    }

    buffer_init(&stdin_buf);

    req.vchan = data_vchan;
    req.stdin_buf = &stdin_buf;

    req.stdin_fd = stdin_fd;
    req.stdout_fd = stdout_fd;
    req.stderr_fd = stderr_fd;
    req.local_pid = pid;

    req.is_service = false;

    req.replace_chars_stdout = replace_chars_stdout > 0;
    req.replace_chars_stderr = replace_chars_stderr > 0;
    req.data_protocol_version = data_protocol_version;

    req.sigchld = &sigchld;
    req.sigusr1 = &sigusr1;

    exit_code = process_io(&req);
    libvchan_close(data_vchan);
    return exit_code;
}

/* Local Variables: */
/* mode: c */
/* indent-tabs-mode: nil */
/* c-basic-offset: 4 */
/* coding: utf-8-unix */
/* End: */
