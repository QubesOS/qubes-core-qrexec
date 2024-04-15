#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>

#include "qrexec.h"
#include "libqrexec-utils.h"
#include "qrexec-daemon-common.h"

const char *socket_dir = QREXEC_DAEMON_SOCKET_DIR;

/* ask the daemon to allocate vchan port */
bool negotiate_connection_params(int s, int other_domid, unsigned type,
        const void *cmdline_param, int cmdline_size,
        int *data_domain, int *data_port)
{
    struct msg_header hdr;
    struct exec_params params;
    hdr.type = type;
    hdr.len = sizeof(params) + cmdline_size;
    params.connect_domain = other_domid;
    params.connect_port = 0;
    if (!write_all(s, &hdr, sizeof(hdr))
            || !write_all(s, &params, sizeof(params))
            || !write_all(s, cmdline_param, cmdline_size)) {
        PERROR("write daemon");
        return false;
    }
    /* the daemon will respond with the same message with connect_port filled
     * and empty cmdline */
    if (!read_all(s, &hdr, sizeof(hdr))) {
        PERROR("read daemon");
        return false;
    }
    assert(hdr.type == type);
    if (hdr.len != sizeof(params)) {
        LOG(ERROR, "Invalid response for 0x%x", type);
        return false;
    }
    if (!read_all(s, &params, sizeof(params))) {
        PERROR("read daemon");
        return false;
    }
    *data_port = params.connect_port;
    *data_domain = params.connect_domain;
    return true;
}

int handle_daemon_handshake(int fd)
{
    struct msg_header hdr;
    struct peer_info info;

    /* daemon send MSG_HELLO first */
    if (!read_all(fd, &hdr, sizeof(hdr))) {
        PERROR("daemon handshake");
        return -1;
    }
    if (hdr.type != MSG_HELLO || hdr.len != sizeof(info)) {
        LOG(ERROR, "Invalid daemon MSG_HELLO");
        return -1;
    }
    if (!read_all(fd, &info, sizeof(info))) {
        PERROR("daemon handshake");
        return -1;
    }

    if (info.version != QREXEC_PROTOCOL_VERSION) {
        LOG(ERROR, "Incompatible daemon protocol version "
            "(daemon %d, client %d)",
            info.version, QREXEC_PROTOCOL_VERSION);
        return -1;
    }

    hdr.type = MSG_HELLO;
    hdr.len = sizeof(info);
    info.version = QREXEC_PROTOCOL_VERSION;

    if (!write_all(fd, &hdr, sizeof(hdr))) {
        LOG(ERROR, "Failed to send MSG_HELLO hdr to daemon");
        return -1;
    }
    if (!write_all(fd, &info, sizeof(info))) {
        LOG(ERROR, "Failed to send MSG_HELLO to daemon");
        return -1;
    }
    return 0;
}

bool qrexec_execute_vm(const char *target, bool autostart, int remote_domain_id,
                       const char *cmd, size_t const service_length,
                       const char *request_id, bool just_exec,
                       bool wait_connection_end)
{
    if (service_length < 2 || (size_t)service_length > MAX_QREXEC_CMD_LEN) {
        /* This is arbitrary, but it helps reduce the risk of overflows in other code */
        LOG(ERROR, "Bad command: command line too long or empty: length %zu\n",
            service_length);
        return false;
    }
    bool rc = false;
    bool disposable = strncmp("@dispvm:", target, sizeof("@dispvm:") - 1) == 0;
    char *buf = NULL;
    size_t resp_len;
    if (disposable) {
        if (!autostart) {
            // Otherwise, we create a disposable VM, do not start it, and
            // time out connecting to it.
            LOG(ERROR, "Target %s with autostart=False makes no sense", target);
            return false;
        }
        if (just_exec) {
            // Otherwise, we kill the VM immediately after starting it.
            LOG(ERROR, "Target %s with MSG_JUST_EXEC makes no sense", target);
            return false;
        }
        // Otherwise, we kill the VM immediately after starting it.
        wait_connection_end = true;
        buf = qubesd_call(target + 8, "admin.vm.CreateDisposable", "", &resp_len);
        if (buf == NULL) // error already printed by qubesd_call
            return false;
        if (memcmp(buf, "0", 2) == 0) {
            /* we exit later so memory leaks do not matter */
            target = buf + 2;
        } else {
            if (memcmp(buf, "2", 2) == 0) {
                LOG(ERROR, "qubesd could not create disposable VM: %s", buf + 2);
            } else {
                LOG(ERROR, "invalid response to admin.vm.CreateDisposable");
            }
            free(buf);
            return false;
        }
    }
    if (autostart) {
        buf = qubesd_call(target, "admin.vm.Start", "", &resp_len);
        if (buf == NULL) // error already printed by qubesd_call
            return false;
        if (!((memcmp(buf, "0", 2) == 0) ||
                    (resp_len >= 24 && memcmp(buf, "2\0QubesVMNotHaltedError", 24) == 0))) {
            if (memcmp(buf, "2", 2) == 0) {
                LOG(ERROR, "qubesd could not start VM %s: %s", target, buf + 2);
            } else {
                LOG(ERROR, "invalid response to admin.vm.Start");
            }
            free(buf);
            return false;
        }
        free(buf);
    }
    int s = connect_unix_socket(target);
    if (s == -1)
        goto kill;
    int data_domain;
    int data_port;
    if (!negotiate_connection_params(s,
                remote_domain_id,
                just_exec ? MSG_JUST_EXEC : MSG_EXEC_CMDLINE,
                cmd,
                service_length,
                &data_domain,
                &data_port))
        goto kill;
    int wait_connection_fd = -1;
    if (wait_connection_end) {
        /* save socket fd, 's' will be reused for the other qrexec-daemon
         * connection */
        wait_connection_fd = s;
    } else {
        close(s);
    }

    s = connect_unix_socket_by_id((unsigned)remote_domain_id);
    rc = send_service_connect(s, request_id, data_domain, data_port);
    close(s);
    if (wait_connection_end) {
        /* wait for EOF */
        struct pollfd fds[1] = {
            { .fd = wait_connection_fd, .events = POLLIN | POLLHUP, .revents = 0 },
        };
        poll(fds, 1, -1);
        size_t l;
kill:
        if (disposable)
            qubesd_call(target, "admin.vm.Kill", "", &l);
    }
    return rc;
}

int connect_unix_socket_by_id(unsigned int domid)
{
    char id_str[11];
    int snprintf_res = snprintf(id_str, sizeof(id_str), "%u", domid);
    if (snprintf_res < 0 || snprintf_res >= (int)sizeof(id_str))
        abort();
    return connect_unix_socket(id_str);
}

int connect_unix_socket(const char *domname)
{
    int s, len, res;
    struct sockaddr_un remote;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOG(ERROR, "socket() failed: %m");
        return -1;
    }

    remote.sun_family = AF_UNIX;
    res = snprintf(remote.sun_path, sizeof remote.sun_path,
                   "%s/qrexec.%s", socket_dir, domname);
    if (res < 0)
        abort();
    if (res >= (int)sizeof(remote.sun_path)) {
        LOG(ERROR, "%s/qrexec.%s is too long for AF_UNIX socket path",
             socket_dir, domname);
        return -1;
    }
    len = (size_t)res + 1 + offsetof(struct sockaddr_un, sun_path);
    if (connect(s, (struct sockaddr *) &remote, len) == -1) {
        LOG(ERROR, "connect %s", remote.sun_path);
        return -1;
    }
    if (handle_daemon_handshake(s) < 0)
        return -1;
    return s;
}

bool send_service_connect(int s, const char *conn_ident,
        int connect_domain, int connect_port)
{
    struct msg_header hdr;
    struct exec_params exec_params;
    struct service_params srv_params;

    hdr.type = MSG_SERVICE_CONNECT;
    hdr.len = sizeof(exec_params) + sizeof(srv_params);

    exec_params.connect_domain = connect_domain;
    exec_params.connect_port = connect_port;
    strncpy(srv_params.ident, conn_ident, sizeof(srv_params.ident) - 1);
    srv_params.ident[sizeof(srv_params.ident) - 1] = '\0';

    if (!write_all(s, &hdr, sizeof(hdr))
            || !write_all(s, &exec_params, sizeof(exec_params))
            || !write_all(s, &srv_params, sizeof(srv_params))) {
        PERROR("write daemon");
        return false;
    }
    return true;
}

#define QREXEC_DATA_MIN_VERSION QREXEC_PROTOCOL_V2

static int local_stdin_fd = 1, local_stdout_fd = 0;
static pid_t local_pid = 0;

static volatile sig_atomic_t sigchld = 0;

static void set_remote_domain(const char *src_domain_name) {
    if (setenv("QREXEC_REMOTE_DOMAIN", src_domain_name, 1)) {
        LOG(ERROR, "Cannot set QREXEC_REMOTE_DOMAIN");
        abort();
    }
}

/* initialize data_protocol_version */
int handle_agent_handshake(libvchan_t *vchan, bool remote_send_first)
{
    struct msg_header hdr;
    struct peer_info info;
    int data_protocol_version = -1;
    int who = 0; // even - send to remote, odd - receive from remote

    while (who < 2) {
        if ((who+remote_send_first) & 1) {
            if (!read_vchan_all(vchan, &hdr, sizeof(hdr))) {
                PERROR("daemon handshake");
                return -1;
            }
            if (hdr.type != MSG_HELLO || hdr.len != sizeof(info)) {
                LOG(ERROR, "Invalid daemon MSG_HELLO");
                return -1;
            }
            if (!read_vchan_all(vchan, &info, sizeof(info))) {
                PERROR("daemon handshake");
                return -1;
            }

            data_protocol_version = info.version < QREXEC_PROTOCOL_VERSION ?
                                    info.version : QREXEC_PROTOCOL_VERSION;
            if (data_protocol_version < QREXEC_DATA_MIN_VERSION) {
                LOG(ERROR, "Incompatible daemon protocol version "
                        "(daemon %d, client %d)",
                        info.version, QREXEC_PROTOCOL_VERSION);
                return -1;
            }
        } else {
            hdr.type = MSG_HELLO;
            hdr.len = sizeof(info);
            info.version = QREXEC_PROTOCOL_VERSION;

            if (!write_vchan_all(vchan, &hdr, sizeof(hdr))) {
                LOG(ERROR, "Failed to send MSG_HELLO hdr to daemon");
                return -1;
            }
            if (!write_vchan_all(vchan, &info, sizeof(info))) {
                LOG(ERROR, "Failed to send MSG_HELLO to daemon");
                return -1;
            }
        }
        who++;
    }
    return data_protocol_version;
}

static void sigchld_handler(int x __attribute__((__unused__)))
{
    sigchld = 1;
}

/* See also qrexec-agent.c:wait_for_session_maybe() */
static bool wait_for_session_maybe(struct qrexec_parsed_command *cmd)
{
    pid_t pid;
    int status;

    if (cmd->nogui) {
        return true;
    }

    if (!cmd->service_descriptor) {
        return true;
    }

    if (load_service_config_v2(cmd) < 0) {
        return false;
    }

    if (!cmd->wait_for_session) {
        return true;
    }

    pid = fork();
    switch (pid) {
        case 0:
            close(0);
            exec_wait_for_session(cmd->source_domain);
            PERROR("exec");
            _exit(1);
        case -1:
            PERROR("fork");
            return false;
        default:
            break;
    }

    if (waitpid(local_pid, &status, 0) > 0) {
        if (status != 0)
            LOG(ERROR, "wait-for-session exited with status %d", status);
    } else
        PERROR("waitpid");

    return true;
}

int prepare_local_fds(struct qrexec_parsed_command *command, struct buffer *stdin_buffer)
{
    if (stdin_buffer == NULL)
        abort();
    struct sigaction action = {
        .sa_handler = sigchld_handler,
        .sa_flags = 0,
    };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL))
        return QREXEC_EXIT_PROBLEM;
    return execute_parsed_qubes_rpc_command(command, &local_pid, &local_stdin_fd, &local_stdout_fd,
            NULL, stdin_buffer);
}

// See also qrexec-agent/qrexec-agent-data.c
static void handle_failed_exec(libvchan_t *data_vchan, bool is_service, int exit_code)
{
    struct msg_header hdr = {
        .type = MSG_DATA_STDOUT,
        .len = 0,
    };

    LOG(ERROR, "failed to spawn process, exiting");
    /*
     * TODO: In case we fail to execute a *local* process (is_service false),
     * we should either
     *  - exit even before connecting to remote domain, or
     *  - send stdin EOF and keep waiting for remote exit code.
     *
     * That will require a slightly bigger refactoring. Right now it's not
     * important, because this function should handle QUBESRPC command failure
     * only (normal commands go through fork+exec), but it will be necessary
     * when we support sockets as a local process.
     */
    if (is_service) {
        libvchan_send(data_vchan, &hdr, sizeof(hdr));
        send_exit_code(data_vchan, exit_code);
    }
}

static int select_loop(struct handshake_params *params)
{
    struct process_io_request req = { 0 };
    int exit_code;

    req.vchan = params->data_vchan;
    req.stdin_buf = params->stdin_buffer;
    req.stdin_fd = local_stdin_fd;
    req.stdout_fd = local_stdout_fd;
    req.stderr_fd = -1;
    req.local_pid = local_pid;
    req.is_service = params->remote_send_first;
    req.replace_chars_stdout = params->replace_chars_stdout;
    req.replace_chars_stderr = params->replace_chars_stderr;
    req.data_protocol_version = params->data_protocol_version;
    req.sigchld = &sigchld;
    req.sigusr1 = NULL;
    req.prefix_data.data = NULL;
    req.prefix_data.len = 0;

    exit_code = process_io(&req);
    return (params->exit_with_code ? exit_code : 0);
}

int run_qrexec_to_dom0(const struct service_params *svc_params,
                        int src_domain_id,
                        const char *src_domain_name,
                        char *remote_cmdline,
                        int connection_timeout,
                        bool exit_with_code)
{
    int data_domain;
    int data_port;
    int s;
    int prepare_ret;
    libvchan_t *data_vchan = NULL;

    set_remote_domain(src_domain_name);
    s = connect_unix_socket_by_id(src_domain_id);
    if (s < 0)
        return QREXEC_EXIT_PROBLEM;
    if (!negotiate_connection_params(s,
            0, /* dom0 */
            MSG_SERVICE_CONNECT,
            svc_params,
            sizeof(*svc_params),
            &data_domain,
            &data_port))
        return QREXEC_EXIT_PROBLEM;

    struct buffer stdin_buffer;
    buffer_init(&stdin_buffer);
    struct qrexec_parsed_command *command =
        parse_qubes_rpc_command(remote_cmdline, false);
    if (command == NULL) {
        prepare_ret = -2;
    } else if (!wait_for_session_maybe(command)) {
        LOG(ERROR, "Cannot load service configuration, or forking process failed");
        prepare_ret = -2;
    } else {
        prepare_ret = prepare_local_fds(command, &stdin_buffer);
    }
    int wait_fd;
    data_vchan = libvchan_client_init_async(data_domain, data_port, &wait_fd);
    if (!data_vchan) {
        LOG(ERROR, "Cannot create data vchan connection");
        return QREXEC_EXIT_PROBLEM;
    }
    if (qubes_wait_for_vchan_connection_with_timeout(
                data_vchan, wait_fd, false, connection_timeout) < 0) {
        LOG(ERROR, "qrexec connection timeout");
        return QREXEC_EXIT_PROBLEM;
    }

    struct handshake_params params = {
        .data_vchan = data_vchan,
        .stdin_buffer = &stdin_buffer,
        .remote_send_first = true, // this is a service call _to_ dom0
        .prepare_ret = prepare_ret,
        .exit_with_code = exit_with_code,
        .replace_chars_stdout = false, // stdout is _from_ dom0
        .replace_chars_stderr = false, // stderr is _from_ dom0
    };
    return handshake_and_go(&params);
}

int handshake_and_go(struct handshake_params *params)
{
    if (params->data_vchan == NULL || !libvchan_is_open(params->data_vchan)) {
        LOG(ERROR, "Failed to open data vchan connection");
        return QREXEC_EXIT_PROBLEM;
    }
    int rc;
    int data_protocol_version = handle_agent_handshake(params->data_vchan,
                                                       params->remote_send_first);
    if (data_protocol_version < 0) {
        rc = QREXEC_EXIT_PROBLEM;
    } else if (params->prepare_ret != 0) {
        rc = params->prepare_ret == -1 ? QREXEC_EXIT_SERVICE_NOT_FOUND : QREXEC_EXIT_PROBLEM;
        handle_failed_exec(params->data_vchan, params->remote_send_first, rc);
    } else {
        params->data_protocol_version = data_protocol_version;
        rc = select_loop(params);
    }
    libvchan_close(params->data_vchan);
    params->data_vchan = NULL;
    return rc;
}
