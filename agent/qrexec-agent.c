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
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <err.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <assert.h>
#include <limits.h>
#ifdef HAVE_PAM
#include <security/pam_appl.h>
#endif
#include <qrexec.h>
#include <libvchan.h>
#include "libqrexec-utils.h"
#include "qrexec-agent.h"

struct connection_info {
    int pid; /* pid of child process handling the data */
    int fd;  /* socket to the process handling the data (wait for EOF here) */
    int connect_domain;
    int connect_port;
};

/* structure describing a single request waiting for qubes.WaitForSession to
 * finish */
struct waiting_request {
    int type;
    int padding;
    struct exec_params *params;
    struct qrexec_parsed_command *cmd;
};

/*  */
static struct connection_info connection_info[MAX_FDS];

static struct waiting_request requests_waiting_for_session[MAX_FDS];

static libvchan_t *ctrl_vchan;

static pid_t wait_for_session_pid = -1;

static int trigger_fd;

static int terminate_requested;

static int meminfo_write_started = 0;

static const char *agent_trigger_path = QREXEC_AGENT_TRIGGER_PATH;
static const char *fork_server_path = QREXEC_FORK_SERVER_SOCKET;

static void handle_server_exec_request_do(int type,
                                          struct qrexec_parsed_command *cmd,
                                          struct exec_params *params);
static void terminate_connection(uint32_t domain, uint32_t port);

const bool qrexec_is_fork_server = false;

#ifdef HAVE_PAM
static int pam_conv_callback(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr __attribute__((__unused__)))
{
#if INT_MAX > SIZE_MAX
    assert(num_msg <= (int)SIZE_MAX);
#endif
    assert(num_msg >= 0);
    int i;
    struct pam_response *resp_array =
        calloc((size_t)num_msg, sizeof(struct pam_response));

    if (resp_array == NULL)
        return PAM_BUF_ERR;

    for (i=0; i<num_msg; i++) {
        if (msg[i]->msg_style == PAM_ERROR_MSG)
            fprintf(stderr, "%s", msg[i]->msg);
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
                msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            resp_array[i].resp = strdup("");
            resp_array[i].resp_retcode = 0;
        }
    }
    *resp = resp_array;
    return PAM_SUCCESS;
}

static struct pam_conv conv = {
    pam_conv_callback,
    NULL
};
#endif
/* Start program requested by dom0 in already prepared process
 * (stdin/stdout/stderr already set, etc)
 * Called in two cases:
 *  MSG_JUST_EXEC - from qrexec-agent-data.c:handle_new_process_common->handle_just_exec
 *  MSG_EXEC_CMDLINE - from
 *  qrexec-agent-data.c:handle_new_process_common->do_fork_exec (callback
 *  registered with register_exec_func in init() here)
 *
 * cmd parameter came from dom0 (MSG_JUST_EXEC or MSG_EXEC_CMDLINE messages), so
 * is trusted. Even in VM-VM service request, the command here is controlled by
 * dom0 - it will be in form:
 * RPC_REQUEST_COMMAND " " service_name " " source_vm_name
 * where service_name is already validated against Qrexec RPC policy
 *
 * If dom0 sends overly long cmd, it will probably crash qrexec-agent (unless
 * process can allocate up to 4GB on both stack and heap), sorry.
 */
_Noreturn void do_exec(const char *prog, const char *cmd, const char *user)
{
#ifdef HAVE_PAM
    int retval, status;
    pam_handle_t *pamh=NULL;
    struct passwd *pw;
    struct passwd pw_copy;
    pid_t child, pid;
    char **env;
    char env_buf[64];
    char *arg0;
    char *shell_basename;
#endif
    sigset_t sigmask;

    sigemptyset(&sigmask);
    sigprocmask(SIG_SETMASK, &sigmask, NULL);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);

#ifdef HAVE_PAM
    if (geteuid() != 0) {
        /* We're not root, assume this is a testing environment. */

        pw = getpwuid(geteuid());
        if (!pw) {
            PERROR("getpwuid");
            exit(QREXEC_EXIT_PROBLEM);
        }
        if (strcmp(pw->pw_name, user)) {
            LOG(ERROR, "requested user %s, but qrexec-agent is running as user %s",
                user, pw->pw_name);
            exit(QREXEC_EXIT_PROBLEM);
        }
        /* call QUBESRPC if requested */
        if (prog) {
            /* no point in creating a login shell for test environments */
            exec_qubes_rpc2(prog, cmd, environ, false);
        }

        /* otherwise exec shell */
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        PERROR("execl");
        exit(QREXEC_EXIT_PROBLEM);
    }

    pw = getpwnam(user);
    if (! (pw && pw->pw_name && pw->pw_name[0] && pw->pw_dir && pw->pw_dir[0]
                && pw->pw_passwd)) {
        LOG(ERROR, "user %s does not exist", user);
        exit(QREXEC_EXIT_PROBLEM);
    }

    /* Make a copy of the password information and point pw at the local
     * copy instead.  Otherwise, some systems (e.g. Linux) would clobber
     * the static data through the getlogin call.
     */
    pw_copy = *pw;
    pw = &pw_copy;
    if (!((pw->pw_name = strdup(pw->pw_name)) &&
          (pw->pw_passwd = strdup(pw->pw_passwd)) &&
          (pw->pw_dir = strdup(pw->pw_dir)) &&
          (pw->pw_shell = strdup(pw->pw_shell)))) {
        PERROR("strdup");
        exit(QREXEC_EXIT_PROBLEM);
    }
    endpwent();

    shell_basename = basename (pw->pw_shell);
    /* this process is going to die shortly, so don't care about freeing */
    arg0 = malloc (strlen (shell_basename) + 2);
    if (!arg0) {
        PERROR("malloc");
        exit(QREXEC_EXIT_PROBLEM);
    }
    arg0[0] = '-';
    strcpy (arg0 + 1, shell_basename);

    retval = pam_start("qrexec", user, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        LOG(ERROR, "PAM handle could not be acquired");
        pamh = NULL;
        goto error;
    }

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS)
        goto error;

    retval = initgroups(pw->pw_name, pw->pw_gid);
    if (retval == -1) {
        PERROR("initgroups");
        goto error;
    }

    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS)
        goto error;

    retval = pam_open_session(pamh, 0);
    if (retval != PAM_SUCCESS)
        goto error;

    /* provide this variable to child process */
    if ((unsigned)snprintf(env_buf, sizeof(env_buf), "QREXEC_AGENT_PID=%d", getppid()) >= sizeof(env_buf))
        goto error;
    retval = pam_putenv(pamh, env_buf);
    if (retval != PAM_SUCCESS)
        goto error;
    if ((unsigned)snprintf(env_buf, sizeof(env_buf), "HOME=%s", pw->pw_dir) >= sizeof(env_buf))
        goto error;
    retval = pam_putenv(pamh, env_buf);
    if (retval != PAM_SUCCESS)
        goto error;
    if ((unsigned)snprintf(env_buf, sizeof(env_buf), "SHELL=%s", pw->pw_shell) >= sizeof(env_buf))
        goto error;
    retval = pam_putenv(pamh, env_buf);
    if (retval != PAM_SUCCESS)
        goto error;
    if ((unsigned)snprintf(env_buf, sizeof(env_buf), "USER=%s", pw->pw_name) >= sizeof(env_buf))
        goto error;
    retval = pam_putenv(pamh, env_buf);
    if (retval != PAM_SUCCESS)
        goto error;
    if ((unsigned)snprintf(env_buf, sizeof(env_buf), "LOGNAME=%s", pw->pw_name) >= sizeof(env_buf))
        goto error;
    retval = pam_putenv(pamh, env_buf);
    if (retval != PAM_SUCCESS)
        goto error;

    /* FORK HERE */
    child = fork();

    switch (child) {
        case -1:
            goto error;
        case 0:
            /* child */

            if (setgid (pw->pw_gid)) {
                PERROR("setgid");
                _exit(QREXEC_EXIT_PROBLEM);
            }
            if (setuid (pw->pw_uid)) {
                PERROR("setuid");
                _exit(QREXEC_EXIT_PROBLEM);
            }
            setsid();
            /* This is a copy but don't care to free as we exec later anyway.  */
            env = pam_getenvlist (pamh);

            /* try to enter home dir, but don't abort if it fails */
            retval = chdir(pw->pw_dir);
            if (retval == -1)
                warn("chdir(%s)", pw->pw_dir);

            /* call QUBESRPC if requested */
            if (prog) {
                /* Set up environment variables for a login shell. */
                exec_qubes_rpc2(prog, cmd, env, true);
            }
            /* otherwise exec shell */
            execle(pw->pw_shell, arg0, "-c", cmd, (char*)NULL, env);
            LOGE(ERROR, "exec shell");
            _exit(QREXEC_EXIT_PROBLEM);
        default:
            /* parent */
            /* close std*, so when child process closes them, qrexec-agent will receive EOF */
            /* this is the main purpose of this reimplementation of /bin/su... */
            close(0);
            close(1);
            close(2);
    }

    /* reachable only in parent */
    pid = waitpid (child, &status, 0);
    if (pid != (pid_t)-1) {
        if (WIFSIGNALED (status))
            status = WTERMSIG (status) + 128;
        else
            status = WEXITSTATUS (status);
    } else
        status = 1;

    retval = pam_close_session (pamh, 0);

    retval = pam_setcred (pamh, PAM_DELETE_CRED | PAM_SILENT);

    if (pam_end(pamh, retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        LOG(ERROR, "pam_end (retval %d)", retval);
        exit(QREXEC_EXIT_PROBLEM);
    }
    exit(status);
error:
    pam_end(pamh, PAM_ABORT);
    exit(QREXEC_EXIT_PROBLEM);
#else
    /* call QUBESRPC if requested */
    if (prog) {
        /* Set up environment variables for a login session. */
        exec_qubes_rpc2(prog, cmd, environ, true);
    }
    /* otherwise exec shell */
    execl("/bin/su", "su", "-", user, "-c", cmd, NULL);
    PERROR("execl");
    exit(QREXEC_EXIT_PROBLEM);
#endif

}

_Noreturn void handle_vchan_error(const char *op)
{
    LOG(ERROR, "Error while vchan %s, exiting", op);
    exit(1);
}

static int my_sd_notify(int unset_environment, const char *state) {
    struct sockaddr_un addr;
    int fd;
    int ret = -1;

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, getenv("NOTIFY_SOCKET"), sizeof(addr.sun_path)-1);
    addr.sun_path[sizeof(addr.sun_path)-1] = '\0';
    if (addr.sun_path[0] == '@')
        addr.sun_path[0] = '\0';

    if (unset_environment)
        unsetenv("NOTIFY_SOCKET");

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd == -1) {
        PERROR("sd_notify socket");
        return -1;
    }

    if (connect(fd, &addr, sizeof(addr)) == -1) {
        PERROR("sd_notify connect");
        goto out;
    }

    if (send(fd, state, strlen(state), 0) == -1) {
        PERROR("sd_notify send");
        goto out;
    }

    ret = 0;
out:
    close(fd);
    return ret;
}

static void init(void)
{
    mode_t old_umask;
    /* FIXME: This 0 is remote domain ID */
    ctrl_vchan = libvchan_server_init(0, VCHAN_BASE_PORT, 4096, 4096);
    if (!ctrl_vchan)
        handle_vchan_error("server_init");
    if (handle_handshake(ctrl_vchan) < 0)
        exit(1);
    old_umask = umask(0);
    trigger_fd = get_server_socket(agent_trigger_path);
    umask(old_umask);
    register_exec_func(do_exec);

    /* wait for qrexec daemon */
    while (!libvchan_is_open(ctrl_vchan))
        libvchan_wait(ctrl_vchan);

    if (getenv("NOTIFY_SOCKET")) {
        my_sd_notify(1, "READY=1");
    }
}

static void wake_meminfo_writer(void)
{
    FILE *f;
    int pid;

    if (meminfo_write_started)
        /* wake meminfo-writer only once */
        return;

    f = fopen(MEMINFO_WRITER_PIDFILE, "re");
    if (f == NULL) {
        /* no meminfo-writer found, ignoring */
        return;
    }
    if (fscanf(f, "%d", &pid) < 1) {
        fclose(f);
        /* no meminfo-writer found, ignoring */
        return;
    }

    fclose(f);
    if (pid <= 1 || pid > 0xffff) {
        /* check within acceptable range */
        return;
    }
    if (kill(pid, SIGUSR1) < 0) {
        /* Can't send signal */
        return;
    }
    meminfo_write_started = 1;
}

static int try_fork_server(int type, int connect_domain, int connect_port,
        const char *cmdline, size_t cmdline_len, const char *username) {
    char *colon;
    char *fork_server_socket_path;
    int s = -1;
    struct sockaddr_un remote;
    struct qrexec_cmd_info info;
    if (!fork_server_path)
        return -1;

    if (cmdline_len > MAX_QREXEC_CMD_LEN)
        return -1;
    colon = strchr(cmdline, ':');
    if (!colon)
        goto fail;

    if (asprintf(&fork_server_socket_path, fork_server_path, username) < 0) {
        LOG(ERROR, "Memory allocation failed");
        goto fail;
    }

    remote.sun_path[sizeof(remote.sun_path) - 1] = '\0';
    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, fork_server_socket_path,
            sizeof(remote.sun_path) - 1);
    free(fork_server_socket_path);

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        PERROR("socket");
        goto fail;
    }
    size_t len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *) &remote, (socklen_t)len) == -1) {
        if (errno != ECONNREFUSED && errno != ENOENT)
            PERROR("connect");
        goto fail;
    }

    memset(&info, 0, sizeof info);
    info.type = type;
    info.connect_domain = connect_domain;
    info.connect_port = connect_port;
    size_t username_len = (size_t)(colon - cmdline);
    assert(cmdline_len <= INT_MAX);
    assert(cmdline_len > username_len);
    info.cmdline_len = (int)(cmdline_len - (username_len + 1));
    if (!write_all(s, &info, sizeof(info))) {
        PERROR("write");
        goto fail;
    }
    if (!write_all(s, colon+1, info.cmdline_len)) {
        PERROR("write");
        goto fail;
    }

    return s;
fail:
    if (s >= 0)
        close(s);
    return -1;
}


static void register_vchan_connection(pid_t pid, int fd, int domain, int port)
{
    int i;

    for (i = 0; i < MAX_FDS; i++) {
        if (connection_info[i].pid == 0) {
            connection_info[i].pid = pid;
            connection_info[i].fd = fd;
            connection_info[i].connect_domain = domain;
            connection_info[i].connect_port = port;
            return;
        }
    }

    LOG(ERROR, "No free slot for child %d (connection to %d:%d)", pid, domain, port);
}

/* Check if requested command/service require GUI session and if so, initiate
 * waiting process.
 *
 * Return:
 *  - 1 - waiting is needed, caller should register request to be proceeded
 *  only after session is started)
 *  - 0 - waiting is not needed, caller may proceed with request immediately
 */
static bool wait_for_session_maybe(struct qrexec_parsed_command *cmd) {
    int stdin_pipe[2];
    sigset_t sigmask;

    /* ok, now we know that service is configured to wait for session */
    if (wait_for_session_pid != -1) {
        /* we're already waiting */
        return true;
    }

    if (pipe(stdin_pipe) == -1) {
        PERROR("pipe for wait-for-session");
        return false;
    }
    /* start waiting process */
    wait_for_session_pid = fork();
    switch (wait_for_session_pid) {
        case 0:
            sigemptyset(&sigmask);
            sigprocmask(SIG_SETMASK, &sigmask, NULL);

            close(stdin_pipe[1]);
            dup2(stdin_pipe[0], 0);
            exec_wait_for_session(cmd->source_domain);
            PERROR("exec");
            _exit(1);
        case -1:
            PERROR("fork");
            return false;
        default:
            close(stdin_pipe[0]);
            if (write(stdin_pipe[1], cmd->username, strlen(cmd->username)) == -1)
                PERROR("write error");
            if (write(stdin_pipe[1], "\n", 1) == -1)
                PERROR("write error");
            close(stdin_pipe[1]);
    }

    /* qubes.WaitForSession started, postpone request until it report back */
    return true;
}


/* hdr parameter is received from dom0, so it is trusted */
static void handle_server_exec_request_init(struct msg_header *hdr)
{
    struct qrexec_parsed_command *cmd;
    struct exec_params *params;
    if (hdr->len <= sizeof(*params) || hdr->len > (uint32_t)INT_MAX)
        handle_vchan_error("buffer size validation");
    size_t buf_len = hdr->len - sizeof(*params);
    params = malloc(hdr->len);
    if (params == NULL)
        handle_vchan_error("buffer alloc");
    if (libvchan_recv(ctrl_vchan, params, hdr->len) != (int)hdr->len)
        handle_vchan_error("read exec params");
    params->cmdline[buf_len - 1] = 0;

    if (hdr->type == MSG_SERVICE_CONNECT) {
        cmd = NULL;
    } else {
        cmd = parse_qubes_rpc_command(params->cmdline, true);
        if (cmd == NULL) {
            LOG(ERROR, "Could not parse command line: %s", params->cmdline);
            goto doit;
        }

        /* load service config only for service requests */
        if (cmd->service_descriptor) {
            if (load_service_config_v2(cmd) < 0) {
                LOG(ERROR, "Could not load config for command %s", params->cmdline);
                destroy_qrexec_parsed_command(cmd);
                cmd = NULL;
                goto doit;
            }

            /* "nogui:" prefix has priority */
            if (!cmd->nogui && cmd->wait_for_session && wait_for_session_maybe(cmd)) {
                /* waiting for session, postpone actual call */
                int slot_index;
                for (slot_index = 0; slot_index < MAX_FDS; slot_index++)
                    if (!requests_waiting_for_session[slot_index].params)
                        break;
                if (slot_index == MAX_FDS) {
                    /* no free slots */
                    LOG(WARNING, "No free slots for waiting for GUI session, continuing!");
                } else {
                    requests_waiting_for_session[slot_index].type = hdr->type;
                    requests_waiting_for_session[slot_index].params = params;
                    requests_waiting_for_session[slot_index].cmd = cmd;
                    /* nothing to do now, when we get GUI session, we'll continue */
                    return;
                }
            }
        }
    }

doit:
    handle_server_exec_request_do(hdr->type, cmd, params);
    destroy_qrexec_parsed_command(cmd);
    free(params);
}

static void handle_server_exec_request_do(int type,
                                          struct qrexec_parsed_command *cmd,
                                          struct exec_params *params) {
    int client_fd;
    pid_t child_agent;
    const char *cmdline = params->cmdline;
    size_t cmdline_len = strlen(cmdline) + 1; // size of cmdline, including \0 at the end

    if (type == MSG_SERVICE_CONNECT) {
        if (sscanf(cmdline, "SOCKET%d", &client_fd) != 1)
            goto bad_ident;

        /* FIXME: Maybe add some check if client_fd is really FD to some
         * qrexec-client-vm process; but this data comes from qrexec-daemon
         * (which sends back what it got from us earlier), so it isn't critical.
         */
        if (write(client_fd, params, sizeof(*params)) < 0) {
            /* Do not start polling invalid FD */
            if (errno == EBADF)
                goto bad_ident;
            /* ignore other errors */
        }
        /* No need to send request_id (buf) - the client don't need it, there
         * is only meaningless (for the client) socket FD */
        /* Register connection even if there was an error sending params to
         * qrexec-client-vm. This way the mainloop will clean the things up
         * (close socket, send MSG_CONNECTION_TERMINATED) when qrexec-client-vm
         * will close the socket (terminate itself). */
        register_vchan_connection(-1, client_fd,
                params->connect_domain, params->connect_port);
        return;
    }

    /* Ask libqrexec-utils if the fork server is safe to use */
    if (qrexec_cmd_use_fork_server(cmd)) {
        /* try fork server */
        int child_socket = try_fork_server(type,
                params->connect_domain, params->connect_port,
                cmdline, cmdline_len, cmd->username);
        if (child_socket >= 0) {
            register_vchan_connection(-1, child_socket,
                    params->connect_domain, params->connect_port);
            return;
        }
    }

    /* No fork server case */
    child_agent = handle_new_process(type,
            params->connect_domain, params->connect_port,
            cmd);

    register_vchan_connection(child_agent, -1,
            params->connect_domain, params->connect_port);
    return;
bad_ident:
    LOG(ERROR, "Got MSG_SERVICE_CONNECT from qrexec-daemon with invalid ident (%s), ignoring",
            cmdline);
}

static void handle_service_refused(struct msg_header *hdr)
{
    struct service_params params;
    int socket_fd;

    if (hdr->len != sizeof(params)) {
        LOG(ERROR, "Invalid msg 0x%x length (%d)", MSG_SERVICE_REFUSED, hdr->len);
        exit(1);
    }

    if (libvchan_recv(ctrl_vchan, &params, sizeof(params)) != sizeof(params))
        handle_vchan_error("read exec params");

    if (sscanf(params.ident, "SOCKET%d", &socket_fd))
        close(socket_fd);
    else
        LOG(WARNING, "Received REFUSED for unknown service request '%s'", params.ident);
}

static void handle_server_cmd(void)
{
    struct msg_header s_hdr;

    if (libvchan_recv(ctrl_vchan, &s_hdr, sizeof(s_hdr)) != sizeof(s_hdr))
        handle_vchan_error("read s_hdr");

    //      fprintf(stderr, "got %x %x %x\n", s_hdr.type, s_hdr.client_id,
    //              s_hdr.len);

    switch (s_hdr.type) {
        case MSG_EXEC_CMDLINE:
        case MSG_JUST_EXEC:
        case MSG_SERVICE_CONNECT:
            wake_meminfo_writer();
            handle_server_exec_request_init(&s_hdr);
            break;
        case MSG_SERVICE_REFUSED:
            handle_service_refused(&s_hdr);
            break;
        default:
            LOG(ERROR, "msg type from daemon is %d ?",
                s_hdr.type);
            exit(1);
    }
}

static volatile sig_atomic_t child_exited;

static void sigchld_handler(int x __attribute__((__unused__)))
{
    child_exited = 1;
    signal(SIGCHLD, sigchld_handler);
}

static void sigterm_handler(int x __attribute__((__unused__)))
{
    terminate_requested = 1;
}

static int find_connection(int pid)
{
    int i;
    for (i = 0; i < MAX_FDS; i++)
        if (connection_info[i].pid == pid)
            return i;
    return -1;
}

static void release_connection(int id) {
    terminate_connection(connection_info[id].connect_domain,
                         connection_info[id].connect_port);
    connection_info[id].pid = 0;
}

static void terminate_connection(uint32_t domain, uint32_t port) {
    struct {
        struct msg_header hdr;
        struct exec_params params;
    } data = {
        .hdr = {
            .type = MSG_CONNECTION_TERMINATED,
            .len = sizeof(struct exec_params),
        },
        .params = {
            .connect_domain = domain,
            .connect_port = port,
        },
    };
    if (libvchan_send(ctrl_vchan, &data, sizeof(data)) != sizeof(data))
        handle_vchan_error("send (MSG_CONNECTION_TERMINATED)");
}

static void reap_children(void)
{
    int status;
    int pid;
    int id;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == wait_for_session_pid) {
            for (id = 0; id < MAX_FDS; id++) {
                if (!requests_waiting_for_session[id].params)
                    continue;
                handle_server_exec_request_do(
                        requests_waiting_for_session[id].type,
                        requests_waiting_for_session[id].cmd,
                        requests_waiting_for_session[id].params);
                destroy_qrexec_parsed_command(requests_waiting_for_session[id].cmd);
                requests_waiting_for_session[id].cmd = NULL;
                free(requests_waiting_for_session[id].params);
                requests_waiting_for_session[id].params = NULL;
            }
            wait_for_session_pid = -1;
            continue;
        }
        id = find_connection(pid);
        if (id < 0)
            continue;
        release_connection(id);
    }
    child_exited = 0;
}

static void handle_trigger_io(void)
{
    struct msg_header hdr;
    struct trigger_service_params3 *params = NULL;
    int client_fd;

    client_fd = do_accept(trigger_fd);
    if (client_fd < 0)
        return;
    if (!read_all(client_fd, &hdr, sizeof(hdr)))
        goto error;
    if (hdr.type != MSG_TRIGGER_SERVICE3 ||
            hdr.len <= sizeof(*params) ||
            hdr.len > sizeof(*params) + MAX_SERVICE_NAME_LEN) {
        LOG(ERROR, "Invalid request received from qrexec-client-vm, is it outdated?");
        goto error;
    }
    params = malloc(hdr.len);
    if (!params)
        goto error;
    if (!read_all(client_fd, params, hdr.len))
        goto error;

    int res = snprintf(params->request_id.ident, sizeof(params->request_id), "SOCKET%d", client_fd);
    if (res < 0 || res >= (int)sizeof(params->request_id))
        abort();
    if (libvchan_send(ctrl_vchan, &hdr, sizeof(hdr)) != sizeof(hdr))
        handle_vchan_error("write hdr");
    if (libvchan_send(ctrl_vchan, params, hdr.len) != (int)hdr.len)
        handle_vchan_error("write params");

    free(params);
    /* do not close client_fd - we'll need it to send the connection details
     * later (when dom0 accepts the request) */
    return;
error:
    LOG(ERROR, "Failed to retrieve/execute request from qrexec-client-vm");
    free(params);
    close(client_fd);
}

static void handle_terminated_fork_client(int id) {
    ssize_t ret;
    char buf[2];

    ret = read(connection_info[id].fd, buf, sizeof(buf));
    if (!(ret == 0 || (ret == -1 && errno == ECONNRESET)))
        PERROR("Unexpected read on fork-server connection: %zd", ret);
    close(connection_info[id].fd);
    release_connection(id);
}

static struct option longopts[] = {
    { "help", no_argument, 0, 'h' },
    { "agent-socket", required_argument, 0, 'a' },
    { "fork-server-socket", required_argument, 0, 's' },
    { "no-fork-server", no_argument, 0, 'S' },
    { NULL, 0, 0, 0 },
};

static _Noreturn void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help - display usage\n");
    fprintf(stderr, "  --agent-socket=PATH - path to listen at, default: %s\n",
            QREXEC_AGENT_TRIGGER_PATH);
    fprintf(stderr, "  --fork-server-socket=PATH - where to find the fork server, default: %s\n",
            QREXEC_FORK_SERVER_SOCKET);
    fprintf(stderr, "    (set empty to disable, use %%s as username)\n");
    fprintf(stderr, "  --no-fork-server - don't try to connect to fork server\n");
    exit(2);
}

int main(int argc, char **argv)
{
    sigset_t selectmask;

    setup_logging("qrexec-agent");

    int opt;
    while (1) {
        opt = getopt_long(argc, argv, "ha:s:S", longopts, NULL);
        if (opt == -1)
            break;
        switch (opt) {
            case 'a':
                agent_trigger_path = strdup(optarg);
                break;
            case 's':
                fork_server_path = strdup(optarg);
                break;
            case 'S':
                fork_server_path = NULL;
                break;
            case 'h':
            case '?':
                usage(argv[0]);
        }
    }

    init();
    struct sigaction action = {
        .sa_handler = sigchld_handler,
        .sa_flags = SA_RESTART,
    };
    sigemptyset(&action.sa_mask);
    sigaction(SIGCHLD, &action, NULL);
    action.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    sigemptyset(&selectmask);
    sigaddset(&selectmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &selectmask, NULL);
    sigemptyset(&selectmask);

    struct pollfd fds[MAX_FDS + 2];
    fds[0] = (struct pollfd) { libvchan_fd_for_select(ctrl_vchan), POLLIN | POLLHUP, 0 };
    fds[1] = (struct pollfd) { trigger_fd, POLLIN | POLLHUP, 0 };

    while (!terminate_requested) {
        struct timespec timeout = { 1, 0 };
        size_t nfds = 1;
        int ret;

        if (child_exited)
            reap_children();

        if (libvchan_buffer_space(ctrl_vchan) > (int)sizeof(struct msg_header)) {
            /* vchan has space, so poll for clients */

            nfds++; /* for trigger_fd */
            for (size_t i = 0; i < MAX_FDS; i++) {
                if (connection_info[i].pid != 0 && connection_info[i].fd != -1)
                    fds[nfds++] = (struct pollfd) { connection_info[i].fd, POLLIN | POLLHUP, 0 };
            }
        }

        ret = ppoll_vchan(ctrl_vchan, fds, nfds, &timeout, &selectmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            PERROR("ppoll");
            return 1;
        }

        if (nfds > 2) {
            size_t fds_checked = 2;

            /*
             * Iterate over the connection_info entries again.  For each entry
             * that is valid (pid nonzero and FD not equal to -1), retrieve the
             * polling result from fds[fds_checked] and increment fds_checked to
             * point to the next polled file descriptor, if any.  This relies on
             * connection_info not having changed since fds[] was populated above,
             * which ensures that the retrieved `struct pollfd` will be the one
             * for the correct `struct _connection_info`.  Therefore, this loop
             * must come immediately after the call to `ppoll_vchan`.
             */
            for (size_t i = 0; i < MAX_FDS; i++) {
                if (connection_info[i].pid != 0 && connection_info[i].fd != -1) {
                    if (nfds <= fds_checked) {
                        fprintf(stderr, "BAD: nfds (%zu) <= fds_checked (%zu), aborting!\n", nfds, fds_checked);
                        assert(nfds > fds_checked);
                        abort();
                    }
                    struct pollfd fd_info = fds[fds_checked++];
                    assert(fd_info.fd == connection_info[i].fd);
                    if (fd_info.revents)
                        handle_terminated_fork_client(i);
                }
            }

            assert(fds_checked == nfds);
        }

        while (libvchan_data_ready(ctrl_vchan))
            handle_server_cmd();

        if (nfds > 1 && fds[1].revents)
            handle_trigger_io();
    }

    libvchan_close(ctrl_vchan);
}
