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

#include <sys/select.h>
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

struct _connection_info {
    int pid; /* pid of child process handling the data */
    int fd;  /* socket to the process handling the data (wait for EOF here) */
    int connect_domain;
    int connect_port;
};

/* structure describing a single request waiting for qubes.WaitForSession to
 * finish */
struct _waiting_request {
    int type;
    int connect_domain;
    int connect_port;
    int padding;
    char *cmdline;
};

/*  */
static struct _connection_info connection_info[MAX_FDS];

static struct _waiting_request requests_waiting_for_session[MAX_FDS];

static libvchan_t *ctrl_vchan;

static pid_t wait_for_session_pid = -1;

static int trigger_fd;

static int terminate_requested;

static int meminfo_write_started = 0;

static const char *agent_trigger_path = QREXEC_AGENT_TRIGGER_PATH;
static const char *fork_server_path = QREXEC_FORK_SERVER_SOCKET;

static void handle_server_exec_request_do(int type, int connect_domain, int connect_port, char *cmdline);

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
        calloc(sizeof(struct pam_response), (size_t)num_msg);

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
_Noreturn void do_exec(const char *cmd, const char *user)
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

    /* ignore "nogui:" prefix in linux agent */
    if (strncmp(cmd, NOGUI_CMD_PREFIX, NOGUI_CMD_PREFIX_LEN) == 0)
        cmd += NOGUI_CMD_PREFIX_LEN;

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
            exit(1);
        }
        if (strcmp(pw->pw_name, user)) {
            LOG(ERROR, "requested user %s, but qrexec-agent is running as user %s",
                user, pw->pw_name);
            exit(1);
        }
        /* call QUBESRPC if requested */
        exec_qubes_rpc_if_requested(cmd, environ);

        /* otherwise exec shell */
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        PERROR("execl");
        exit(1);
    }

    pw = getpwnam(user);
    if (! (pw && pw->pw_name && pw->pw_name[0] && pw->pw_dir && pw->pw_dir[0]
                && pw->pw_passwd)) {
        LOG(ERROR, "user %s does not exist", user);
        exit(1);
    }

    /* Make a copy of the password information and point pw at the local
     * copy instead.  Otherwise, some systems (e.g. Linux) would clobber
     * the static data through the getlogin call.
     */
    pw_copy = *pw;
    pw = &pw_copy;
    pw->pw_name = strdup(pw->pw_name);
    pw->pw_passwd = strdup(pw->pw_passwd);
    pw->pw_dir = strdup(pw->pw_dir);
    pw->pw_shell = strdup(pw->pw_shell);
    endpwent();

    shell_basename = basename (pw->pw_shell);
    /* this process is going to die shortly, so don't care about freeing */
    arg0 = malloc (strlen (shell_basename) + 2);
    if (!arg0)
        goto error;
    arg0[0] = '-';
    strcpy (arg0 + 1, shell_basename);

    retval = pam_start("qrexec", user, &conv, &pamh);
    if (retval != PAM_SUCCESS)
        goto error;

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

            if (setgid (pw->pw_gid))
                exit(126);
            if (setuid (pw->pw_uid))
                exit(126);
            setsid();
            /* This is a copy but don't care to free as we exec later anyway.  */
            env = pam_getenvlist (pamh);

            /* try to enter home dir, but don't abort if it fails */
            retval = chdir(pw->pw_dir);
            if (retval == -1)
                warn("chdir(%s)", pw->pw_dir);

            /* call QUBESRPC if requested */
            exec_qubes_rpc_if_requested(cmd, env);

            /* otherwise exec shell */
            execle(pw->pw_shell, arg0, "-c", cmd, (char*)NULL, env);
            exit(127);
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
        exit(1);
    }
    exit(status);
error:
    pam_end(pamh, PAM_ABORT);
    exit(1);
#else
    /* call QUBESRPC if requested */
    exec_qubes_rpc_if_requested(cmd, environ);

    /* otherwise exec shell */
    execl("/bin/su", "su", "-", user, "-c", cmd, NULL);
    PERROR("execl");
    exit(1);
#endif

}

_Noreturn void handle_vchan_error(const char *op)
{
    LOG(ERROR, "Error while vchan %s, exiting", op);
    exit(1);
}

int my_sd_notify(int unset_environment, const char *state) {
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
    if ((trigger_fd = get_server_socket(agent_trigger_path)) >= FD_SETSIZE) {
        fprintf(stderr, "TRIGGER_FD too large (got %d, FD_SETSIZE is %d)\n",
                trigger_fd, FD_SETSIZE);
        exit(1);
    }
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
        char *cmdline, size_t cmdline_len) {
    char *colon;
    char *fork_server_socket_path;
    int s = -1;
    struct sockaddr_un remote;
    struct qrexec_cmd_info info;
    if (!fork_server_path)
        return -1;

    if (cmdline_len > MAX_QREXEC_CMD_LEN)
        return -1;
    char *username = malloc(cmdline_len);
    if (!username) {
        PERROR("Memory allocation failed");
        return -1;
    }
    memcpy(username, cmdline, cmdline_len);
    colon = strchr(username, ':');
    if (!colon)
        goto fail;
    *colon = '\0';

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
    size_t username_len = strlen(username);
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

    free(username);
    return s;
fail:
    if (s >= 0)
        close(s);
    free(username);
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
static int wait_for_session_maybe(char *cmdline) {
    struct qrexec_parsed_command *cmd;
    int stdin_pipe[2];
    int wait_for_session = 0;
    int ret = 0;
    sigset_t sigmask;

    cmd = parse_qubes_rpc_command(cmdline, true);
    if (!cmd)
        /* error parsing the command, this will be properly reported later */
        return 0;

    /* "nogui:" prefix has priority - do not wait for session */
    if (cmd->nogui)
        goto out;

    /* wait for session only for service requests */
    if (!cmd->service_descriptor)
        goto out;

    /* load service config - if it fails, use initial value */
    load_service_config(cmd, &wait_for_session);

    if (!wait_for_session)
        /* setting not set, or set to 0 */
        goto out;

    /* ok, now we know that service is configured to wait for session */
    if (wait_for_session_pid != -1) {
        /* we're already waiting */
        ret = 1;
        goto out;
    }

    if (pipe(stdin_pipe) == -1) {
        PERROR("pipe for wait-for-session");
        goto out;
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
            exit(1);
        case -1:
            PERROR("fork");
            goto out;
        default:
            close(stdin_pipe[0]);
            if (write(stdin_pipe[1], cmd->username, strlen(cmd->username)) == -1)
                PERROR("write error");
            if (write(stdin_pipe[1], "\n", 1) == -1)
                PERROR("write error");
            close(stdin_pipe[1]);
    }

    /* qubes.WaitForSession started, postpone request until it report back */
    ret = 1;

out:
    destroy_qrexec_parsed_command(cmd);
    return ret;
}


/* hdr parameter is received from dom0, so it is trusted */
static void handle_server_exec_request_init(struct msg_header *hdr)
{
    struct exec_params params;
    int buf_len = hdr->len-sizeof(params);
    char *buf = malloc(buf_len);
    if (!buf) abort();

    assert((hdr->len >= sizeof params));

    if (libvchan_recv(ctrl_vchan, &params, sizeof(params)) != sizeof(params))
        handle_vchan_error("read exec params");
    if (libvchan_recv(ctrl_vchan, buf, buf_len) != buf_len)
        handle_vchan_error("read exec cmd");

    buf[buf_len-1] = 0;

    if (hdr->type != MSG_SERVICE_CONNECT && wait_for_session_maybe(buf)) {
        /* waiting for session, postpone actual call */
        int slot_index;
        for (slot_index = 0; slot_index < MAX_FDS; slot_index++)
            if (!requests_waiting_for_session[slot_index].cmdline)
                break;
        if (slot_index == MAX_FDS) {
            /* no free slots */
            LOG(WARNING, "No free slots for waiting for GUI session, continuing!");
        } else {
            requests_waiting_for_session[slot_index].type = hdr->type;
            requests_waiting_for_session[slot_index].connect_domain = params.connect_domain;
            requests_waiting_for_session[slot_index].connect_port = params.connect_port;
            requests_waiting_for_session[slot_index].cmdline = strdup(buf);
            /* nothing to do now, when we get GUI session, we'll continue */
            return;
        }
    }

    handle_server_exec_request_do(hdr->type, params.connect_domain, params.connect_port, buf);
}

static void handle_server_exec_request_do(int type, int connect_domain, int connect_port, char *cmdline) {
    int client_fd;
    pid_t child_agent;
    size_t cmdline_len = strlen(cmdline) + 1; // size of cmdline, including \0 at the end
    struct exec_params params = {
        .connect_domain = connect_domain,
        .connect_port = connect_port,
    };

    if ((type == MSG_EXEC_CMDLINE || type == MSG_JUST_EXEC) &&
            !strstr(cmdline, ":nogui:")) {
        int child_socket;

        child_socket = try_fork_server(type,
                params.connect_domain, params.connect_port,
                cmdline, cmdline_len);
        if (child_socket >= 0) {
            register_vchan_connection(-1, child_socket,
                    params.connect_domain, params.connect_port);
            return;
        }
    }

    if (type == MSG_SERVICE_CONNECT && sscanf(cmdline, "SOCKET%d", &client_fd)) {
        /* FIXME: Maybe add some check if client_fd is really FD to some
         * qrexec-client-vm process; but this data comes from qrexec-daemon
         * (which sends back what it got from us earlier), so it isn't critical.
         */
        if (write(client_fd, &params, sizeof(params)) < 0) {
            /* Do not start pooling invalid FD - it will crash the qrexec-agent with
             * "pselect: Bad file descriptor"
             */
            if (errno == EBADF) {
                LOG(ERROR, "Got MSG_SERVICE_CONNECT from qrexec-daemon with invalid ident (%s), ignoring",
                        cmdline);
                return;
            }
            /* ignore other errors */
        }
        /* No need to send request_id (buf) - the client don't need it, there
         * is only meaningless (for the client) socket FD */
        /* Register connection even if there was an error sending params to
         * qrexec-client-vm. This way the mainloop will clean the things up
         * (close socket, send MSG_CONNECTION_TERMINATED) when qrexec-client-vm
         * will close the socket (terminate itself). */
        register_vchan_connection(-1, client_fd,
                params.connect_domain, params.connect_port);
        return;
    }

    /* No fork server case */
    child_agent = handle_new_process(type,
            params.connect_domain, params.connect_port,
            cmdline, cmdline_len);

    register_vchan_connection(child_agent, -1,
            params.connect_domain, params.connect_port);
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
    struct msg_header hdr;
    struct exec_params params;

    hdr.type = MSG_CONNECTION_TERMINATED;
    hdr.len = sizeof(struct exec_params);
    params.connect_domain = connection_info[id].connect_domain;
    params.connect_port = connection_info[id].connect_port;
    if (libvchan_send(ctrl_vchan, &hdr, sizeof(hdr)) != sizeof(hdr))
        handle_vchan_error("send (MSG_CONNECTION_TERMINATED hdr)");
    if (libvchan_send(ctrl_vchan, &params, sizeof(params)) != sizeof(params))
        handle_vchan_error("send (MSG_CONNECTION_TERMINATED data)");
    connection_info[id].pid = 0;
}

static void reap_children(void)
{
    int status;
    int pid;
    int id;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == wait_for_session_pid) {
            for (id = 0; id < MAX_FDS; id++) {
                if (!requests_waiting_for_session[id].cmdline)
                    continue;
                handle_server_exec_request_do(
                        requests_waiting_for_session[id].type,
                        requests_waiting_for_session[id].connect_domain,
                        requests_waiting_for_session[id].connect_port,
                        requests_waiting_for_session[id].cmdline);
                free(requests_waiting_for_session[id].cmdline);
                requests_waiting_for_session[id].cmdline = NULL;
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

static int fill_fds_for_select(fd_set * rdset, fd_set * wrset)
{
    int max = -1;
    int i;
    FD_ZERO(rdset);
    FD_ZERO(wrset);

    FD_SET(trigger_fd, rdset);
    if (trigger_fd > max)
        max = trigger_fd;

    for (i = 0; i < MAX_FDS; i++) {
        if (connection_info[i].pid != 0 && connection_info[i].fd != -1) {
            if (connection_info[i].fd >= FD_SETSIZE) {
                fprintf(stderr,
                        "connection_info[%d].fd (%d) not less than FD_SETSIZE (%d)\n",
                        i, connection_info[i].fd, FD_SETSIZE);
                abort();
            }
            FD_SET(connection_info[i].fd, rdset);
            if (connection_info[i].fd > max)
                max = connection_info[i].fd;
        }
    }
    return max;
}

static void handle_trigger_io(void)
{
    struct msg_header hdr;
    struct trigger_service_params3 params;
    char *command = NULL;
    size_t command_len;
    int client_fd;

    client_fd = do_accept(trigger_fd);
    if (client_fd < 0)
        return;
    if (!read_all(client_fd, &hdr, sizeof(hdr)))
        goto error;
    if (hdr.type != MSG_TRIGGER_SERVICE3 ||
            hdr.len < sizeof(params) ||
            hdr.len > sizeof(params) + MAX_SERVICE_NAME_LEN) {
        LOG(ERROR, "Invalid request received from qrexec-client-vm, is it outdated?");
        goto error;
    }
    if (!read_all(client_fd, &params, sizeof(params)))
        goto error;
    command_len = hdr.len - sizeof(params);
    command = malloc(command_len);
    if (!command)
        goto error;
    if (!read_all(client_fd, command, command_len))
        goto error;
    if (command[command_len-1] != '\0')
        goto error;

    snprintf(params.request_id.ident, sizeof(params.request_id), "SOCKET%d", client_fd);
    if (libvchan_send(ctrl_vchan, &hdr, sizeof(hdr)) != sizeof(hdr))
        handle_vchan_error("write hdr");
    if (libvchan_send(ctrl_vchan, &params, sizeof(params)) != sizeof(params))
        handle_vchan_error("write params");
    if (libvchan_send(ctrl_vchan, command, command_len) != (int)command_len)
        handle_vchan_error("write command");

    free(command);
    /* do not close client_fd - we'll need it to send the connection details
     * later (when dom0 accepts the request) */
    return;
error:
    LOG(ERROR, "Failed to retrieve/execute request from qrexec-client-vm");
    if (command)
        free(command);
    close(client_fd);
}

static void handle_terminated_fork_client(fd_set *rdset) {
    int i;
    ssize_t ret;
    char buf[2];

    for (i = 0; i < MAX_FDS; i++) {
        if (connection_info[i].pid && connection_info[i].fd >= 0 &&
                FD_ISSET(connection_info[i].fd, rdset)) {
            ret = read(connection_info[i].fd, buf, sizeof(buf));
            if (ret == 0 || (ret == -1 && errno == ECONNRESET)) {
                close(connection_info[i].fd);
                release_connection(i);
            } else {
                PERROR("Unexpected read on fork-server connection: %zd", ret);
                close(connection_info[i].fd);
                release_connection(i);
            }
        }
    }
}

struct option longopts[] = {
    { "help", no_argument, 0, 'h' },
    { "agent-socket", required_argument, 0, 'a' },
    { "fork-server-socket", optional_argument, 0, 's' },
    { "no-fork-server", no_argument, 0, 'S' },
    { NULL, 0, 0, 0 },
};

_Noreturn void usage(const char *argv0)
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
    signal(SIGCHLD, sigchld_handler);
    signal(SIGTERM, sigterm_handler);
    signal(SIGPIPE, SIG_IGN);

    sigemptyset(&selectmask);
    sigaddset(&selectmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &selectmask, NULL);
    sigemptyset(&selectmask);

    while (!terminate_requested) {
        struct timespec timeout = { 1, 0 };
        fd_set rdset, wrset;
        int ret, max;

        if (child_exited)
            reap_children();

        max = fill_fds_for_select(&rdset, &wrset);
        if (libvchan_buffer_space(ctrl_vchan) <= (int)sizeof(struct msg_header))
            FD_ZERO(&rdset);

        ret = pselect_vchan(ctrl_vchan, max+1, &rdset, &wrset, &timeout, &selectmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            PERROR("pselect");
            return 1;
        }

        while (libvchan_data_ready(ctrl_vchan))
            handle_server_cmd();

        if (FD_ISSET(trigger_fd, &rdset))
            handle_trigger_io();

        handle_terminated_fork_client(&rdset);
    }

    libvchan_close(ctrl_vchan);
}
