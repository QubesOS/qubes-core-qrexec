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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <err.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include "qrexec.h"
#include "libqrexec-utils.h"

#define QREXEC_MIN_VERSION QREXEC_PROTOCOL_V2
#define QREXEC_SOCKET_PATH "/var/run/qubes/policy.sock"

#ifdef COVERAGE
void __gcov_dump(void);
void __gcov_reset(void);
#endif

enum client_state {
    CLIENT_INVALID = 0,	// table slot not used
    CLIENT_HELLO, // waiting for client hello
    CLIENT_CMDLINE,	// waiting for cmdline from client
    CLIENT_RUNNING // waiting for client termination (to release vchan port)
};

enum vchan_port_state {
    VCHAN_PORT_UNUSED = -1
};

struct _client {
    int state;		// enum client_state
};

enum policy_response {
    RESPONSE_PENDING,
    RESPONSE_ALLOW,
    RESPONSE_DENY
};

struct _policy_pending {
    pid_t pid;
    struct service_params params;
    enum policy_response response_sent;
};

#define VCHAN_BASE_DATA_PORT (VCHAN_BASE_PORT+1)

/*
   The "clients" array is indexed by client's fd.
   Thus its size must be equal MAX_FDS; defining MAX_CLIENTS for clarity.
   */

#define MAX_CLIENTS MAX_FDS
struct _client clients[MAX_CLIENTS];	// data on all qrexec_client connections

struct _policy_pending policy_pending[MAX_CLIENTS];
int policy_pending_max = -1;

/* indexed with vchan port number relative to VCHAN_BASE_DATA_PORT; stores
 * either VCHAN_PORT_* or remote domain id for used port */
int used_vchan_ports[MAX_CLIENTS];

/* notify client (close its connection) when connection initiated by it was
 * terminated - used by qrexec-policy to cleanup (disposable) VM; indexed with
 * vchan port number relative to VCHAN_BASE_DATA_PORT; stores fd of given
 * client or -1 if none requested */
int vchan_port_notify_client[MAX_CLIENTS];

int max_client_fd = -1;		// current max fd of all clients; so that we need not to scan all the "clients" table
int qrexec_daemon_unix_socket_fd;	// /var/run/qubes/qrexec.xid descriptor
const char *default_user = "user";
const char default_user_keyword[] = "DEFAULT:";
#define default_user_keyword_len_without_colon (sizeof(default_user_keyword)-2)

int opt_quiet = 0;
int opt_direct = 0;

const char *socket_dir = QREXEC_DAEMON_SOCKET_DIR;
const char *policy_program = QREXEC_POLICY_PROGRAM;

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

volatile int children_count;
volatile int child_exited;
volatile int terminate_requested;

libvchan_t *vchan;
int protocol_version;

void sigusr1_handler(int UNUSED(x))
{
    if (!opt_quiet)
        LOG(INFO, "Connected to VM");
    exit(0);
}

void sigchld_parent_handler(int UNUSED(x))
{
    children_count--;
    /* starting value is 0 so we see dead real qrexec-daemon as -1 */
    if (children_count < 0) {
        LOG(ERROR, "Connection to the VM failed");
        exit(1);
    }
}


char *remote_domain_name;	// guess what
int remote_domain_id;

void unlink_qrexec_socket()
{
    char socket_address[40];
    char link_to_socket_name[strlen(remote_domain_name) + sizeof(socket_address)];

    int v = snprintf(socket_address, sizeof(socket_address),
                     "%s/qrexec.%d", socket_dir, remote_domain_id);
    if (v < (int)sizeof("/qrexec.1") || v >= (int)sizeof(socket_address))
        abort();
    v = snprintf(link_to_socket_name, sizeof(link_to_socket_name),
                 "%s/qrexec.%s", socket_dir, remote_domain_name);
    if (v < (int)sizeof("/qrexec.") || v >= (int)sizeof(link_to_socket_name))
        abort();
    unlink(socket_address);
    unlink(link_to_socket_name);
}

void handle_vchan_error(const char *op)
{
    LOG(ERROR, "Error while vchan %s, exiting", op);
    exit(1);
}


int create_qrexec_socket(int domid, const char *domname)
{
    char socket_address[40];
    char link_to_socket_name[strlen(domname) + sizeof(socket_address)];

    snprintf(socket_address, sizeof(socket_address),
             "%s/qrexec.%d", socket_dir, domid);
    snprintf(link_to_socket_name, sizeof link_to_socket_name,
             "%s/qrexec.%s", socket_dir, domname);
    unlink(link_to_socket_name);

    /* When running as root, make the socket accessible; perms on /var/run/qubes still apply */
    umask(0);
    if (symlink(socket_address, link_to_socket_name)) {
        PERROR("symlink(%s,%s)", socket_address, link_to_socket_name);
    }
    int fd = get_server_socket(socket_address);
    umask(0077);
    return fd;
}

#define MAX_STARTUP_TIME_DEFAULT 60

static void incompatible_protocol_error_message(
        const char *domain_name, int remote_version)
{
    char text[1024];
    int ret;
    struct stat buf;
    ret=stat("/usr/bin/kdialog", &buf);
#define KDIALOG_CMD "kdialog --title 'Qrexec daemon' --sorry "
#define ZENITY_CMD "zenity --title 'Qrexec daemon' --warning --text "
    snprintf(text, sizeof(text),
            "%s"
            "'Domain %s uses incompatible qrexec protocol (%d instead of %d). "
            "You need to update either dom0 or VM packages.\n"
            "To access this VM console do not close this error message and run:\n"
            "sudo xl console -t pv %s'",
            ret==0 ? KDIALOG_CMD : ZENITY_CMD,
            domain_name, remote_version, QREXEC_PROTOCOL_VERSION, domain_name);
#undef KDIALOG_CMD
#undef ZENITY_CMD
    /* silence -Wunused-result */
    ret = system(text);
}

int handle_agent_hello(libvchan_t *ctrl, const char *domain_name)
{
    struct msg_header hdr;
    struct peer_info info;
    int actual_version;

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

    if (actual_version < QREXEC_MIN_VERSION) {
        LOG(ERROR, "Incompatible agent protocol version (remote %d, local %d)", info.version, QREXEC_PROTOCOL_VERSION);
        incompatible_protocol_error_message(domain_name, info.version);
        return -1;
    }

    /* send own HELLO */
    /* those messages are the same as received from agent, but set it again for
     * readability */
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

    return actual_version;
}

static void signal_handler(int sig);

/* do the preparatory tasks, needed before entering the main event loop */
void init(int xid)
{
    char qrexec_error_log_name[256];
    int logfd;
    int i;
    pid_t pid;
    int startup_timeout = MAX_STARTUP_TIME_DEFAULT;
    const char *startup_timeout_str = NULL;

    if (xid <= 0) {
        LOG(ERROR, "domain id=0?");
        exit(1);
    }
    startup_timeout_str = getenv("QREXEC_STARTUP_TIMEOUT");
    if (startup_timeout_str) {
        startup_timeout = atoi(startup_timeout_str);
        if (startup_timeout <= 0)
            // invalid or negative number
            startup_timeout = MAX_STARTUP_TIME_DEFAULT;
    }

    if (!opt_direct) {
        struct sigaction action = {
            .sa_handler = sigusr1_handler,
            .sa_flags = 0,
        };
        if (sigaction(SIGUSR1, &action, NULL))
            err(1, "sigaction");
        action.sa_handler = sigchld_parent_handler;
        if (sigaction(SIGCHLD, &action, NULL))
            err(1, "sigaction");
        switch (pid=fork()) {
            case -1:
                PERROR("fork");
                exit(1);
            case 0:
                break;
            default:
                if (getenv("QREXEC_STARTUP_NOWAIT"))
                    exit(0);
                if (!opt_quiet)
                    LOG(ERROR, "Waiting for VM's qrexec agent.");
                for (i=0;i<startup_timeout;i++) {
                    sleep(1);
                    if (!opt_quiet)
                        fprintf(stderr, ".");
                    if (i==startup_timeout-1) {
                        break;
                    }
                }
                LOG(ERROR, "Cannot connect to '%s' qrexec agent for %d seconds, giving up", remote_domain_name, startup_timeout);
                exit(3);
        }
    }

    close(0);

    if (!opt_direct) {
        snprintf(qrexec_error_log_name, sizeof(qrexec_error_log_name),
                 "/var/log/qubes/qrexec.%s.log", remote_domain_name);
        umask(0007);        // make the log readable by the "qubes" group
        logfd =
            open(qrexec_error_log_name, O_WRONLY | O_CREAT | O_TRUNC,
                 0660);

        if (logfd < 0) {
            PERROR("open");
            exit(1);
        }

        dup2(logfd, 1);
        dup2(logfd, 2);

        if (chdir("/var/run/qubes") < 0) {
            PERROR("chdir /var/run/qubes failed");
            exit(1);
        }
        if (setsid() < 0) {
            PERROR("setsid()");
            exit(1);
        }
    }

    vchan = libvchan_client_init(xid, VCHAN_BASE_PORT);
    if (!vchan) {
        PERROR("cannot connect to qrexec agent");
        exit(1);
    }

    protocol_version = handle_agent_hello(vchan, remote_domain_name);
    if (protocol_version < 0) {
        exit(1);
    }

    if (setgid(getgid()) < 0) {
        PERROR("setgid()");
        exit(1);
    }
    if (setuid(getuid()) < 0) {
        PERROR("setuid()");
        exit(1);
    }

    /* initialize clients state arrays */
    for (i = 0; i < MAX_CLIENTS; i++) {
        clients[i].state = CLIENT_INVALID;
        policy_pending[i].pid = 0;
        used_vchan_ports[i] = VCHAN_PORT_UNUSED;
        vchan_port_notify_client[i] = VCHAN_PORT_UNUSED;
    }

    atexit(unlink_qrexec_socket);
    qrexec_daemon_unix_socket_fd =
        create_qrexec_socket(xid, remote_domain_name);

    struct sigaction sigchld_action = {
        .sa_handler = signal_handler,
        .sa_flags = SA_NOCLDSTOP,
    };
    struct sigaction sigterm_action = {
        .sa_handler = signal_handler,
        .sa_flags = 0,
    };
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        err(1, "signal");
    if (sigaction(SIGCHLD, &sigchld_action, NULL))
        err(1, "sigaction");
    if (signal(SIGUSR1, SIG_DFL) == SIG_ERR)
        err(1, "signal");
    if (sigaction(SIGTERM, &sigterm_action, NULL))
        err(1, "sigaction");
    if (!opt_direct)
        kill(getppid(), SIGUSR1);   // let the parent know we are ready
}

static int send_client_hello(int fd)
{
    struct msg_header hdr;
    struct peer_info info;

    hdr.type = MSG_HELLO;
    hdr.len = sizeof(info);
    info.version = QREXEC_PROTOCOL_VERSION;

    if (!write_all(fd, &hdr, sizeof(hdr))) {
        LOG(ERROR, "Failed to send MSG_HELLO hdr to client %d", fd);
        return -1;
    }
    if (!write_all(fd, &info, sizeof(info))) {
        LOG(ERROR, "Failed to send MSG_HELLO to client %d", fd);
        return -1;
    }
    return 0;
}

static int allocate_vchan_port(int connect_domain)
{
    /*
      Make sure the allocated ports numbers are unique for a given {domX, domY}
      set.

      For domX-domY connections, both daemons can allocate ports. If they both
      allocate the same port number, this can cause trouble:
      - We might receive MSG_CONNECTION_TERMINATED for the wrong connection.
      - Although vchan connections in both directions can exist independently,
        the direction (client-server or server-client) is not always
        the same, so collision is still possible.

      To prevent that from happening, for X < Y allow the daemon for X to
      allocate only odd port numbers, and the daemon for Y to allocate only
      even port numbers.

      (This does not apply if we are connecting to/from dom0, as there is no
      separate daemon running for dom0).
     */

    int i, step;
    if (connect_domain == 0) {
        i = 0;
        step = 1;
    } else {
        i = connect_domain > remote_domain_id ? 1 : 0;
        step = 2;
    }

    for (; i < MAX_CLIENTS; i += step) {
        if (used_vchan_ports[i] == VCHAN_PORT_UNUSED) {
            used_vchan_ports[i] = connect_domain;
            return VCHAN_BASE_DATA_PORT+i;
        }
    }
    return 0;
}

static void handle_new_client()
{
    int fd = do_accept(qrexec_daemon_unix_socket_fd);
    if (fd >= MAX_CLIENTS) {
        LOG(ERROR, "too many clients ?");
        exit(1);
    }

    if (send_client_hello(fd) < 0) {
        close(fd);
        clients[fd].state = CLIENT_INVALID;
        return;
    }

    clients[fd].state = CLIENT_HELLO;
    if (fd > max_client_fd)
        max_client_fd = fd;
}

static void terminate_client(int fd)
{
    int port;
    clients[fd].state = CLIENT_INVALID;
    close(fd);
    /* if client requested vchan connection end notify, cancel it */
    for (port = 0; port < MAX_CLIENTS; port++) {
        if (vchan_port_notify_client[port] == fd)
            vchan_port_notify_client[port] = VCHAN_PORT_UNUSED;
    }
}

static void release_vchan_port(int port, int expected_remote_id)
{
    /* release only if was reserved for connection to given domain */
    if (used_vchan_ports[port-VCHAN_BASE_DATA_PORT] == expected_remote_id) {
        used_vchan_ports[port-VCHAN_BASE_DATA_PORT] = VCHAN_PORT_UNUSED;
        /* notify client if requested - it will clear notification request */
        if (vchan_port_notify_client[port-VCHAN_BASE_DATA_PORT] != VCHAN_PORT_UNUSED)
            terminate_client(vchan_port_notify_client[port-VCHAN_BASE_DATA_PORT]);
    }
}

static int handle_cmdline_body_from_client(int fd, struct msg_header *hdr)
{
    struct exec_params params;
    int len = hdr->len-sizeof(params);
    char buf[len];
    int use_default_user = 0;
    int i;

    if (!read_all(fd, &params, sizeof(params))) {
        terminate_client(fd);
        return 0;
    }
    if (!read_all(fd, buf, len)) {
        terminate_client(fd);
        return 0;
    }

    if (hdr->type == MSG_SERVICE_CONNECT) {
        /* if the service was accepted, do not send spurious
         * MSG_SERVICE_REFUSED when service process itself exit with non-zero
         * code. Avoid also sending MSG_SERVICE_CONNECT twice. */
        for (i = 0; i <= policy_pending_max; i++) {
            if (policy_pending[i].pid &&
                    policy_pending[i].response_sent == RESPONSE_PENDING &&
                    strncmp(policy_pending[i].params.ident, buf, len) == 0) {
                break;
            }
        }
        if (i > policy_pending_max) {
            LOG(ERROR, "Connection with ident %s not requested or already handled",
                    policy_pending[i].params.ident);
            terminate_client(fd);
            return 0;
        }
        policy_pending[i].response_sent = RESPONSE_ALLOW;
    }

    if (!params.connect_port) {
        struct exec_params client_params;
        /* allocate port and send it to the client */
        params.connect_port = allocate_vchan_port(params.connect_domain);
        if (params.connect_port <= 0) {
            LOG(ERROR, "Failed to allocate new vchan port, too many clients?");
            terminate_client(fd);
            return 0;
        }
        /* notify the client when this connection got terminated */
        vchan_port_notify_client[params.connect_port-VCHAN_BASE_DATA_PORT] = fd;
        client_params.connect_port = params.connect_port;
        client_params.connect_domain = remote_domain_id;
        hdr->len = sizeof(client_params);
        if (!write_all(fd, hdr, sizeof(*hdr))) {
            terminate_client(fd);
            release_vchan_port(params.connect_port, params.connect_domain);
            return 0;
        }
        if (!write_all(fd, &client_params, sizeof(client_params))) {
            terminate_client(fd);
            release_vchan_port(params.connect_port, params.connect_domain);
            return 0;
        }
        /* restore original len value */
        hdr->len = len+sizeof(params);
    } else {
        assert(params.connect_port >= VCHAN_BASE_DATA_PORT);
        assert(params.connect_port < VCHAN_BASE_DATA_PORT+MAX_CLIENTS);
    }

    if (!strncmp(buf, default_user_keyword, default_user_keyword_len_without_colon+1)) {
        use_default_user = 1;
        hdr->len -= default_user_keyword_len_without_colon;
        hdr->len += strlen(default_user);
    }
    if (libvchan_send(vchan, hdr, sizeof(*hdr)) != sizeof(*hdr))
        handle_vchan_error("send");
    if (libvchan_send(vchan, &params, sizeof(params)) != sizeof(params))
        handle_vchan_error("send params");
    if (use_default_user) {
        int send_len = strlen(default_user);
        if (libvchan_send(vchan, default_user, send_len) != send_len)
            handle_vchan_error("send default_user");
        send_len = len-default_user_keyword_len_without_colon;
        if (libvchan_send(vchan, buf+default_user_keyword_len_without_colon,
                    send_len) != send_len)
            handle_vchan_error("send buf");
    } else
        if (libvchan_send(vchan, buf, len) < len)
            handle_vchan_error("send buf");
    return 1;
}

static void handle_cmdline_message_from_client(int fd)
{
    struct msg_header hdr;
    if (!read_all(fd, &hdr, sizeof hdr)) {
        terminate_client(fd);
        return;
    }
    switch (hdr.type) {
        case MSG_EXEC_CMDLINE:
        case MSG_JUST_EXEC:
        case MSG_SERVICE_CONNECT:
            break;
        default:
            terminate_client(fd);
            return;
    }

    if (!handle_cmdline_body_from_client(fd, &hdr))
        // client disconnected while sending cmdline, above call already
        // cleaned up client info
        return;
    clients[fd].state = CLIENT_RUNNING;
}

static void handle_client_hello(int fd)
{
    struct msg_header hdr;
    struct peer_info info;

    if (!read_all(fd, &hdr, sizeof hdr)) {
        terminate_client(fd);
        return;
    }
    if (hdr.type != MSG_HELLO || hdr.len != sizeof(info)) {
        LOG(ERROR, "Invalid HELLO packet received from client %d: "
                "type %d, len %d", fd, hdr.type, hdr.len);
        terminate_client(fd);
        return;
    }
    if (!read_all(fd, &info, sizeof info)) {
        terminate_client(fd);
        return;
    }
    if (info.version != QREXEC_PROTOCOL_VERSION) {
        LOG(ERROR, "Incompatible client protocol version (remote %d, local %d)", info.version, QREXEC_PROTOCOL_VERSION);
        terminate_client(fd);
        return;
    }
    clients[fd].state = CLIENT_CMDLINE;
}

/* handle data received from one of qrexec_client processes */
static void handle_message_from_client(int fd)
{
    char buf[1];

    switch (clients[fd].state) {
        case CLIENT_HELLO:
            handle_client_hello(fd);
            return;
        case CLIENT_CMDLINE:
            handle_cmdline_message_from_client(fd);
            return;
        case CLIENT_RUNNING:
            // expected EOF
            if (read(fd, buf, sizeof(buf)) != 0) {
                LOG(ERROR, "Unexpected data received from client %d", fd);
            }
            terminate_client(fd);
            return;
        default:
            LOG(ERROR, "Invalid client state %d", clients[fd].state);
            exit(1);
    }
}


/*
 * The signal handler executes asynchronously; therefore all it should do is
 * to set a flag "signal has arrived", and let the main even loop react to this
 * flag in appropriate moment.
 */
static void signal_handler(int sig)
{
    switch (sig) {
    case SIGCHLD:
        child_exited = 1;
        break;
    case SIGTERM:
        terminate_requested = 1;
        break;
    default:
        /* cannot happen */
        abort();
    }
}

static void send_service_refused(libvchan_t *vchan, const struct service_params *params) {
    struct msg_header hdr;

    hdr.type = MSG_SERVICE_REFUSED;
    hdr.len = sizeof(*params);

    if (libvchan_send(vchan, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        LOG(ERROR, "Failed to send MSG_SERVICE_REFUSED hdr to agent");
        exit(1);
    }

    if (libvchan_send(vchan, params, sizeof(*params)) != sizeof(*params)) {
        LOG(ERROR, "Failed to send MSG_SERVICE_REFUSED to agent");
        exit(1);
    }
}

/* clean zombies, check for denied service calls */
static void reap_children()
{
    int status;
    int i;

    pid_t pid;
    while ((pid=waitpid(-1, &status, WNOHANG)) > 0) {
        for (i = 0; i <= policy_pending_max; i++) {
            if (policy_pending[i].pid == pid) {
                status = WEXITSTATUS(status);
                if (status != 0) {
                    if (policy_pending[i].response_sent != RESPONSE_PENDING) {
                        LOG(ERROR, "qrexec-policy-exec for connection %s exited with code %d, but the response (%s) was already sent",
                                policy_pending[i].params.ident, status,
                                policy_pending[i].response_sent == RESPONSE_ALLOW ? "allow" : "deny");
                    } else {
                        send_service_refused(vchan, &policy_pending[i].params);
                    }
                }
                /* in case of allowed calls, we will do the rest in
                 * MSG_SERVICE_CONNECT from client handler */
                policy_pending[i].pid = 0;
                while (policy_pending_max > 0 &&
                        policy_pending[policy_pending_max].pid == 0)
                    policy_pending_max--;
                break;
            }
        }
    }
    child_exited = 0;
}

static int find_policy_pending_slot() {
    int i;

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (policy_pending[i].pid == 0) {
            if (i > policy_pending_max)
                policy_pending_max = i;
            return i;
        }
    }
    return -1;
}

static void sanitize_name(char * untrusted_s_signed, char *extra_allowed_chars)
{
    unsigned char * untrusted_s;
    for (untrusted_s=(unsigned char*)untrusted_s_signed; *untrusted_s; untrusted_s++) {
        if (*untrusted_s >= 'a' && *untrusted_s <= 'z')
            continue;
        if (*untrusted_s >= 'A' && *untrusted_s <= 'Z')
            continue;
        if (*untrusted_s >= '0' && *untrusted_s <= '9')
            continue;
        if (*untrusted_s == '_' ||
               *untrusted_s == '-' ||
               *untrusted_s == '.')
            continue;
        if (extra_allowed_chars && strchr(extra_allowed_chars, *untrusted_s))
            continue;
        *untrusted_s = '_';
    }
}

#define ENSURE_NULL_TERMINATED(x) x[sizeof(x)-1] = 0

/*
 * Called when agent sends a message asking to execute a predefined command.
 */

static int connect_daemon_socket(
        const int remote_domain_id,
        const char *remote_domain_name,
        const char *target_domain,
        const char *service_name,
        const struct service_params *request_id
) {
    int result;
    int command_size;
    char response[32];
    char *command;
    int daemon_socket;
    struct sockaddr_un daemon_socket_address = {
        .sun_family = AF_UNIX,
        .sun_path = QREXEC_SOCKET_PATH
    };

    daemon_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (daemon_socket < 0) {
         PERROR("socket creation failed");
         return -1;
    }

    result = connect(daemon_socket, (struct sockaddr *) &daemon_socket_address,
            sizeof(daemon_socket_address));
    if (result < 0) {
         PERROR("connection to socket failed");
         return -1;
    }

    command_size = asprintf(&command, "domain_id=%d\n"
        "source=%s\n"
        "intended_target=%s\n"
        "service_and_arg=%s\n"
        "process_ident=%s\n\n",
        remote_domain_id, remote_domain_name, target_domain,
        service_name, request_id->ident);
    if (command_size < 0) {
         PERROR("failed to construct request");
         return -1;
    }

    result = send(daemon_socket, command, command_size, 0);
    free(command);
    if (result < 0) {
         PERROR("send to socket failed");
         return -1;
    }

    result = recv(daemon_socket, response, sizeof(response) - 1, 0);
    if (result < 0) {
         PERROR("error reading from socket");
         return -1;
    }
    else {
        response[result] = '\0';
        if (!strncmp(response, "result=allow\n", sizeof("result=allow\n")-1)) {
            return 0;
        } else if (!strncmp(response, "result=deny\n", sizeof("result=deny\n")-1)) {
            return 1;
        } else {
            LOG(ERROR, "invalid response: %s", response);
            return -1;
        }
    }
}


static void handle_execute_service(
        const int remote_domain_id,
        const char *remote_domain_name,
        const char *target_domain,
        const char *service_name,
        const struct service_params *request_id)
{
    int i;
    int result;
    int policy_pending_slot;
    pid_t pid;
    char remote_domain_id_str[10];
    sigset_t sigmask;

    policy_pending_slot = find_policy_pending_slot();
    if (policy_pending_slot < 0) {
        LOG(ERROR, "Service request denied, too many pending requests");
        send_service_refused(vchan, request_id);
        return;
    }

    switch (pid=fork()) {
        case -1:
            PERROR("fork");
            exit(1);
        case 0:
            break;
        default:
            policy_pending[policy_pending_slot].pid = pid;
            policy_pending[policy_pending_slot].params = *request_id;
            policy_pending[policy_pending_slot].response_sent = RESPONSE_PENDING;
            return;
    }

    for (i = 3; i < MAX_FDS; i++)
        close(i);

    result = connect_daemon_socket(remote_domain_id, remote_domain_name,
                                   target_domain, service_name, request_id);
    if (result >= 0) {
        _exit(result);
    }

    LOG(ERROR, "couldn't invoke qrexec-policy-daemon, using qrexec-policy-exec");

    sigemptyset(&sigmask);
    if (sigprocmask(SIG_SETMASK, &sigmask, NULL)) {
        PERROR("sigprocmask");
        _exit(1);
    }
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR ||
        signal(SIGPIPE, SIG_DFL) == SIG_ERR)
    {
        PERROR("signal");
        _exit(1);
    }
    int v = snprintf(remote_domain_id_str, sizeof(remote_domain_id_str), "%d",
                     remote_domain_id);
    if (v >= 1 && v < (int)sizeof(remote_domain_id_str)) {
        execl(policy_program, "qrexec-policy-exec", "--",
              remote_domain_id_str,
              remote_domain_name,
              target_domain,
              service_name,
              request_id->ident,
              NULL);
        PERROR("execl");
    } else {
        PERROR("snprintf");
    }
    _exit(1);
}


static void handle_connection_terminated()
{
    struct exec_params untrusted_params, params;

    if (libvchan_recv(vchan, &untrusted_params, sizeof(untrusted_params))
            != sizeof(untrusted_params))
        handle_vchan_error("recv params");
    /* sanitize start */
    if (untrusted_params.connect_port < VCHAN_BASE_DATA_PORT ||
            untrusted_params.connect_port >= VCHAN_BASE_DATA_PORT+MAX_CLIENTS) {
        LOG(ERROR, "Invalid port in MSG_CONNECTION_TERMINATED (%d)",
                untrusted_params.connect_port);
        exit(1);
    }
    /* untrusted_params.connect_domain even if invalid will not harm - in worst
     * case the port will not be released */
    params = untrusted_params;
    /* sanitize end */
    release_vchan_port(params.connect_port, params.connect_domain);
}

static void sanitize_message_from_agent(struct msg_header *untrusted_header)
{
    switch (untrusted_header->type) {
        case MSG_TRIGGER_SERVICE:
            if (protocol_version >= QREXEC_PROTOCOL_V3) {
                LOG(ERROR, "agent sent (old) MSG_TRIGGER_SERVICE "
                    "although it uses protocol %d", protocol_version);
                exit(1);
            }
            if (untrusted_header->len != sizeof(struct trigger_service_params)) {
                LOG(ERROR, "agent sent invalid MSG_TRIGGER_SERVICE packet");
                exit(1);
            }
            break;
        case MSG_TRIGGER_SERVICE3:
            if (protocol_version < QREXEC_PROTOCOL_V3) {
                LOG(ERROR, "agent sent (new) MSG_TRIGGER_SERVICE3 "
                    "although it uses protocol %d", protocol_version);
                exit(1);
            }
            if (untrusted_header->len <= sizeof(struct trigger_service_params3)) {
                LOG(ERROR, "agent sent invalid MSG_TRIGGER_SERVICE3 packet");
                exit(1);
            }
            if (untrusted_header->len - sizeof(struct trigger_service_params3)
                    > MAX_SERVICE_NAME_LEN) {
                LOG(ERROR, "agent sent too large MSG_TRIGGER_SERVICE3 packet");
                exit(1);
            }
            break;
        case MSG_CONNECTION_TERMINATED:
            if (untrusted_header->len != sizeof(struct exec_params)) {
                LOG(ERROR, "agent sent invalid MSG_CONNECTION_TERMINATED packet");
                exit(1);
            }
            break;
        default:
            LOG(ERROR, "unknown mesage type 0x%x from agent",
                    untrusted_header->type);
            exit(1);
    }
}

static void handle_message_from_agent(void)
{
    struct msg_header hdr, untrusted_hdr;
    struct trigger_service_params untrusted_params, params;
    struct trigger_service_params3 untrusted_params3, params3;
    char *untrusted_service_name = NULL, *service_name = NULL;
    size_t service_name_len;

    if (libvchan_recv(vchan, &untrusted_hdr, sizeof(untrusted_hdr))
            != sizeof(untrusted_hdr))
        handle_vchan_error("recv hdr");
    /* sanitize start */
    sanitize_message_from_agent(&untrusted_hdr);
    hdr = untrusted_hdr;
    /* sanitize end */

    //      fprintf(stderr, "got %x %x %x\n", hdr.type, hdr.client_id,
    //              hdr.len);

    switch (hdr.type) {
        case MSG_TRIGGER_SERVICE:
            if (libvchan_recv(vchan, &untrusted_params, sizeof(untrusted_params))
                    != sizeof(untrusted_params))
                handle_vchan_error("recv params");

            /* sanitize start */
            ENSURE_NULL_TERMINATED(untrusted_params.service_name);
            ENSURE_NULL_TERMINATED(untrusted_params.target_domain);
            ENSURE_NULL_TERMINATED(untrusted_params.request_id.ident);
            sanitize_name(untrusted_params.service_name, "+");
            sanitize_name(untrusted_params.target_domain, "@:");
            sanitize_name(untrusted_params.request_id.ident, " ");
            params = untrusted_params;
            /* sanitize end */

            handle_execute_service(remote_domain_id, remote_domain_name,
                    params.target_domain,
                    params.service_name,
                    &params.request_id);
            return;
        case MSG_TRIGGER_SERVICE3:
            service_name_len = hdr.len - sizeof(untrusted_params3);
            untrusted_service_name = malloc(service_name_len);
            if (!untrusted_service_name)
                handle_vchan_error("malloc(service_name)");

            if (libvchan_recv(vchan, &untrusted_params3, sizeof(untrusted_params3))
                    != sizeof(untrusted_params3))
                handle_vchan_error("recv params3");
            if (libvchan_recv(vchan, untrusted_service_name, service_name_len)
                    != (int)service_name_len)
                handle_vchan_error("recv params3(service_name)");

            /* sanitize start */
            ENSURE_NULL_TERMINATED(untrusted_params3.target_domain);
            ENSURE_NULL_TERMINATED(untrusted_params3.request_id.ident);
            untrusted_service_name[service_name_len-1] = 0;
            sanitize_name(untrusted_params3.target_domain, "@:");
            sanitize_name(untrusted_params3.request_id.ident, " ");
            sanitize_name(untrusted_service_name, "+");
            params3 = untrusted_params3;
            service_name = untrusted_service_name;
            untrusted_service_name = NULL;
            /* sanitize end */

            handle_execute_service(remote_domain_id, remote_domain_name,
                    params3.target_domain,
                    service_name,
                    &params3.request_id);
            free(service_name);
            return;
        case MSG_CONNECTION_TERMINATED:
            handle_connection_terminated();
            return;
    }
}

/*
 * Scan the "clients" table, add ones we want to read from (because the other
 * end has not send MSG_XOFF on them) to read_fdset, add ones we want to write
 * to (because its pipe is full) to write_fdset. Return the highest used file
 * descriptor number, needed for the first select() parameter.
 */
static int fill_fdsets_for_select(fd_set * read_fdset, fd_set * write_fdset)
{
    int i;
    int max = -1;

    FD_ZERO(read_fdset);
    FD_ZERO(write_fdset);
    assert(max_client_fd < FD_SETSIZE);
    assert(qrexec_daemon_unix_socket_fd < FD_SETSIZE);
    for (i = 0; i <= max_client_fd; i++) {
        if (clients[i].state != CLIENT_INVALID) {
            FD_SET(i, read_fdset);
            max = i;
        }
    }

    FD_SET(qrexec_daemon_unix_socket_fd, read_fdset);
    if (qrexec_daemon_unix_socket_fd > max)
        max = qrexec_daemon_unix_socket_fd;

    return max;
}

/* qrexec-agent has disconnected, cleanup local state and try to connect again.
 * If remote domain dies, terminate qrexec-daemon.
 */
static int handle_agent_restart(int xid) {
    size_t i;

    // Stop listening.
    unlink_qrexec_socket();
    close(qrexec_daemon_unix_socket_fd);

    /* Close old (dead) vchan connection. */
    libvchan_close(vchan);
    vchan = NULL;

    /* Disconnect all local clients. This will look like all the qrexec
     * connections were terminated, which isn't necessary true (established
     * qrexec connection may survive qrexec-agent and qrexec-daemon restart),
     * but we won't be notified about its termination. This may kill DispVM
     * prematurely (if anyone restarts qrexec-agent inside DispVM), but it's
     * better than the alternative (leaking DispVMs).
     *
     * But, do not mark related vchan ports as unused. Since we won't get call
     * end notification, we don't know when such ports will really be unused.
     */
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].state != CLIENT_INVALID)
            terminate_client(i);
    }

    /* Abort pending qrexec requests */
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (policy_pending[i].pid != 0)
            policy_pending[i].pid = 0;
    }
    policy_pending_max = -1;

    /* Restore default SIGTERM handling: libvchan_client_init() might block
     * indefinitely, so we want the program to be killable.
     */
    if (signal(SIGTERM, SIG_DFL) == SIG_ERR)
        err(1, "signal()");
    if (terminate_requested)
        return -1;

#ifdef COVERAGE
    /* Dump coverage in case we are killed here. */
    __gcov_dump();
    __gcov_reset();
#endif

    vchan = libvchan_client_init(remote_domain_id, VCHAN_BASE_PORT);
    if (!vchan) {
        PERROR("cannot connect to qrexec agent");
        return -1;
    }
    if (handle_agent_hello(vchan, remote_domain_name) < 0) {
        libvchan_close(vchan);
        vchan = NULL;
        return -1;
    }
    LOG(INFO, "qrexec-agent has reconnected");

    struct sigaction action = {
        .sa_handler = signal_handler,
        .sa_flags = 0,
    };
    if (sigaction(SIGTERM, &action, NULL))
        err(1, "sigaction");

    qrexec_daemon_unix_socket_fd =
        create_qrexec_socket(xid, remote_domain_name);
    return 0;
}

struct option longopts[] = {
    { "help", no_argument, 0, 'h' },
    { "quiet", no_argument, 0, 'q' },
    { "socket-dir", required_argument, 0, 'd' + 128 },
    { "policy-program", required_argument, 0, 'p' },
    { "direct", no_argument, 0, 'D' },
    { NULL, 0, 0, 0 },
};

_Noreturn void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [options] domainid domain-name [default user]\n", argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help - display usage\n");
    fprintf(stderr, "  -q, --quiet - quiet mode\n");
    fprintf(stderr, "  --socket-dir=PATH - directory for qrexec socket, default: %s\n",
            QREXEC_DAEMON_SOCKET_DIR);
    fprintf(stderr, "  -p, --policy-program=PATH - program to execute to check policy, default: %s\n",
            QREXEC_POLICY_PROGRAM);
    fprintf(stderr, "  -D, --direct - run directly, don't daemonize, log to stderr\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int i, opt;
    sigset_t selectmask;

    setup_logging("qrexec-daemon");

    while ((opt=getopt_long(argc, argv, "hqp:D", longopts, NULL)) != -1) {
        switch (opt) {
            case 'q':
                opt_quiet = 1;
                break;
            case 'd' + 128:
                if ((socket_dir = strdup(optarg)) == NULL)
                    err(1, "strdup()");
                break;
            case 'p':
                if ((policy_program = strdup(optarg)) == NULL)
                    err(1, "strdup()");
                break;
            case 'D':
                opt_direct = 1;
                break;
            case 'h':
            default: /* '?' */
                usage(argv[0]);
        }
    }
    if (argc - optind < 2 || argc - optind > 3) {
        usage(argv[0]);
    }
    remote_domain_id = atoi(argv[optind]);
    remote_domain_name = argv[optind+1];
    if (argc - optind >= 3)
        default_user = argv[optind+2];
    init(remote_domain_id);

    sigemptyset(&selectmask);
    sigaddset(&selectmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &selectmask, NULL);
    sigemptyset(&selectmask);

    /*
     * The main event loop. Waits for one of the following events:
     * - message from client
     * - message from agent
     * - new client
     * - child exited
     */
    while (!terminate_requested) {
        struct timespec timeout = { 1, 0 };
        fd_set rdset, wrset;
        int ret, max;

        if (child_exited)
            reap_children();

        max = fill_fdsets_for_select(&rdset, &wrset);
        if (libvchan_buffer_space(vchan) <= (int)sizeof(struct msg_header))
            FD_ZERO(&rdset);	// vchan full - don't read from clients

        ret = pselect_vchan(vchan, max+1, &rdset, &wrset, &timeout, &selectmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            PERROR("pselect");
            return 1;
        }

        if (!libvchan_is_open(vchan)) {
            LOG(WARNING, "qrexec-agent has disconnected");
            if (handle_agent_restart(remote_domain_id) < 0) {
                LOG(ERROR, "Failed to reconnect to qrexec-agent, terminating");
                return 1;
            }
            /* rdset may be outdated at this point, calculate it again. */
            continue;
        }

        if (FD_ISSET(qrexec_daemon_unix_socket_fd, &rdset))
            handle_new_client();

        while (libvchan_data_ready(vchan))
            handle_message_from_agent();

        for (i = 0; i <= max_client_fd; i++)
            if (clients[i].state != CLIENT_INVALID
                && FD_ISSET(i, &rdset))
                handle_message_from_client(i);
    }

    if (vchan)
        libvchan_close(vchan);
}

// vim:ts=4:sw=4:et:
