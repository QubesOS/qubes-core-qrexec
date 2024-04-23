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
#include "../libqrexec/ioall.h"
#include "qrexec-daemon-common.h"

#define QREXEC_MIN_VERSION QREXEC_PROTOCOL_V2
#define QREXEC_SOCKET_PATH "/run/qubes/policy.sock"

#ifdef COVERAGE
void __gcov_dump(void);
void __gcov_reset(void);
#endif
static _Noreturn void daemon__exit(int status) {
#ifdef COVERAGE
    __gcov_dump();
#endif
    _exit(status);
}

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
    RESPONSE_DENY,
    RESPONSE_MALFORMED,
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
static struct _client clients[MAX_CLIENTS];	// data on all qrexec_client connections

static struct _policy_pending policy_pending[MAX_CLIENTS];
static int policy_pending_max = -1;

/* indexed with vchan port number relative to VCHAN_BASE_DATA_PORT; stores
 * either VCHAN_PORT_* or remote domain id for used port */
static int used_vchan_ports[MAX_CLIENTS];

/* notify client (close its connection) when connection initiated by it was
 * terminated - used by qrexec-policy to cleanup (disposable) VM; indexed with
 * vchan port number relative to VCHAN_BASE_DATA_PORT; stores fd of given
 * client or -1 if none requested */
static int vchan_port_notify_client[MAX_CLIENTS];

static int max_client_fd = -1;		// current max fd of all clients; so that we need not to scan all the "clients" table
static int qrexec_daemon_unix_socket_fd;	// /var/run/qubes/qrexec.xid descriptor
static const char *default_user = "user";
static const char default_user_keyword[] = "DEFAULT:";
#define default_user_keyword_len_without_colon (sizeof(default_user_keyword)-2)

static int opt_quiet = 0;

static const char *policy_program = QREXEC_POLICY_PROGRAM;

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

static volatile int child_exited;
static volatile int terminate_requested;

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include "../fuzz/fuzz.h"
#else
static
#endif
libvchan_t *vchan;
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static
#endif
int protocol_version;

static char *remote_domain_name;	// guess what
static int remote_domain_id;

static void unlink_qrexec_socket(void)
{
    char socket_address[40];
    char link_to_socket_name[strlen(remote_domain_name) + sizeof(socket_address)];

    int v = snprintf(socket_address, sizeof(socket_address),
                     "qrexec.%d", remote_domain_id);
    if (v < (int)sizeof("qrexec.1") - 1 || v >= (int)sizeof(socket_address))
        abort();
    v = snprintf(link_to_socket_name, sizeof(link_to_socket_name),
                 "qrexec.%s", remote_domain_name);
    if (v < (int)sizeof("qrexec.") - 1 || v >= (int)sizeof(link_to_socket_name))
        abort();
    v = unlink(socket_address);
    if (v != 0 && !(v == -1 && errno == ENOENT))
        err(1, "unlink(%s)", socket_address);
    v = unlink(link_to_socket_name);
    if (v != 0 && !(v == -1 && errno == ENOENT))
        err(1, "unlink(%s)", link_to_socket_name);
}

static void handle_vchan_error(const char *op)
{
    LOG(ERROR, "Error while vchan %s, exiting", op);
    exit(1);
}


static int create_qrexec_socket(int domid, const char *domname)
{
    char socket_address[40];
    char link_to_socket_name[strlen(domname) + sizeof(socket_address)];
    int res;

    if ((unsigned)snprintf(socket_address, sizeof(socket_address),
                           "qrexec.%d", domid) >= sizeof(socket_address))
        errx(1, "socket name too long");
    if ((unsigned)snprintf(link_to_socket_name, sizeof link_to_socket_name,
                           "qrexec.%s", domname) >= sizeof link_to_socket_name)
        errx(1, "socket link name too long");
    res = unlink(link_to_socket_name);
    if (res != 0 && !(res == -1 && errno == ENOENT))
        err(1, "unlink(%s)", link_to_socket_name);

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

static int handle_agent_hello(libvchan_t *ctrl, const char *domain_name)
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
static void init(int xid, bool opt_direct)
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

    int pipes[2];
    if (!opt_direct) {
        if (pipe2(pipes, O_CLOEXEC))
            err(1, "pipe2()");
        switch (pid=fork()) {
            case -1:
                PERROR("fork");
                exit(1);
            case 0:
                close(pipes[0]);
                break;
            default:
                if (getenv("QREXEC_STARTUP_NOWAIT"))
                    exit(0);
                close(pipes[1]);
                if (!opt_quiet)
                    LOG(ERROR, "Waiting for VM's qrexec agent.");
                struct pollfd fds[1] = {{ .fd = pipes[0], .events = POLLIN | POLLHUP, .revents = 0 }};
                for (;;) {
                    int res = poll(fds, 1, 1000);
                    if (res < 0)
                        err(1, "poll()");
                    if (res) {
                        char buf[1];
                        ssize_t bytes = read(pipes[0], buf, sizeof buf);
                        if (bytes < 0)
                            err(1, "read()");
                        if (bytes == 0) {
                            LOG(ERROR, "Connection to the VM failed");
                            exit(1);
                        }
                        switch (buf[0]) {
                        case 0:
                            if (!opt_quiet)
                                LOG(INFO, "Connected to VM");
                            exit(0);
                        case 1:
                            LOG(ERROR, "Cannot connect to '%s' qrexec agent for %d seconds, giving up", remote_domain_name, startup_timeout);
                            exit(3);
                        default:
                            abort();
                        }
                    }
                    if (!opt_quiet)
                        fprintf(stderr, ".");
                }
        }
    }


    if (chdir(socket_dir) < 0) {
        PERROR("chdir %s failed", socket_dir);
        exit(1);
    }

    if (!opt_direct) {
        if ((unsigned)snprintf(qrexec_error_log_name, sizeof(qrexec_error_log_name),
                               "qrexec.%s.log", remote_domain_name) >=
                sizeof(qrexec_error_log_name))
            errx(1, "remote domain name too long");
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

        if (setsid() < 0) {
            PERROR("setsid()");
            exit(1);
        }
    }

    int wait_fd;
    vchan = libvchan_client_init_async(xid, VCHAN_BASE_PORT, &wait_fd);
    if (!vchan) {
        LOG(ERROR, "Cannot create data vchan connection");
        exit(3);
    }
    if (qubes_wait_for_vchan_connection_with_timeout(
                vchan, wait_fd, false, startup_timeout) < 0) {
        if (!opt_direct && write(pipes[1], "\1", 1)) {}
        LOG(ERROR, "qrexec connection timeout");
        exit(3);
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
    sigemptyset(&sigchld_action.sa_mask);
    sigemptyset(&sigterm_action.sa_mask);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        err(1, "signal");
    if (sigaction(SIGCHLD, &sigchld_action, NULL))
        err(1, "sigaction");
    if (sigaction(SIGTERM, &sigterm_action, NULL))
        err(1, "sigaction");
    if (!opt_direct) {
        if (write(pipes[1], "", 1) != 1)
            err(1, "write(pipe)");
        close(pipes[1]);
    }
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

static void handle_new_client(void)
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
        case CLIENT_INVALID:
            return; /* nothing to do */
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

static void send_service_refused(libvchan_t *vchan, const struct service_params *untrusted_params) {
    struct msg_header hdr;

    hdr.type = MSG_SERVICE_REFUSED;
    hdr.len = sizeof(*untrusted_params);

    if (libvchan_send(vchan, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        LOG(ERROR, "Failed to send MSG_SERVICE_REFUSED hdr to agent");
        exit(1);
    }

    if (libvchan_send(vchan, untrusted_params, sizeof(*untrusted_params)) != sizeof(*untrusted_params)) {
        LOG(ERROR, "Failed to send MSG_SERVICE_REFUSED to agent");
        exit(1);
    }
}

/* clean zombies, check for denied service calls */
static void reap_children(void)
{
    int status;
    int i;

    pid_t pid;
    while ((pid=waitpid(-1, &status, WNOHANG)) > 0) {
        for (i = 0; i <= policy_pending_max; i++) {
            if (policy_pending[i].pid == pid) {
                if (!WIFEXITED(status))
                    continue;
                status = WEXITSTATUS(status);
                if (status != 0) {
                    if (policy_pending[i].response_sent != RESPONSE_PENDING) {
                        LOG(ERROR, "qrexec-policy-exec for connection %s exited with code %d, but the response (%s) was already sent",
                                policy_pending[i].params.ident, status,
                                policy_pending[i].response_sent == RESPONSE_ALLOW ? "allow" : "deny");
                    } else {
                        policy_pending[i].response_sent = RESPONSE_DENY;
                        send_service_refused(vchan, &policy_pending[i].params);
                    }
                } else {
                    policy_pending[i].response_sent = RESPONSE_ALLOW;
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

static int find_policy_pending_slot(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
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

static int parse_policy_response(
    char *response,
    size_t result_bytes,
    bool daemon,
    char **user,
    char **target,
    char **requested_target,
    int *autostart
) {
    *user = *target = *requested_target = NULL;
    int result = *autostart = -1;
    const char *const msg = daemon ? "qrexec-policy-daemon" : "qrexec-policy-exec";
    // At least one byte must be returned
    if (result_bytes < 1) {
        LOG(ERROR, "%s didn't return any data", msg);
        return RESPONSE_MALFORMED;
    }
    // Forbid NUL bytes in response.  qrexec_read_all_to_malloc() has added the
    // NUL terminator already.
    if (strlen(response) != result_bytes) {
        LOG(ERROR, "%s wrote a NUL byte", msg);
        return RESPONSE_MALFORMED;
    }
    // Strip any trailing newlines.
    if (response[result_bytes - 1] == '\n') {
        result_bytes--;
        response[result_bytes] = '\0';
    }
    char *resp = response, *current_response;
    while ((current_response = strsep(&resp, "\n"))) {
        if (!strncmp(current_response, "result=", sizeof("result=") - 1)) {
            current_response += sizeof("result=") - 1;
            if (result != -1) {
                goto bad_response;
            }
            if (!strcmp(current_response, "allow"))
                result = 0;
            else if (!strcmp(current_response, "deny")) {
                result = 1;
            } else {
                goto bad_response;
            }
        } else if (!strncmp(current_response, "user=", sizeof("user=") - 1)) {
            if (*user)
                goto bad_response;
            *user = strdup(current_response + (sizeof("user=") - 1));
            if (*user == NULL)
                abort();
        } else if (!strncmp(current_response, "target=", sizeof("target=") - 1)) {
            if (*target != NULL)
                goto bad_response;
            *target = strdup(current_response + (sizeof("target=") - 1));
            if (*target == NULL)
                abort();
        } else if (!strncmp(current_response, "autostart=", sizeof("autostart=") - 1)) {
            current_response += sizeof("autostart=") - 1;
            if (*autostart != -1)
                goto bad_response;
            if (!strcmp(current_response, "True"))
                *autostart = 1;
            else if (!strcmp(current_response, "False"))
                *autostart = 0;
            else
                goto bad_response;
        } else if (!strncmp(current_response, "requested_target=", sizeof("requested_target=") - 1)) {
            if (*requested_target != NULL)
                goto bad_response;
            *requested_target = strdup(current_response + (sizeof("requested_target=") - 1));
            if (*requested_target == NULL)
                abort();
        } else {
            char *p = strchr(current_response, '=');
            if (p == NULL)
                goto bad_response;
            *p = '\0';
            LOG(ERROR, "Unknown response key %s, ignoring", current_response);
        }
    }

    switch (result) {
    case 0:
        if (*user == NULL || *target == NULL || *requested_target == NULL || *autostart == -1)
            break;
        return RESPONSE_ALLOW;
    case 1:
        if (*user != NULL || *target != NULL || *requested_target != NULL || *autostart != -1)
            break;
        return RESPONSE_DENY;
    default:
        break;
    }

bad_response:
    LOG(ERROR, "%s sent invalid response", msg);
    return RESPONSE_MALFORMED;
}

struct QrexecPolicyRequest {
};

static void send_request_to_daemon(
        const int daemon_socket,
        const char *remote_domain_name,
        const char *target_domain,
        const char *service_name)
{
    char *command;
    ssize_t bytes_sent = 0;
    int command_size = asprintf(&command,
            "source=%s\n"
            "intended_target=%s\n"
            "service_and_arg=%s\n\n",
            remote_domain_name,
            target_domain,
            service_name);
    if (command_size < 0) {
        PERROR("failed to construct request");
        daemon__exit(126);
    }

    for (int i = 0; i < command_size; i += bytes_sent) {
        bytes_sent = send(daemon_socket, command + i, command_size - i, MSG_NOSIGNAL);
        if (bytes_sent > command_size - i)
            abort(); // kernel read beyond buffer bounds?
        if (bytes_sent < 0) {
            assert(bytes_sent == -1);
            PERROR("send to socket failed");
            daemon__exit(126);
        }
    }
    free(command);
}

static _Noreturn void null_exit(void)
{
#ifdef COVERAGE
    __gcov_dump();
#endif
    _exit(126);
}

/*
 * Called when agent sends a message asking to execute a predefined command.
 */

static enum policy_response connect_daemon_socket(
        const char *remote_domain_name,
        const char *target_domain,
        const char *service_name,
        char **user,
        char **target,
        char **requested_target,
        int *autostart
) {
    int pid = -1;
    struct sockaddr_un daemon_socket_address = {
        .sun_family = AF_UNIX,
        .sun_path = QREXEC_SOCKET_PATH
    };

    int daemon_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (daemon_socket < 0) {
         PERROR("socket creation failed");
         daemon__exit(126);
    }

    int connect_result = connect(daemon_socket,
            (struct sockaddr *) &daemon_socket_address,
            sizeof(daemon_socket_address));
    if (connect_result == 0) {
        send_request_to_daemon(daemon_socket,
                               remote_domain_name,
                               target_domain,
                               service_name);
        size_t result_bytes;
        // this closes the socket
        char *result = qubes_read_all_to_malloc(daemon_socket, 64, 4096, &result_bytes);
        int policy_result = parse_policy_response(result, result_bytes, true, user, target, requested_target, autostart);
        if (policy_result != RESPONSE_MALFORMED) {
            // This leaks 'result', but as the code execs later anyway this isn't a problem.
            // 'result' cannot be freed as 'user', 'target', and 'requested_target' point into
            // the same buffer.
            return policy_result;
        }
        free(result);
    } else {
        PERROR("connection to socket failed");
        assert(connect_result == -1);
        if (close(daemon_socket))
            abort();
    }
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds)) {
        PERROR("socketpair()");
        daemon__exit(126);
    }
    daemon_socket = fds[0];

    pid = fork();
    switch (pid) {
        case -1:
            LOG(ERROR, "Could not fork!");
            daemon__exit(126);
        case 0:
            if (close(fds[0]))
                _exit(126);
            if (dup2(fds[1], 0) != 0 || dup2(fds[1], 1) != 1) {
                PERROR("dup2()");
                daemon__exit(126);
            }
            if (close(fds[1]))
                abort();
            char remote_domain_id_str[10];
            int v = snprintf(remote_domain_id_str, sizeof(remote_domain_id_str), "%d",
                    remote_domain_id);
            if (v >= 1 && v < (int)sizeof(remote_domain_id_str)) {
                execl(policy_program,
                        "qrexec-policy-exec",
                        "--",
                        remote_domain_name,
                        target_domain,
                        service_name,
                        NULL);
                PERROR("execl");
            } else {
                PERROR("snprintf");
            }
            daemon__exit(126);
        default:
            if (close(fds[1]))
                abort();
            size_t result_bytes;
            int status;
            // this closes the socket
            char *result = qubes_read_all_to_malloc(daemon_socket, 64, 4096, &result_bytes);
            do {
                if (waitpid(pid, &status, 0) != pid) {
                    PERROR("waitpid");
                    daemon__exit(126);
                }
            } while (!WIFEXITED(status));
            if (WEXITSTATUS(status) != 0) {
                LOG(ERROR, "qrexec-policy-exec failed");
                daemon__exit(126);
            }
            // This leaks 'result', but as the code execs later anyway this isn't a problem.
            // 'result' cannot be freed as 'user', 'target', and 'requested_target' point into
            // the same buffer.
            return parse_policy_response(result, result_bytes, true, user, target, requested_target, autostart);
    }
}

static size_t compute_service_length(const char *const remote_cmdline) {
    const size_t service_length = strlen(remote_cmdline) + 1;
    if (service_length < 2 || service_length > MAX_QREXEC_CMD_LEN) {
        /* This is arbitrary, but it helps reduce the risk of overflows in other code */
        errx(1, "Bad command: command line too long or empty: length %zu\n", service_length);
    }
    return service_length;
}

/* called from do_fork_exec */
static _Noreturn void do_exec(const char *prog, const char *username __attribute__((unused)))
{
    /* avoid calling qubes-rpc-multiplexer through shell */
    exec_qubes_rpc_if_requested(prog, environ);

    /* if above haven't executed qubes-rpc-multiplexer, pass it to shell */
    execl("/bin/bash", "bash", "-c", prog, NULL);
    PERROR("exec bash");
    _exit(126);
}

_Noreturn static void handle_execute_service_child(
        const int remote_domain_id,
        const char *remote_domain_name,
        const char *target_domain,
        const char *service_name,
        const struct service_params *request_id) {
    int i;

    for (i = 3; i < MAX_FDS; i++)
        close(i);

    char *user, *target, *requested_target;
    int autostart;
    int policy_response =
        connect_daemon_socket(remote_domain_name, target_domain, service_name,
                              &user, &target, &requested_target, &autostart);

    if (policy_response != RESPONSE_ALLOW)
        daemon__exit(126);

    /* Replace the target domain with the version normalized by the policy engine */
    target_domain = requested_target;
    char *cmd = NULL;
    bool disposable = false;
    size_t resp_len;

    /*
     * If there was no service argument, pretend that an empty argument was
     * provided by appending "+" to the service name.
     */
    const char *const trailer = strchr(service_name, '+') ? "" : "+";

    /* Check if the target is dom0, which requires special handling. */
    bool target_is_dom0 = strcmp(target, "@adminvm") == 0 ||
                          strcmp(target, "dom0") == 0;
    if (target_is_dom0) {
        char *type;
        bool target_is_keyword = target_domain[0] == '@';
        if (target_is_keyword) {
            target_domain++;
            type = "keyword";
        } else {
            type = "name";
        }
        if (asprintf(&cmd, "QUBESRPC %s%s %s %s %s",
                     service_name,
                     trailer,
                     remote_domain_name,
                     type,
                     target_domain) <= 0)
            daemon__exit(126);
        register_exec_func(&do_exec);
        daemon__exit(run_qrexec_to_dom0(request_id,
                           remote_domain_id,
                           remote_domain_name,
                           cmd,
                           5 /* 5 second timeout */,
                           false /* return 0 not remote status code */));
    } else {
        char *buf;
        if (strncmp("@dispvm:", target, sizeof("@dispvm:") - 1) == 0) {
            disposable = true;
            buf = qubesd_call(target + 8, "admin.vm.CreateDisposable", "", &resp_len);
            if (!buf) // error already printed by qubesd_call
                daemon__exit(126);
            if (memcmp(buf, "0", 2) == 0) {
                /* we exec later so memory leaks do not matter */
                target = buf + 2;
            } else {
                if (memcmp(buf, "2", 2) == 0) {
                    LOG(ERROR, "qubesd could not create disposable VM: %s", buf + 2);
                } else {
                    LOG(ERROR, "invalid response to admin.vm.CreateDisposable");
                }
                daemon__exit(126);
            }
        }
        if (asprintf(&cmd, "%s:QUBESRPC %s%s %s",
                    user,
                    service_name,
                    trailer,
                    remote_domain_name) <= 0)
            daemon__exit(126);
        if (autostart) {
            buf = qubesd_call(target, "admin.vm.Start", "", &resp_len);
            if (!buf) // error already printed by qubesd_call
                daemon__exit(126);
            if (!((memcmp(buf, "0", 2) == 0) ||
                  (resp_len >= 24 && memcmp(buf, "2\0QubesVMNotHaltedError", 24) == 0))) {
                if (memcmp(buf, "2", 2) == 0) {
                    LOG(ERROR, "qubesd could not start VM %s: %s", target, buf + 2);
                } else {
                    LOG(ERROR, "invalid response to admin.vm.Start");
                }
                daemon__exit(126);
            }
            free(buf);
        }
        int s = connect_unix_socket(target);
        int data_domain;
        int data_port;
        int rc = 126;
        if (!negotiate_connection_params(s,
                remote_domain_id,
                MSG_EXEC_CMDLINE,
                cmd,
                compute_service_length(cmd),
                &data_domain,
                &data_port))
            daemon__exit(126);
        int wait_connection_end = -1;
        if (disposable) {
            wait_connection_end = s;
        } else {
            close(s);
        }

        s = connect_unix_socket_by_id((unsigned)remote_domain_id);
        if (send_service_connect(s, request_id->ident, data_domain, data_port))
            rc = 0;
        close(s);
        if (wait_connection_end != -1) {
            /* wait for EOF */
            struct pollfd fds[1] = {
                { .fd = wait_connection_end, .events = POLLIN | POLLHUP, .revents = 0 },
            };
            poll(fds, 1, -1);
            size_t l;
            qubesd_call(target, "admin.vm.Kill", "", &l);
        }
        daemon__exit(rc);
    }
}

static void handle_execute_service(
        const int remote_domain_id,
        const char *remote_domain_name,
        const char *target_domain,
        const char *service_name,
        const struct service_params *request_id)
{
    int policy_pending_slot;
    pid_t pid;

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
            if (atexit(null_exit))
                _exit(126);
            handle_execute_service_child(remote_domain_id, remote_domain_name,
                                         target_domain, service_name, request_id);
            abort();
        default:
            policy_pending[policy_pending_slot].pid = pid;
            policy_pending[policy_pending_slot].params = *request_id;
            policy_pending[policy_pending_slot].response_sent = RESPONSE_PENDING;
            return;
    }
}


static void handle_connection_terminated(void)
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

static bool validate_request_id(struct service_params *untrusted_params, const char *msg)
{
    for (size_t i = 0; i < sizeof(untrusted_params->ident); ++i) {
        switch (untrusted_params->ident[i]) {
        case '0' ... '9':
        case 'A' ... 'Z':
        case 'a' ... 'z':
        case '_':
        case '-':
        case '.':
        case ' ':
            continue;
        case '\0': {
            size_t terminator_offset = i;
            /* Ensure that nothing non-NUL follows the terminator */
            for (i++; i < sizeof(untrusted_params->ident); i++) {
                if (untrusted_params->ident[i]) {
                    LOG(ERROR, "Non-NUL byte %u at offset %zu follows NUL terminator at offset %zu in message %s",
                        untrusted_params->ident[i], i, terminator_offset, msg);
                    return false;
                }
            }
            return true;
        }
        default:
            LOG(ERROR, "Bad byte %u at offset %zu for message %s", untrusted_params->ident[i], i, msg);
            return false;
        }
    }
    LOG(ERROR, "No NUL terminator in message %s", msg);
    return false; // no NUL terminator
}

#define ENSURE_NULL_TERMINATED(x) x[sizeof(x)-1] = 0

static bool validate_service_name(char *untrusted_service_name)
{
    switch (untrusted_service_name[0]) {
    case '\0':
        LOG(ERROR, "Empty service name not allowed");
        return false;
    case '+':
        LOG(ERROR, "Service name must not start with '+'");
        return false;
    default:
        sanitize_name(untrusted_service_name, "+");
        return true;
    }
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static
#endif
void handle_message_from_agent(void)
{
    struct msg_header hdr, untrusted_hdr;

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
        case MSG_TRIGGER_SERVICE: {
            struct trigger_service_params untrusted_params, params;
            if (libvchan_recv(vchan, &untrusted_params, sizeof(untrusted_params))
                    != sizeof(untrusted_params))
                handle_vchan_error("recv params");

            /* sanitize start */
            ENSURE_NULL_TERMINATED(untrusted_params.service_name);
            ENSURE_NULL_TERMINATED(untrusted_params.target_domain);
            sanitize_name(untrusted_params.service_name, "+");
            sanitize_name(untrusted_params.target_domain, "@:");
            if (!validate_request_id(&untrusted_params.request_id, "MSG_TRIGGER_SERVICE")) {
                send_service_refused(vchan, &untrusted_params.request_id);
                return;
            }
            if (!validate_service_name(untrusted_params.service_name)) {
                send_service_refused(vchan, &untrusted_params.request_id);
                return;
            }
            params = untrusted_params;
            /* sanitize end */

            handle_execute_service(remote_domain_id, remote_domain_name,
                    params.target_domain,
                    params.service_name,
                    &params.request_id);
            return;
        }
        case MSG_TRIGGER_SERVICE3: {
            struct trigger_service_params3 untrusted_params3, params3;
            size_t service_name_len = hdr.len - sizeof(untrusted_params3), nul_offset;
            char *untrusted_service_name = malloc(service_name_len), *service_name = NULL;

            if (!untrusted_service_name)
                handle_vchan_error("malloc(service_name)");

            if (libvchan_recv(vchan, &untrusted_params3, sizeof(untrusted_params3))
                    != sizeof(untrusted_params3)) {
                free(untrusted_service_name);
                handle_vchan_error("recv params3");
            }
            if (libvchan_recv(vchan, untrusted_service_name, service_name_len)
                    != (int)service_name_len) {
                free(untrusted_service_name);
                handle_vchan_error("recv params3(service_name)");
            }
            service_name_len -= 1;

            /* sanitize start */
            ENSURE_NULL_TERMINATED(untrusted_params3.target_domain);
            sanitize_name(untrusted_params3.target_domain, "@:");
            if (!validate_request_id(&untrusted_params3.request_id, "MSG_TRIGGER_SERVICE3"))
                goto fail3;
            params3 = untrusted_params3;
            if (untrusted_service_name[service_name_len] != 0) {
                LOG(ERROR, "Service name not NUL-terminated");
                goto fail3;
            }
            nul_offset = strlen(untrusted_service_name);
            if (nul_offset != service_name_len) {
                LOG(ERROR, "Service name contains NUL byte at offset %zu", nul_offset);
                goto fail3;
            }
            if (!validate_service_name(untrusted_service_name))
                goto fail3;
            service_name = untrusted_service_name;
            untrusted_service_name = NULL;
            /* sanitize end */

            handle_execute_service(remote_domain_id, remote_domain_name,
                    params3.target_domain,
                    service_name,
                    &params3.request_id);
            free(service_name);
            return;
fail3:
            send_service_refused(vchan, &untrusted_params3.request_id);
            free(untrusted_service_name);
            return;
        }
        case MSG_CONNECTION_TERMINATED:
            handle_connection_terminated();
            return;
    }
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

static struct option longopts[] = {
    { "help", no_argument, 0, 'h' },
    { "quiet", no_argument, 0, 'q' },
    { "socket-dir", required_argument, 0, 'd' + 128 },
    { "policy-program", required_argument, 0, 'p' },
    { "direct", no_argument, 0, 'D' },
    { NULL, 0, 0, 0 },
};

static _Noreturn void usage(const char *argv0)
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
    bool opt_direct = false;

    {
        int null_fd = open("/dev/null", O_RDONLY|O_NOCTTY);
        if (null_fd < 0)
            err(1, "open(%s)", "/dev/null");
        if (null_fd > 0) {
            if (dup2(null_fd, 0) != 0)
                err(1, "dup2(%d, 0)", null_fd);
            if (null_fd > 2 && close(null_fd) != 0)
                err(1, "close(%d)", null_fd);
        }
    }

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
    init(remote_domain_id, opt_direct);

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
        int ret;

        if (child_exited)
            reap_children();

        size_t nfds = 0;
        struct pollfd fds[MAX_CLIENTS + 2];
        fds[nfds++] = (struct pollfd) { libvchan_fd_for_select(vchan), POLLIN | POLLHUP, 0 };
        if (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
            assert(max_client_fd < MAX_CLIENTS);
            // vchan not full, read from clients
            fds[nfds++] = (struct pollfd) { qrexec_daemon_unix_socket_fd, POLLIN | POLLHUP, 0 };
            for (i = 0; i <= max_client_fd; i++) {
                if (clients[i].state != CLIENT_INVALID)
                    fds[nfds++] = (struct pollfd) { i, POLLIN | POLLHUP, 0 };
            }
        }

        ret = ppoll_vchan(vchan, fds, nfds, &timeout, &selectmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            PERROR("ppoll");
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

        if (nfds > 1 && fds[1].revents)
            handle_new_client();

        while (libvchan_data_ready(vchan))
            handle_message_from_agent();

        for (size_t i = 2; i < nfds; i++) {
            if (fds[i].revents)
                handle_message_from_client(fds[i].fd);
        }
    }

    if (vchan)
        libvchan_close(vchan);

    return 0;
}

// vim:ts=4:sw=4:et:
