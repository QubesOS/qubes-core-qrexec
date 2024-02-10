#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <err.h>

#include "qrexec.h"
#include "libqrexec-utils.h"
#include "qrexec-daemon-common.h"

const char *socket_dir = QREXEC_DAEMON_SOCKET_DIR;

/* ask the daemon to allocate vchan port */
void negotiate_connection_params(int s, int other_domid, unsigned type,
        void *cmdline_param, int cmdline_size,
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
        exit(1);
    }
    /* the daemon will respond with the same message with connect_port filled
     * and empty cmdline */
    if (!read_all(s, &hdr, sizeof(hdr))) {
        PERROR("read daemon");
        exit(1);
    }
    assert(hdr.type == type);
    if (hdr.len != sizeof(params)) {
        LOG(ERROR, "Invalid response for 0x%x", type);
        exit(1);
    }
    if (!read_all(s, &params, sizeof(params))) {
        PERROR("read daemon");
        exit(1);
    }
    *data_port = params.connect_port;
    *data_domain = params.connect_domain;
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

int connect_unix_socket_by_id(unsigned int domid)
{
    char id_str[11];
    int snprintf_res = snprintf(id_str, sizeof(id_str), "%u", domid);
    if (snprintf_res < 0 || snprintf_res >= (int)sizeof(id_str))
        err(1, "snprintf()");
    return connect_unix_socket(id_str);
}

int connect_unix_socket(const char *domname)
{
    int s, len, res;
    struct sockaddr_un remote;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        err(1, "socket");

    remote.sun_family = AF_UNIX;
    res = snprintf(remote.sun_path, sizeof remote.sun_path,
                   "%s/qrexec.%s", socket_dir, domname);
    if (res < 0)
        err(1, "snprintf");
    if (res >= (int)sizeof(remote.sun_path))
        errx(1, "%s/qrexec.%s is too long for AF_UNIX socket path",
             socket_dir, domname);
    len = (size_t)res + 1 + offsetof(struct sockaddr_un, sun_path);
    if (connect(s, (struct sockaddr *) &remote, len) == -1)
        err(1, "connect %s", remote.sun_path);
    if (handle_daemon_handshake(s) < 0)
        exit(1);
    return s;
}

void send_service_connect(int s, const char *conn_ident,
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
        exit(1);
    }
}
