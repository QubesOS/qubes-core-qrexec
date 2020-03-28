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

#ifndef _QREXEC_H
#define _QREXEC_H

/* For information on qrexec, see:
 * - https://www.qubes-os.org/doc/qrexec/
 * - https://www.qubes-os.org/doc/qrexec-internals/
*/

#include <stdint.h>

#define QREXEC_PROTOCOL_VERSION 3
#define MAX_FDS 256
/* protocol version 2 */
#define MAX_DATA_CHUNK_V2 4096
/* protocol version 3+ */
#define MAX_DATA_CHUNK_V3 65536

/* large, but arbitrary; make it fit in vchan buffer (64k), together with
 * message header */
#define MAX_SERVICE_NAME_LEN 65000

#define RPC_REQUEST_COMMAND "QUBESRPC"
#define RPC_REQUEST_COMMAND_LEN (sizeof(RPC_REQUEST_COMMAND)-1)
#define NOGUI_CMD_PREFIX "nogui:"
#define NOGUI_CMD_PREFIX_LEN (sizeof(NOGUI_CMD_PREFIX)-1)
#define VCHAN_BASE_PORT 512
#define MAX_QREXEC_CMD_LEN 65535UL

/* protocol version */
enum {
    /* legacy protocol, without version negotiation support
     * Qubes < R3.0
     */
    QREXEC_PROTOCOL_V1 = 1,

    /* Changes:
     *  - separate data and control channels
     *  - handshake with protocol version
     * Qubes R3.0 - R4.0
     */
    QREXEC_PROTOCOL_V2 = 2,

    /* Changes:
     *  - MAX_DATA_CHUNK increased to 64k
     *  - MSG_TRIGGER_SERVICE3
     * Qubes >= R4.1
     */
    QREXEC_PROTOCOL_V3 = 3,
};

/* Messages sent over control vchan between daemon(dom0) and agent(vm).
 * The same are used between client(dom0) and daemon(dom0).
 */
enum {
    /* daemon->agent messages */

    /* start process in VM and pass its stdin/out/err to dom0
     * struct exec_params passed as data */
    MSG_EXEC_CMDLINE = 0x200,

    /* start process in VM discarding its stdin/out/err (connect to /dev/null)
    * struct exec_params passed as data */
    MSG_JUST_EXEC,

    /* connect to existing process in VM to receive its stdin/out/err
     * struct service_params passed as cmdline field in exec_params */
    MSG_SERVICE_CONNECT,

    /* refuse to start a service (denied by policy, invalid parameters etc)
     * struct service_params passed as data to identify which service call was
     * refused */
    MSG_SERVICE_REFUSED,

    /* agent->daemon messages */
    /* call Qubes RPC service (protocol 2)
     * struct trigger_service_params passed as data */
    MSG_TRIGGER_SERVICE = 0x210,


    /* connection was terminated, struct exec_params passed as data (with empty
     * cmdline field) informs about released vchan port */
    MSG_CONNECTION_TERMINATED,

    /* agent->daemon messages */
    /* call Qubes RPC service (protocol 3+)
     * struct trigger_service_params3 passed as data */
    MSG_TRIGGER_SERVICE3,

    /* common messages */
    /* initialize connection, struct peer_info passed as data
     * should be sent as the first message (server first, then client) */
    MSG_HELLO = 0x300,
};

/* uniform for all peers, data type depends on message type */
struct msg_header {
    uint32_t type;           /* message type */
    uint32_t len;            /* data length */
};

/* variable size */
struct exec_params {
    uint32_t connect_domain; /* target domain name */
    uint32_t connect_port;   /* target vchan port for i/o exchange */
    char cmdline[];          /* command line to execute, null terminated, size = msg_header.len - sizeof(struct exec_params) */
};

struct service_params {
    char ident[32];          /* null terminated ASCII string */
};

struct trigger_service_params {
    char service_name[64];            /* null terminated ASCII string */
    char target_domain[32];           /* null terminated ASCII string */
    struct service_params request_id; /* service request id */
};

struct trigger_service_params3 {
    char target_domain[64];           /* null terminated ASCII string */
    struct service_params request_id; /* service request id */
    // char service_name[0];          /* null terminated ASCII string, size = msg_header.len - sizeof(struct trigger_service_params3) */
};

struct peer_info {
    uint32_t version; /* qrexec protocol version */
};

/* data vchan client<->agent, separate for each VM process */
enum {
    /* stdin dom0->VM */
    MSG_DATA_STDIN = 0x190,
    /* stdout VM->dom0 */
    MSG_DATA_STDOUT,
    /* stderr VM->dom0 */
    MSG_DATA_STDERR,
    /* VM process exit code VM->dom0 (uint32_t) */
    MSG_DATA_EXIT_CODE,
};

// linux-specific stuff below

#define QREXEC_AGENT_TRIGGER_PATH "/var/run/qubes/qrexec-agent"
#define QREXEC_AGENT_FDPASS_PATH "/var/run/qubes/qrexec-agent-fdpass"
#define MEMINFO_WRITER_PIDFILE "/var/run/meminfo-writer.pid"
#define QUBES_RPC_MULTIPLEXER_PATH "/usr/lib/qubes/qubes-rpc-multiplexer"
#define QREXEC_DAEMON_SOCKET_DIR "/var/run/qubes"
#define QREXEC_POLICY_PROGRAM "/usr/bin/qrexec-policy-exec"
#define QREXEC_SERVICE_PATH "/usr/local/etc/qubes-rpc:/etc/qubes-rpc"

// directory for services configuration (for example 'wait-for-session' flag)
#define QUBES_RPC_CONFIG_PATH "/etc/qubes/rpc-config"
// support only very small configuration files,
#define MAX_CONFIG_SIZE 4096

#endif /* _QREXEC_H */
