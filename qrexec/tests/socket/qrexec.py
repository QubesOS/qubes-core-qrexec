# -*- encoding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2020  Paweł Marczewski  <pawel@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

import socket
import os
import struct
import time


# See libqrexec/qrexec.h
MSG_DATA_STDIN = 0x190
MSG_DATA_STDOUT = 0x191
MSG_DATA_STDERR = 0x192
MSG_DATA_EXIT_CODE = 0x193
MSG_EXEC_CMDLINE = 0x200
MSG_JUST_EXEC = 0x201
MSG_SERVICE_CONNECT = 0x202
MSG_SERVICE_REFUSED = 0x203
MSG_CONNECTION_TERMINATED = 0x211
MSG_TRIGGER_SERVICE3 = 0x212
MSG_HELLO = 0x300
QREXEC_PROTOCOL_VERSION = 3


class QrexecClient:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def sendall(self, data):
        self.conn.sendall(data)

    def recvall(self, data_len):
        data = b''
        while len(data) < data_len:
            res = self.conn.recv(data_len - len(data))
            if not res:
                return data
            data += res
        return data

    def close(self):
        self.conn.close()

    def send_message(self, message_type, data):
        header = struct.pack('<LL', message_type, len(data))
        self.sendall(header)
        self.sendall(data)

    def recv_message(self):
        header = self.conn.recv(8)
        message_type, data_len = struct.unpack('<LL', header)
        data = self.recvall(data_len)
        return message_type, data

    def recv_all_messages(self):
        messages = []
        while True:
            header = self.recvall(8)
            if len(header) < 8:
                break
            message_type, data_len = struct.unpack('<LL', header)
            data = self.recvall(data_len)
            assert len(data) == data_len, (len(data), data_len)
            messages.append((message_type, data))
        return messages

    def handshake(self):
        self.send_message(MSG_HELLO,
                          struct.pack('<L', QREXEC_PROTOCOL_VERSION))
        message_type, data = self.recv_message()
        assert message_type == MSG_HELLO
        ver, = struct.unpack('<L', data)
        assert ver == QREXEC_PROTOCOL_VERSION


class QrexecServer(QrexecClient):
    def __init__(self, server_conn):
        super().__init__(None)
        self.server_conn = server_conn

    def close(self):
        if self.server_conn:
            self.server_conn.close()
        if self.conn:
            self.conn.close()

    def accept(self):
        self.conn, _addr = self.server_conn.accept()
        self.server_conn.close()
        self.server_conn = None


def vchan_client(socket_dir, domain, remote_domain, port):
    vchan_socket_path = os.path.join(
        socket_dir, 'vchan.{}.{}.{}.sock'.format(
            domain, remote_domain, port))
    return socket_client(vchan_socket_path)


def socket_client(socket_path):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connect_when_ready(conn, socket_path)
    return QrexecClient(conn)


def vchan_server(socket_dir, domain, remote_domain, port):
    vchan_socket_path = os.path.join(
        socket_dir, 'vchan.{}.{}.{}.sock'.format(
            domain, remote_domain, port))
    return socket_server(vchan_socket_path)


def socket_server(socket_path):
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)
    return QrexecServer(server)


def connect_when_ready(conn, path):
    # Wait for the server to come up
    n_tries = 10
    delay = 0.05
    for _ in range(n_tries):
        try:
            conn.connect(path)
        except IOError:
            time.sleep(delay)
        else:
            return

    # Try for the last time (to propagate the exception)
    try:
        conn.connect(path)
    except IOError:
        conn.close()
        raise
