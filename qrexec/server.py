# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2020 Paweł Marczewski <pawel@invisiblethingslab.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <https://www.gnu.org/licenses/>.


'''
A client and server for socket-based QubesRPC (currently used for
qrexec-policy-agent).

The request (dom0 -> VM) is JSON-encoded, response is plain ASCII text.
'''

import os
import os.path
import asyncio
import subprocess
import json
import socket

from systemd.daemon import listen_fds

from . import QREXEC_CLIENT, RPC_PATH


async def client_connected(reader, writer, handler):
    try:
        data = await reader.read()
        data = data.decode('ascii')
        assert '\0' in data, data

        header, json_data = data.split('\0', 1)
        service, source_domain = header.split(' ')
        params = json.loads(json_data)

        response = await handler(params, service, source_domain)

        writer.write(response.encode('ascii'))
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


def start_server(handler, socket_path, socket_activated=False):
    _handler = lambda reader, writer: client_connected(reader, writer, handler)

    if socket_activated:
        fds = listen_fds()
        if fds:
            assert len(fds) == 1, 'too many listen_fds: {}'.format(listen_fds)
            sock = socket.socket(fileno=fds[0])
            return asyncio.start_unix_server(_handler, sock=sock)

    if os.path.exists(socket_path):
        os.unlink(socket_path)
    return asyncio.start_unix_server(_handler, path=socket_path)


def call_socket_service(
        remote_domain, service, source_domain, params,
        rpc_path=RPC_PATH):
    if remote_domain == 'dom0':
        return call_socket_service_local(
            service, source_domain, params, rpc_path)
    return call_socket_service_remote(
        remote_domain, service, source_domain, params)


async def call_socket_service_local(service, source_domain, params,
                                    rpc_path=RPC_PATH):
    path = os.path.join(rpc_path, service)
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write('{} {}\0'.format(service, source_domain).encode('ascii'))
    writer.write(json.dumps(params).encode('ascii'))
    writer.write_eof()
    await writer.drain()
    response = await reader.read()
    return response.decode('ascii')


async def call_socket_service_remote(remote_domain, service, source_domain,
                                     params):
    qrexec_opts = ['-d', remote_domain]
    cmd = 'DEFAULT:QUBESRPC {} {}'.format(service, source_domain)
    command = [QREXEC_CLIENT] + qrexec_opts + [cmd]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    stdin, _stderr = await process.communicate(
        json.dumps(params).encode('ascii'))
    return stdin.decode('ascii')
