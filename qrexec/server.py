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


async def run_server(service, handler, rpc_path=RPC_PATH):
    path = os.path.join(rpc_path, service)
    if os.path.exists(path):
        os.unlink(path)
    server = await asyncio.start_unix_server(
        lambda reader, writer: client_connected(reader, writer, handler), path)
    async with server:
        await server.serve_forever()


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
