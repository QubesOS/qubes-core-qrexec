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

The request (intended to be dom0 -> VM) is JSON-encoded, response is plain
ASCII text.

Currently disregards the target specification part of the request.
'''

import os
import os.path
import asyncio
import json
import socket

from systemd.daemon import listen_fds

from . import RPC_PATH
from .client import call_async

class SocketService:
    def __init__(self, socket_path, socket_activated=False):
        self._socket_path = socket_path
        self._socket_activated = socket_activated

    async def run(self):
        server = await self.start()
        async with server:
            await server.serve_forever()

    async def start(self):
        if self._socket_activated:
            fds = listen_fds()
            if fds:
                assert len(fds) == 1, 'too many listen_fds: {}'.format(
                    listen_fds)
                sock = socket.socket(fileno=fds[0])
                return await asyncio.start_unix_server(self._client_connected,
                                                       sock=sock)

        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)
        return await asyncio.start_unix_server(self._client_connected,
                                               path=self._socket_path)

    async def _client_connected(self, reader, writer):
        try:
            data = await reader.read()
            data = data.decode('ascii')
            assert '\0' in data, data
            header, json_data = data.split('\0', 1)

            # Note that we process only the first two parts (service and
            # source_domain) and disregard the second two parts (target
            # specification) that appear when we're running in dom0.
            header_parts = header.split(' ')
            assert len(header_parts) >= 2, header
            service = header_parts[0]
            source_domain = header_parts[1]

            params = json.loads(json_data)

            response = await self.handle_request(params, service, source_domain)

            writer.write(response.encode('ascii'))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_request(self, params, service, source_domain):
        raise NotImplementedError()


def call_socket_service(
        remote_domain, service, source_domain, params,
        rpc_path=RPC_PATH):
    '''
    Call a socket service, either over qrexec or locally.

    The request is JSON-encoded, response is plain ASCII text.
    '''

    if remote_domain == source_domain:
        return call_socket_service_local(
            service, source_domain, params, rpc_path)
    return call_socket_service_remote(
        remote_domain, service, params)


async def call_socket_service_local(service, source_domain, params,
                                    rpc_path=RPC_PATH):
    if source_domain == 'dom0':
        header = '{} dom0 name dom0\0'.format(service).encode('ascii')
    else:
        header = '{} {}\0'.format(service, source_domain).encode('ascii')

    path = os.path.join(rpc_path, service)
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write(header)
    writer.write(json.dumps(params).encode('ascii'))
    writer.write_eof()
    await writer.drain()
    response = await reader.read()
    return response.decode('ascii')


async def call_socket_service_remote(remote_domain, service, params):
    input_data = json.dumps(params)
    output_data = await call_async(remote_domain, service, input=input_data)
    return output_data
