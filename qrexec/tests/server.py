import json
import tempfile
import shutil
import os
import asyncio
import socket
from unittest import mock

import pytest

from ..server import start_server, call_socket_service_local

# Disable warnings that conflict with Pytest's use of fixtures.
# pylint: disable=redefined-outer-name, unused-argument


async def handler(params, method, source_domain):
    return json.dumps({
        'params': params,
        'method': method,
        'source_domain': source_domain
    })


@pytest.fixture
def temp_dir():
    temp_dir = tempfile.mkdtemp()
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)


@pytest.fixture(params=['normal', 'socket_activated'])
async def server(temp_dir, request):
    socket_path = os.path.join(temp_dir, 'Service')
    if request.param == 'socket_activated':
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(socket_path)
        fd = sock.detach()
        with mock.patch('qrexec.server.listen_fds') as mock_listen_fds:
            mock_listen_fds.return_value = [fd]
            server = await start_server(handler, socket_path,
                                        socket_activated=True)
    else:
        server = await start_server(handler, socket_path)
    try:
        await server.start_serving()
        yield socket_path
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_server(server):
    for i in range(2):
        reader, writer = await asyncio.open_unix_connection(server)
        writer.write(b'Service source\0' + json.dumps({'request': i}).encode())
        writer.write_eof()
        await writer.drain()
        response = await reader.read()
        assert json.loads(response) == {
            'params': {'request': i},
            'method': 'Service',
            'source_domain': 'source',
        }


@pytest.mark.asyncio
async def test_call_socket_service_local(temp_dir, server):
    for i in range(2):
        response = await call_socket_service_local(
            'Service', 'source',
            {'request': i}, rpc_path=temp_dir)
        assert json.loads(response) == {
            'params': {'request': i},
            'method': 'Service',
            'source_domain': 'source',
        }
