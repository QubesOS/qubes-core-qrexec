#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2019 Marta Marczykowska-Górecka
#                               <marmarta@invisiblethingslab.com>
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
#

import asyncio
from contextlib import suppress

import pytest
import asynctest
from unittest.mock import Mock
import functools

import unittest
import unittest.mock

from ..tools import qrexec_policy_daemon


class TestPolicyDaemon:
    @pytest.fixture
    def mock_request(self, monkeypatch):
        mock_request = asynctest.CoroutineMock()
        monkeypatch.setattr('qrexec.tools.qrexec_policy_daemon.handle_request',
                            mock_request)
        return mock_request

    @pytest.fixture
    async def async_server(self, tmp_path, request):
        log = unittest.mock.Mock()

        server = await asyncio.start_unix_server(
            functools.partial(qrexec_policy_daemon.handle_client_connection,
                              log, Mock()),
            path=str(tmp_path / "socket.d"))

        yield server

        server.close()

    async def send_data(self, server, path, data):
        reader, writer = await asyncio.open_unix_connection(
            str(path / "socket.d"))
        writer.write(data)
        await writer.drain()

        await reader.read()

        writer.close()

        server.close()

        await server.wait_closed()


    @pytest.mark.asyncio
    async def test_simple_request(self, mock_request, async_server, tmp_path):

        data = b'domain_id=a\n' \
               b'source=b\n' \
               b'intended_target=c\n' \
               b'service_and_arg=d\n' \
               b'process_ident=1 9\n\n'

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_called_once_with(
            domain_id='a', source='b', intended_target='c',
            service_and_arg='d', process_ident='1 9', log=unittest.mock.ANY,
            policy_cache=unittest.mock.ANY,
            allow_resolution_type=qrexec_policy_daemon.DaemonAllowResolution,
            origin_writer=unittest.mock.ANY)

    @pytest.mark.asyncio
    async def test_complex_request(self, mock_request, async_server, tmp_path):

        data = b'domain_id=a\n' \
               b'source=b\n' \
               b'intended_target=c\n' \
               b'service_and_arg=d\n' \
               b'process_ident=9\n' \
               b'assume_yes_for_ask=yes\n' \
               b'just_evaluate=yes\n\n'

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_called_once_with(
            domain_id='a', source='b', intended_target='c',
            service_and_arg='d', process_ident='9', log=unittest.mock.ANY,
            assume_yes_for_ask=True, just_evaluate=True,
            policy_cache=unittest.mock.ANY,
            allow_resolution_type=qrexec_policy_daemon.DaemonAllowResolution,
            origin_writer=unittest.mock.ANY)

    @pytest.mark.asyncio
    async def test_complex_request2(self, mock_request, async_server, tmp_path):

        data = b'domain_id=a\n' \
               b'source=b\n' \
               b'intended_target=c\n' \
               b'service_and_arg=d\n' \
               b'process_ident=9\n' \
               b'assume_yes_for_ask=no\n' \
               b'just_evaluate=no\n\n'

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_called_once_with(
            domain_id='a', source='b', intended_target='c',
            service_and_arg='d', process_ident='9', log=unittest.mock.ANY,
            assume_yes_for_ask=False, just_evaluate=False,
            policy_cache=unittest.mock.ANY,
            allow_resolution_type=qrexec_policy_daemon.DaemonAllowResolution,
            origin_writer=unittest.mock.ANY)

    @pytest.mark.asyncio
    async def test_unfinished_request(
            self, mock_request, async_server, tmp_path):

        data = b'unfinished'

        task = self.send_data(async_server, tmp_path, data)

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(task, timeout=2)

        for task in asyncio.all_tasks():
            task.cancel()

        with suppress(asyncio.CancelledError):
            await asyncio.sleep(1)

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_too_short_request(
            self, mock_request, async_server, tmp_path):

        data = b'domain_id=None\n\n'

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_duplicate_arg(self, mock_request, async_server, tmp_path):

        data = b'domain_id=a\n' \
               b'source=b\n' \
               b'intended_target=c\n' \
               b'service_and_arg=d\n' \
               b'process_ident=9\n' \
               b'assume_yes_for_ask=no\n' \
               b'just_evaluate=no\n' \
               b'domain_id=a\n\n'

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_wrong_arg(self, mock_request, async_server, tmp_path):

        data = b'tremendous_domain_id=a\n' \
               b'source=b\n' \
               b'intended_target=c\n' \
               b'service_and_arg=d\n' \
               b'process_ident=9\n' \
               b'assume_yes_for_ask=no\n' \
               b'just_evaluate=no\n\n'

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_not_called()
