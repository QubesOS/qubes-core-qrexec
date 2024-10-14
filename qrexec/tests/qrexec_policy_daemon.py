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
import pytest_asyncio
from unittest.mock import Mock, AsyncMock
import functools

import unittest
import unittest.mock

from ..tools import qrexec_policy_daemon

server_types = [b"Simple", b"GUI"]
import logging

log = logging.getLogger("policy")
log.setLevel(logging.INFO)

try:
    asyncio_fixture = pytest_asyncio.fixture
except AttributeError:
    asyncio_fixture = pytest.fixture


class TestPolicyDaemon:
    @pytest.fixture
    def mock_request(self, monkeypatch):
        mock_request = AsyncMock()
        mock_request.return_value = "result=deny"
        monkeypatch.setattr(
            "qrexec.tools.qrexec_policy_daemon.handle_request", mock_request
        )
        return mock_request

    @pytest.fixture
    def mock_system(self, monkeypatch):
        mock_system = unittest.mock.MagicMock(
            return_value={
                "domains": {
                    "a": {"tags": ["guivm-c", "created-by-dom0"]},
                    "b": {"tags": ["guivm-c", "created-by-dom0"]},
                    "c": {"tags": ["created-by-dom0"]},
                    "dom0": {"tags": []},
                },
            },
        )
        monkeypatch.setattr(
            "qrexec.tools.qrexec_policy_daemon.get_system_info", mock_system
        )
        return mock_system

    @asyncio_fixture
    async def async_server(self, tmp_path, request):
        server = await asyncio.start_unix_server(
            functools.partial(
                qrexec_policy_daemon.handle_client_connection, log, Mock()
            ),
            path=str(tmp_path / "socket.d"),
        )

        yield server

        server.close()

    @asyncio_fixture
    async def qrexec_server(self, tmp_path, request):
        mock_policy = Mock()
        eval_server = await asyncio.start_unix_server(
            functools.partial(
                qrexec_policy_daemon.handle_qrexec_connection,
                log=log,
                policy_cache=mock_policy,
                check_gui=False,
                service_name=b"policy.EvalSimple",
            ),
            path=str(tmp_path / "socket.Simple"),
        )

        gui_server = await asyncio.start_unix_server(
            functools.partial(
                qrexec_policy_daemon.handle_qrexec_connection,
                log=log,
                policy_cache=mock_policy,
                check_gui=True,
                service_name=b"policy.EvalGUI",
            ),
            path=str(tmp_path / "socket.GUI"),
        )

        yield {b"Simple": eval_server, b"GUI": gui_server}

        eval_server.close()
        gui_server.close()

    async def send_data(self, server, path, data, qrexec=b""):
        reader, writer = await asyncio.open_unix_connection(
            str(
                path
                / (
                    ("socket." + qrexec.decode("ascii", "strict"))
                    if qrexec
                    else "socket.d"
                )
            )
        )
        writer.write(data)

        await writer.drain()

        writer.write_eof()

        s = await reader.read()

        writer.close()

        server.close()

        await server.wait_closed()

        return s

    @pytest.mark.asyncio
    async def test_simple_request(self, mock_request, async_server, tmp_path):

        data = b"source=b\n" b"intended_target=c\n" b"service_and_arg=d\n"

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_called_once_with(
            source="b",
            intended_target="c",
            service_and_arg="d",
            log=unittest.mock.ANY,
            policy_cache=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    async def test_complex_request(self, mock_request, async_server, tmp_path):

        data = (
            b"source=b\n"
            b"intended_target=c\n"
            b"service_and_arg=d\n"
            b"assume_yes_for_ask=yes\n"
            b"just_evaluate=yes\n\n"
        )

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_called_once_with(
            source="b",
            intended_target="c",
            service_and_arg="d",
            log=unittest.mock.ANY,
            assume_yes_for_ask=True,
            just_evaluate=True,
            policy_cache=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    async def test_complex_request2(self, mock_request, async_server, tmp_path):

        data = (
            b"source=b\n"
            b"intended_target=c\n"
            b"service_and_arg=d\n"
            b"assume_yes_for_ask=no\n"
            b"just_evaluate=no\n\n"
        )

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_called_once_with(
            source="b",
            intended_target="c",
            service_and_arg="d",
            log=unittest.mock.ANY,
            assume_yes_for_ask=False,
            just_evaluate=False,
            policy_cache=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    async def test_too_short_request(
        self, mock_request, async_server, tmp_path
    ):

        data = b"domain_id=None\n\n"

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_duplicate_arg(self, mock_request, async_server, tmp_path):

        data = (
            b"source=b\n"
            b"source=b\n"
            b"intended_target=c\n"
            b"service_and_arg=d\n"
            b"assume_yes_for_ask=no\n"
            b"just_evaluate=no\n"
        )

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_wrong_arg(self, mock_request, async_server, tmp_path):

        data = (
            b"domain_id=a\n"
            b"source=b\n"
            b"intended_target=c\n"
            b"service_and_arg=d\n"
            b"assume_yes_for_ask=no\n"
            b"just_evaluate=no\n\n"
        )

        await self.send_data(async_server, tmp_path, data)

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_simple_qrexec_request_succeeds(
        self, mock_request, qrexec_server, tmp_path, mock_system, server_type
    ):
        mock_request.return_value = "result=allow"

        data = b"policy.Eval%s+d c keyword adminvm\0a\0b" % server_type

        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b"result=allow\n"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_simple_qrexec_request(
        self, mock_request, qrexec_server, tmp_path, mock_system, server_type
    ):

        data = b"policy.Eval%s+d c keyword adminvm\0a\0b" % server_type

        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b"result=deny\n"
        )

        mock_request.assert_called_once_with(
            source="a",
            intended_target="b",
            service_and_arg="d",
            assume_yes_for_ask=True,
            just_evaluate=True,
            log=log,
            policy_cache=unittest.mock.ANY,
            system_info=unittest.mock.ANY,
        )
        mock_request.reset_mock()

    @pytest.mark.asyncio
    async def test_not_guivm(
        self, mock_request, qrexec_server, tmp_path, mock_system
    ):
        data = b"policy.EvalGUI+d b keyword adminvm\0c\0a"
        assert (
            await self.send_data(qrexec_server[b"GUI"], tmp_path, data, b"GUI")
            == b""
        ), (
            "policy.EvalGUI requires the calling domain to provide GUI to "
            "both other domains"
        )
        mock_request.assert_not_called()
        data = b"policy.EvalSimple+d b keyword adminvm\0c\0a"
        assert (
            await self.send_data(
                qrexec_server[b"Simple"], tmp_path, data, b"Simple"
            )
            == b"result=deny\n"
        )
        mock_request.assert_called_once_with(
            source="c",
            intended_target="a",
            service_and_arg="d",
            log=log,
            assume_yes_for_ask=True,
            just_evaluate=True,
            policy_cache=unittest.mock.ANY,
            system_info=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    async def test_not_guivm_2(
        self, mock_request, qrexec_server, tmp_path, mock_system
    ):
        data = b"policy.EvalGUI+d c keyword adminvm\0c\0a"
        assert len(qrexec_server) == 2
        assert (
            await self.send_data(qrexec_server[b"GUI"], tmp_path, data, b"GUI")
            == b""
        ), (
            "policy.EvalGUI requires the calling domain to provide GUI to "
            "both other domains"
        )
        mock_request.assert_not_called()
        data = b"policy.EvalSimple+d c keyword adminvm\0c\0a"
        assert (
            await self.send_data(
                qrexec_server[b"Simple"], tmp_path, data, b"Simple"
            )
            == b"result=deny\n"
        )
        mock_request.assert_called_once_with(
            source="c",
            intended_target="a",
            service_and_arg="d",
            log=log,
            assume_yes_for_ask=True,
            just_evaluate=True,
            policy_cache=unittest.mock.ANY,
            system_info=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    async def test_not_guivm_3(
        self, mock_request, qrexec_server, tmp_path, mock_system
    ):
        data = b"policy.EvalGUI+d c keyword adminvm\0a\0c"
        assert len(qrexec_server) == 2
        assert (
            await self.send_data(qrexec_server[b"GUI"], tmp_path, data, b"GUI")
            == b""
        ), (
            "policy.EvalGUI requires the calling domain to provide GUI to "
            "both other domains"
        )
        mock_request.assert_not_called()
        data = b"policy.EvalSimple+d c keyword adminvm\0a\0c"
        assert (
            await self.send_data(
                qrexec_server[b"Simple"], tmp_path, data, b"Simple"
            )
            == b"result=deny\n"
        )
        mock_request.assert_called_once_with(
            source="a",
            intended_target="c",
            service_and_arg="d",
            log=log,
            assume_yes_for_ask=True,
            just_evaluate=True,
            policy_cache=unittest.mock.ANY,
            system_info=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_unfinished_request(
        self, mock_request, qrexec_server, tmp_path, mock_system, server_type
    ):

        data = b"unfinished"

        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b""
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_too_long_qrexec_request(
        self, mock_request, qrexec_server, tmp_path, mock_system, server_type
    ):
        data = b"policy.Eval%s+%s ignore ignore ignore\0a\0b" % (
            server_type,
            b"a" * 65536,
        )
        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b""
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_too_long_source_qube_name(
        self, mock_request, qrexec_server, tmp_path, mock_system, server_type
    ):
        data = b"policy.Eval%s+a b c d\0%s\0d" % (server_type, b"c" * 32)
        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b""
        )
        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_too_long_destination_qube_name(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):
        data = b"policy.Eval%s+a b c d\0d\0%s" % (server_type, b"c" * 32)
        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b""
        )
        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_no_nul_separator(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):
        data = b"policy.Eval%s+a b c d\0%s" % (server_type, b"c" * 31)
        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b""
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_empty_argument(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):

        data = b"policy.Eval%s+ b c d\0e\0f" % server_type
        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b""
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_no_argument(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):

        data = b"policy.Eval%s b c d\0e\0f" % server_type
        assert (
            await self.send_data(
                qrexec_server[server_type], tmp_path, data, server_type
            )
            == b""
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_qrexec_request_wrong_service_gui(
        self, mock_request, qrexec_server, tmp_path, mock_system
    ):

        data = b"policy.EvalSimple+d c keyword adminvm\0a\0b"
        assert (
            await self.send_data(
                qrexec_server[b"Simple"], tmp_path, data, b"Simple"
            )
            == b"result=deny\n"
        )
        assert (
            await self.send_data(qrexec_server[b"GUI"], tmp_path, data, b"GUI")
            == b""
        )
        mock_request.assert_called_once_with(
            source="a",
            intended_target="b",
            service_and_arg="d",
            log=log,
            assume_yes_for_ask=True,
            just_evaluate=True,
            policy_cache=unittest.mock.ANY,
            system_info=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    async def test_qrexec_request_wrong_service_simple(
        self, mock_request, qrexec_server, tmp_path, mock_system
    ):

        data = b"policy.EvalGUI+d c keyword adminvm\0a\0b"
        assert (
            await self.send_data(qrexec_server[b"GUI"], tmp_path, data, b"GUI")
            == b"result=deny\n"
        )
        assert (
            await self.send_data(
                qrexec_server[b"Simple"], tmp_path, data, b"Simple"
            )
            == b""
        )
        mock_request.assert_called_once_with(
            source="a",
            intended_target="b",
            service_and_arg="d",
            log=log,
            assume_yes_for_ask=True,
            just_evaluate=True,
            policy_cache=unittest.mock.ANY,
            system_info=unittest.mock.ANY,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_bad_source_name(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):
        data = b"policy.Eval%s+a b c d\0\n\0f" % server_type
        await self.send_data(
            qrexec_server[server_type], tmp_path, data, server_type
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_bad_destination_name(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):

        data = b"policy.Eval%s+a b c d\0e\0\n" % server_type
        await self.send_data(
            qrexec_server[server_type], tmp_path, data, server_type
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_two_nul_chars(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):

        data = b"policy.Eval%s+a b c d\0e\0\0" % server_type
        await self.send_data(
            qrexec_server[server_type], tmp_path, data, server_type
        )

        mock_request.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_type", server_types)
    async def test_qrexec_request_trailing_nul_char(
        self, mock_request, qrexec_server, tmp_path, server_type
    ):

        data = b"policy.Eval%s+a b c d\0e\0e\0" % server_type
        await self.send_data(
            qrexec_server[server_type], tmp_path, data, server_type
        )

        mock_request.assert_not_called()
