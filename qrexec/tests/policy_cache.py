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

import os
import asyncio
import pytest
import unittest
import unittest.mock

from ..policy import utils


class TestPolicyCache:
    @pytest.fixture
    def mock_parser(self, monkeypatch):
        mock_parser = unittest.mock.Mock()
        monkeypatch.setattr(
            "qrexec.policy.utils.parser.FilePolicy", mock_parser
        )
        return mock_parser

    def test_00_policy_init(self, tmp_path, mock_parser):
        cache = utils.PolicyCache(tmp_path)
        mock_parser.assert_called_once_with(policy_path=tmp_path)

    @pytest.mark.asyncio
    async def test_10_file_created(self, tmp_path, mock_parser):
        cache = utils.PolicyCache(tmp_path)
        cache.initialize_watcher()

        assert not cache.outdated

        file = tmp_path / "test"
        file.write_text("test")

        await asyncio.sleep(1)

        assert cache.outdated

    @pytest.mark.asyncio
    async def test_11_file_changed(self, tmp_path, mock_parser):
        file = tmp_path / "test"
        file.write_text("test")

        cache = utils.PolicyCache(tmp_path)
        cache.initialize_watcher()

        assert not cache.outdated

        file.write_text("new_content")

        await asyncio.sleep(1)

        assert cache.outdated

    @pytest.mark.asyncio
    async def test_12_file_deleted(self, tmp_path, mock_parser):
        file = tmp_path / "test"
        file.write_text("test")

        cache = utils.PolicyCache(tmp_path)
        cache.initialize_watcher()

        assert not cache.outdated

        os.remove(file)

        await asyncio.sleep(1)

        assert cache.outdated

    @pytest.mark.asyncio
    async def test_13_no_change(self, tmp_path, mock_parser):
        cache = utils.PolicyCache(tmp_path)
        cache.initialize_watcher()

        assert not cache.outdated

        await asyncio.sleep(1)

        assert not cache.outdated

    @pytest.mark.asyncio
    async def test_14_policy_move(self, tmp_path, mock_parser):
        policy_path = tmp_path / "policy"
        policy_path.mkdir()
        cache = utils.PolicyCache(policy_path)
        cache.initialize_watcher()

        mock_parser.assert_called_once_with(policy_path=policy_path)

        assert not cache.outdated

        file = tmp_path / "test"
        file.write_text("test")

        await asyncio.sleep(1)

        assert not cache.outdated

        # move in
        file_moved = file.rename(policy_path / "test")

        await asyncio.sleep(1)

        assert cache.outdated

        cache.get_policy()

        assert not cache.outdated

        # now move out
        file_moved.rename(file)

        await asyncio.sleep(1)

        assert cache.outdated

        cache.get_policy()

        call = unittest.mock.call(policy_path=policy_path)
        assert mock_parser.mock_calls == [call, call, call]

    @pytest.mark.asyncio
    async def test_20_policy_updates(self, tmp_path, mock_parser):
        cache = utils.PolicyCache(tmp_path)
        cache.initialize_watcher()

        mock_parser.assert_called_once_with(policy_path=tmp_path)

        assert not cache.outdated

        file = tmp_path / "test"
        file.write_text("test")

        await asyncio.sleep(1)

        assert cache.outdated

        cache.get_policy()

        call = unittest.mock.call(policy_path=tmp_path)

        assert mock_parser.mock_calls == [call, call]
