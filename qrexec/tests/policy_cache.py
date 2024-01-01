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
import pathlib

from ..policy import utils


class TestPolicyCache:
    @pytest.fixture
    def tmp_paths(self, tmp_path: pathlib.Path) -> list[pathlib.Path]:
        path1 = tmp_path / "path1"
        path2 = tmp_path / "path2"
        path1.mkdir()
        path2.mkdir()
        return [path1, path2]

    @pytest.fixture
    def mock_parser(self, monkeypatch):
        mock_parser = unittest.mock.Mock()
        monkeypatch.setattr(
            "qrexec.policy.utils.parser.FilePolicy", mock_parser
        )
        return mock_parser

    def test_00_policy_init(self, tmp_path, mock_parser):
        cache = utils.PolicyCache([tmp_path])
        mock_parser.assert_called_once_with(policy_path=[tmp_path])

    @pytest.mark.asyncio
    async def test_10_file_created(self, tmp_paths, mock_parser):
        for i in tmp_paths:
            cache = utils.PolicyCache(tmp_paths)
            cache.initialize_watcher()

            assert not cache.outdated

            (i / "file").write_text("test")

            await asyncio.sleep(1)

            assert cache.outdated

    @pytest.mark.asyncio
    async def test_11_file_changed(self, tmp_paths, mock_parser):
        for i in tmp_paths:
            file = i / "test"
            file.write_text("test")

            cache = utils.PolicyCache(tmp_paths)
            cache.initialize_watcher()

            assert not cache.outdated

            file.write_text("new_content")

            await asyncio.sleep(1)

            assert cache.outdated

    @pytest.mark.asyncio
    async def test_12_file_deleted(self, tmp_paths, mock_parser):
        for i in tmp_paths:
            file = i / "test"
            file.write_text("test")

            cache = utils.PolicyCache(tmp_paths)
            cache.initialize_watcher()

            assert not cache.outdated

            os.remove(file)

            await asyncio.sleep(1)

            assert cache.outdated

    @pytest.mark.asyncio
    async def test_13_no_change(self, tmp_paths, mock_parser):
        cache = utils.PolicyCache(tmp_paths)
        cache.initialize_watcher()

        assert not cache.outdated

        await asyncio.sleep(1)

        assert not cache.outdated

    @pytest.mark.asyncio
    async def test_20_policy_updates(self, tmp_paths, mock_parser):
        count = 0
        call = unittest.mock.call(policy_path=tmp_paths)

        for i in tmp_paths:
            count += 2
            cache = utils.PolicyCache(tmp_paths)
            cache.initialize_watcher()

            assert mock_parser.mock_calls == [call] * (count - 1)

            assert not cache.outdated

            file = i / "test"
            file.write_text("test")

            await asyncio.sleep(1)

            assert cache.outdated

            cache.get_policy()

            assert mock_parser.mock_calls == [call] * count
