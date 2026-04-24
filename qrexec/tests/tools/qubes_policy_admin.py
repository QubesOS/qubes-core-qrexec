#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2026 Ben Grande <ben@invisiblethingslab.com>
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

import io
import os
import re
import shutil
import unittest

import pytest

from qrexec.tools.qubes_policy_admin import main


class TestPolicyAdminTool:

    def _call_api(
        self,
        stdin: bytes = b"",
        expected_stdout: str = "",
        expected_stderr: str = "",
        exc: Exception = None,  # type: ignore[assignment]
    ):
        service = "policy.List"
        stdin_patch = io.TextIOBase()
        payload = stdin
        stdin_patch.buffer = io.BytesIO(payload)  # type: ignore[attr-defined]
        os.environ.update(
            {
                "QREXEC_SERVICE_FULL_NAME": service,
                "QREXEC_REMOTE_DOMAIN": "dummy",
                "QREXEC_POLICY_DIR": str(self.policy_dir),
                "QREXEC_POLICY_ADMIN_LOG": str(self.log_file),
            }
        )
        with unittest.mock.patch("sys.stdin", stdin_patch):
            if exc:
                with pytest.raises(exc):  # type: ignore[call-overload]
                    main()
            else:
                main()

        captured = self.capsys.readouterr()
        assert re.match(expected_stdout, captured.out)
        assert re.match(expected_stderr, captured.err)

    @pytest.fixture
    def setup_dirs(self, capsys, tmp_path):
        # pylint: disable=attribute-defined-outside-init
        policy_dir = tmp_path / "policy.d"
        policy_include_dir = policy_dir / "include"
        policy_include_dir.mkdir(parents=True)
        log_file = tmp_path / "policy-admin.log"
        log_file.touch()
        # Pytest is finicky about having an __init__ method.
        self.policy_dir = policy_dir
        self.policy_include_dir = policy_include_dir
        self.log_file = log_file
        self.capsys = capsys

    def test_tool_admin_specific_exception(self, setup_dirs):
        # pylint: disable=unused-argument
        self._call_api(
            stdin=b"test\n",
            expected_stdout="",
            expected_stderr="PolicyAdminProtocolException Unexpected payload",
            exc=SystemExit,
        )

    def test_tool_admin_unhandled_exception(self, setup_dirs):
        # pylint: disable=unused-argument
        shutil.rmtree(self.policy_dir)
        self._call_api(
            stdin=b"",
            expected_stdout="",
            expected_stderr="^Internal error.*",
            exc=SystemExit,
        )

    def test_tool_admin_result(self, setup_dirs):
        # pylint: disable=unused-argument
        self._call_api(
            stdin=b"",
            expected_stdout="",
            expected_stderr="",
        )

        (self.policy_dir / "file1.policy").touch()
        (self.policy_dir / "file2.policy").touch()
        (self.policy_dir / "file3").touch()

        self._call_api(
            stdin=b"",
            expected_stdout="^file1\nfile2\n$",
            expected_stderr="",
        )
