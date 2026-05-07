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


import argparse
import io
import os
import re
import shutil
import sys
import unittest

import pytest

from qrexec.tools.qubes_policy import main, run_method


class TestPolicyTool:

    def _call_api(
        self,
        args: list = [],
        expected_stdout: str = "",
        expected_stderr: str = "",
        stdin: str = "",
        exc: Exception = None,  # type: ignore[assignment]
    ):
        # pylint: disable=too-many-positional-arguments

        with unittest.mock.patch.object(sys, "stdin") as mock_stdin:  # type: ignore[attr-defined]
            mock_stdin.read.return_value = stdin
            if exc:
                with pytest.raises(exc):  # type: ignore[call-overload]
                    main(args)
            else:
                main(args)

        captured = self.capsys.readouterr()
        assert re.search(expected_stdout, captured.out, flags=re.MULTILINE)
        assert re.search(expected_stderr, captured.err, flags=re.MULTILINE)

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

        self.make_command_patch = unittest.mock.patch(
            "qrexec.client.make_command",
            side_effect=self.make_command_side_effect,
        )
        self.make_command_patch.start()

    def make_command_side_effect(self, dest, rpcname, arg):
        # pylint: disable=unused-argument
        if arg:
            rpcname += "+" + arg
        return [
            "env",
            "QREXEC_POLICY_DIR=" + str(self.policy_dir),
            "QREXEC_POLICY_ADMIN_LOG=" + str(self.log_file),
            "QREXEC_SERVICE_FULL_NAME=" + rpcname,
            "QREXEC_REMOTE_DOMAIN=dom0",
            "python3",
            "-m",
            "qrexec.tools.qubes_policy_admin",
        ]

    def test_tool_cli_specific_exception(self, setup_dirs):
        # pylint: disable=unused-argument
        self._call_api(
            args=["--get", "unexistent"],
            expected_stderr="^Not found: .*",
            exc=SystemExit,
        )

        self._call_api(
            args=["--list", "file"],
            expected_stderr=".*--list doesn't work with a file name.*",
            exc=SystemExit,
        )

        self._call_api(
            args=["--get", "fi*le"],
            expected_stderr=".*invalid character.*",
            exc=SystemExit,
        )

    def test_tool_cli_unhandled_exception(self, setup_dirs):
        # pylint: disable=unused-argument
        shutil.rmtree(self.policy_dir)
        self._call_api(
            stdin=b"",
            expected_stdout="",
            expected_stderr="^Command failed",
            exc=SystemExit,
        )

        with pytest.raises(AssertionError):
            run_method(
                method="inexistent", name="file1", is_include=False, client=None
            )

    def test_tool_cli_result(self, setup_dirs):
        # pylint: disable=unused-argument
        self._call_api(
            args=["--list"],
            expected_stdout="\n",
        )
        self._call_api(
            args=[],
            expected_stdout="\n",
        )

        (self.policy_dir / "file1.policy").touch()
        (self.policy_dir / "file2.policy").touch()
        (self.policy_dir / "file3").touch()

        self._call_api(
            args=["--list"],
            expected_stdout="file1\nfile2\n",
        )

        self._call_api(
            args=["--get", "file1"],
        )

        rule = "srv +arg src dst deny"
        escaped_rule = r"srv \+arg src dst deny\n"
        self._call_api(
            args=["--replace", "file1"],
            stdin=rule,
        )

        self._call_api(
            args=["--get", "file1"],
            expected_stdout=escaped_rule,
        )

        self._call_api(
            args=["--remove", "file1"],
        )

        (self.policy_include_dir / "inc").touch()
        self._call_api(
            args=["--get", "include/inc"],
            expected_stdout="\n",
        )
