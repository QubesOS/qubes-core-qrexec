#
# The Qubes OS Project, https://www.qubes-os.org/
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
#

from pathlib import Path
import os
import shutil
import tempfile
import unittest

import pytest

from ..policy.admin_client import PolicyClient
from ..policy.admin import (
    PolicyAdminFileNotFoundException,
    PolicyAdminInvalidFileNameException,
    PolicyAdminProtocolException,
    PolicyAdminSyntaxException,
    PolicyAdminTokenException,
    compute_token,
)


class Client(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.client = PolicyClient()
        self.make_command_patch = unittest.mock.patch(
            "qrexec.client.make_command",
            side_effect=self.make_command_side_effect,
        )
        self.make_command_patch.start()
        with tempfile.TemporaryDirectory(delete=False) as dir_name:
            self.policy_dir = Path(dir_name)
            (Path(self.policy_dir) / "include").mkdir()
        with tempfile.NamedTemporaryFile(delete=False) as file_name:
            self.log_file = file_name.name

    def tearDown(self):
        super().tearDown()
        self.make_command_patch.stop()
        shutil.rmtree(self.policy_dir)
        os.remove(self.log_file)

    def make_command_side_effect(self, dest, rpcname, arg):
        # pylint: disable=unused-argument
        if arg:
            rpcname += "+" + arg
        return [
            "env",
            "QREXEC_POLICY_DIR=" + str(self.policy_dir),
            "QREXEC_POLICY_ADMIN_LOG=" + self.log_file,
            "QREXEC_SERVICE_FULL_NAME=" + rpcname,
            "QREXEC_REMOTE_DOMAIN=dom0",
            "python3",
            "-m",
            "qrexec.tools.qubes_policy_admin",
        ]

    def test_api_list(self):
        (self.policy_dir / "file1.policy").touch()
        (self.policy_dir / "file2.policy").touch()
        (self.policy_dir / "file3").touch()
        assert self.client.policy_list() == ["file1", "file2"]
        assert self.client.policy_list(is_include=True) == [""]
        (self.policy_dir / "include/admin-ro").touch()
        assert self.client.policy_list(is_include=True) == ["admin-ro"]
        assert (
            self.client.policy_list(is_include=True)
            == self.client.policy_include_list()
        )

    def test_api_get(self):
        with pytest.raises(
            PolicyAdminProtocolException, match="Invalid argument"
        ):
            self.client.policy_get(name="space in here")
        with pytest.raises(
            PolicyAdminInvalidFileNameException, match="Invalid policy file"
        ):
            self.client.policy_get(name=".hidden_evil_policy")
        with pytest.raises(PolicyAdminFileNotFoundException, match="Not found"):
            self.client.policy_get(name="hey")

        (self.policy_dir / "file1.policy").write_text("policy text")
        text, token = self.client.policy_get(name="file1")
        assert text == "policy text"
        assert token.startswith("sha256:")

        (self.policy_dir / "include/inc").write_text("include text")
        text, token = self.client.policy_get(name="inc", is_include=True)
        assert text == "include text"
        assert token.startswith("sha256:")
        old_text, _ = self.client.policy_include_get(name="inc")
        assert text == old_text

    def test_api_replace(self):
        self.client.policy_replace(name="file1", content="", token="any")
        assert (self.policy_dir / "file1.policy").read_text() == ""

        with pytest.raises(
            PolicyAdminSyntaxException, match="wrong number of fields"
        ):
            self.client.policy_replace(
                name="file1", content="policy text", token="any"
            )
        with pytest.raises(
            PolicyAdminSyntaxException, match="contains invalid characters"
        ):
            self.client.policy_replace(
                name="file1",
                content="service ** source dest allow",
                token="any",
            )
        assert (self.policy_dir / "file1.policy").read_text() == ""

        self.client.policy_replace(
            name="file1", content="rpc.Name * * * deny", token="any"
        )
        assert (
            self.policy_dir / "file1.policy"
        ).read_text() == "rpc.Name * * * deny"

        with pytest.raises(
            PolicyAdminProtocolException, match="Unrecognized token"
        ):
            self.client.policy_replace(
                name="file1", content="rpc.Name * * * deny", token="what"
            )

        with pytest.raises(
            PolicyAdminTokenException, match="File exists but token is 'new'"
        ):
            self.client.policy_replace(
                name="file1", content="rpc.Name * * * deny", token="new"
            )

        with pytest.raises(PolicyAdminTokenException, match="Token mismatch"):
            self.client.policy_replace(
                name="file1", content="", token="sha256:aaaa"
            )

        with pytest.raises(
            PolicyAdminTokenException, match="File doesn't exist"
        ):
            self.client.policy_replace(
                name="file2", content="", token="sha256:aaaa"
            )

        self.client.policy_replace(
            name="inc",
            content="rpc.Name * * * deny",
            token="any",
            is_include=True,
        )
        assert (
            self.policy_dir / "include/inc"
        ).read_text() == "rpc.Name * * * deny"

        self.client.policy_include_replace(
            name="inc", content="rpc.Name * * * allow", token="any"
        )
        assert (
            self.policy_dir / "include/inc"
        ).read_text() == "rpc.Name * * * allow"

        with pytest.raises(PolicyAdminSyntaxException, match="not a file"):
            self.client.policy_replace(
                name="file1",
                content="!include include/nonexistent",
                token="any",
            )

        self.client.policy_replace(
            name="file1", content="!include include/inc", token="any"
        )
        with pytest.raises(
            PolicyAdminSyntaxException, match="invalid number of params"
        ):
            self.client.policy_replace(
                name="file1",
                content="!include-service include/inc",
                token="any",
            )

    def test_api_remove(self):
        with pytest.raises(PolicyAdminFileNotFoundException, match="Not found"):
            self.client.policy_remove(name="file1")

        (self.policy_dir / "file1.policy").touch()
        (self.policy_dir / "include/inc").touch()

        self.client.policy_remove(name="file1", token="any")
        assert not (self.policy_dir / "file1").exists()

        self.client.policy_remove(name="inc", token="any", is_include=True)
        assert not (self.policy_dir / "include/inc").exists()

    def test_api_remove_check_token(self):
        file_path = self.policy_dir / "file1.policy"

        file_path.touch()
        self.client.policy_remove(name="file1", token=compute_token(b""))
        assert not file_path.exists()

        file_path.touch()
        with pytest.raises(PolicyAdminTokenException, match="Token mismatch"):
            self.client.policy_remove(name="file1", token="sha256:aaaa")

    def test_api_remove_validate(self):
        (self.policy_dir / "file1.policy").write_text("!include include/inc")
        (self.policy_dir / "include/inc").touch()

        with pytest.raises(
            PolicyAdminSyntaxException,
            match="including a file that will be removed",
        ):
            self.client.policy_remove(name="inc", token="any", is_include=True)

    def test_api_get_files(self):
        assert not self.client.policy_get_files("nonexistent")

        (self.policy_dir / "file1.policy").write_text(
            "test.service * @anyvm dom0 deny\n"
            "test.service * @anyvm @anyvm allow"
        )
        (self.policy_dir / "file2.policy").write_text(
            "other.service * dom0 dom0 allow\n"
            "third.service * @anyvm @anyvm deny"
        )

        assert self.client.policy_get_files(name="test.service") == ["file1"]
        assert self.client.policy_get_files(name="other.service") == ["file2"]

        with pytest.raises(
            PolicyAdminProtocolException, match="Service cannot be empty"
        ):
            self.client.policy_get_files(name="")

        with pytest.raises(
            PolicyAdminProtocolException, match="contains invalid characters"
        ):
            self.client.policy_get_files(name="service+param")
