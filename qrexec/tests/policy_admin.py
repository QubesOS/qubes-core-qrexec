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
import tempfile

import pytest

from ..policy.admin import (
    PolicyAdmin,
    PolicyAdminException,
    PolicyAdminTokenException,
    compute_token,
)

# Disable warnings that conflict with Pytest's use of fixtures.
# pylint: disable=redefined-outer-name


@pytest.fixture
def policy_dir():
    with tempfile.TemporaryDirectory() as dir_name:
        policy_dir = Path(dir_name)
        (policy_dir / "include").mkdir()
        yield policy_dir


@pytest.fixture
def api(policy_dir):
    return PolicyAdmin(policy_dir)


def test_api_list(policy_dir, api):
    (policy_dir / "file1.policy").touch()
    (policy_dir / "file2.policy").touch()
    (policy_dir / "file3").touch()

    assert api.handle_request("policy.List", "", b"") == b"file1\nfile2\n"

    assert api.handle_request("policy.include.List", "", b"") == b""

    (policy_dir / "include/inc").touch()

    assert api.handle_request("policy.include.List", "", b"") == b"inc\n"


def test_api_get(policy_dir, api):
    (policy_dir / "file1.policy").write_text("policy text")

    data = api.handle_request("policy.Get", "file1", b"").decode()
    assert data.startswith("sha256:")
    assert data.endswith("\npolicy text")

    (policy_dir / "include/inc").write_text("include text")

    data = api.handle_request("policy.include.Get", "inc", b"").decode()
    assert data.startswith("sha256:")
    assert data.endswith("\ninclude text")

    with pytest.raises(PolicyAdminException, match="Not found"):
        api.handle_request("policy.Get", "nonexistent", b"")

    with pytest.raises(PolicyAdminException, match="Invalid policy file"):
        api.handle_request("policy.Get", ".hidden_evil_policy", b"")

    with pytest.raises(PolicyAdminException, match="Invalid policy file"):
        api.handle_request("policy.include.Get", "..", b"")

    with pytest.raises(PolicyAdminException, match="Invalid policy file"):
        api.handle_request("policy.include.Get", "", b"")

    with pytest.raises(PolicyAdminException, match="Invalid argument"):
        api.handle_request("policy.include.Get", "space in argument", b"")


def test_api_replace(policy_dir, api):
    api.handle_request("policy.Replace", "file1", b"any\n")
    assert (policy_dir / "file1.policy").read_text() == ""

    api.handle_request("policy.Replace", "file1", b"any\nrpc.Name * * * deny")
    assert (policy_dir / "file1.policy").read_text() == "rpc.Name * * * deny"

    api.handle_request(
        "policy.include.Replace", "inc", b"any\nrpc.Name * * * deny"
    )
    assert (policy_dir / "include/inc").read_text() == "rpc.Name * * * deny"

    api.handle_request("policy.Replace", "file1", b"any\n!include include/inc")


def test_api_replace_check_token(policy_dir, api):
    sample = b"rpc.Name * * * deny"

    api.handle_request("policy.Replace", "file1", b"new\n" + sample)
    assert (policy_dir / "file1.policy").read_bytes() == sample

    api.handle_request("policy.Replace", "file1", compute_token(sample) + b"\n")
    assert (policy_dir / "file1.policy").read_bytes() == b""

    with pytest.raises(PolicyAdminTokenException, match="File exists"):
        api.handle_request("policy.Replace", "file1", b"new\n")

    with pytest.raises(PolicyAdminTokenException, match="Token mismatch"):
        api.handle_request("policy.Replace", "file1", b"sha256:aaaa\n")

    with pytest.raises(PolicyAdminTokenException, match="File doesn't exist"):
        api.handle_request("policy.Replace", "file2", b"sha256:aaaa\n")


def test_api_replace_validate(api):
    with pytest.raises(PolicyAdminException, match="wrong number of fields"):
        api.handle_request("policy.Replace", "file1", b"any\nxxx")

    # Trying to include a nonexistent file
    with pytest.raises(PolicyAdminException, match="not a file"):
        api.handle_request(
            "policy.Replace", "file1", b"any\n!include include/inc"
        )

    # File that can be included, but not using !include-service
    api.handle_request(
        "policy.include.Replace", "inc", b"any\nrpc.Name * * * deny"
    )
    api.handle_request("policy.Replace", "file1", b"any\n!include include/inc")
    with pytest.raises(PolicyAdminException, match="invalid number of params"):
        api.handle_request(
            "policy.Replace", "file1", b"any\n!include-service include/inc"
        )


def test_api_remove(policy_dir, api):
    (policy_dir / "file1.policy").touch()
    (policy_dir / "include/inc").touch()

    api.handle_request("policy.Remove", "file1", b"any")
    assert not (policy_dir / "file1").exists()

    api.handle_request("policy.include.Remove", "inc", b"any")
    assert not (policy_dir / "include/inc").exists()


def test_api_remove_check_token(policy_dir, api):
    file_path = policy_dir / "file1.policy"

    file_path.touch()
    api.handle_request("policy.Remove", "file1", compute_token(b""))
    assert not file_path.exists()

    file_path.touch()
    with pytest.raises(PolicyAdminTokenException, match="Token mismatch"):
        api.handle_request("policy.Remove", "file1", b"sha256:aaaa\n")


def test_api_remove_validate(policy_dir, api):
    (policy_dir / "file1.policy").write_text("!include include/inc")
    (policy_dir / "include/inc").touch()

    with pytest.raises(
        PolicyAdminException, match="including a file that will be removed"
    ):
        api.handle_request("policy.include.Remove", "inc", b"any")


def test_api_get_files(policy_dir, api):
    (policy_dir / "file1.policy").write_text("test.service * $any dom0 deny\n"
                                             "test.service * $any $any allow")
    (policy_dir / "file2.policy").write_text("other.service * dom0 dom0 allow\n"
                                             "third.service * $any $any deny")

    assert api.handle_request(
        "policy.GetFiles", "test.service", b"") == b"file1\n"
    assert api.handle_request(
        "policy.GetFiles", "other.service", b"") == b"file2\n"

    # files from outside normal policy directory should be listed as
    # complete path
    with tempfile.TemporaryDirectory() as other_dir_name:
        (policy_dir / 'compat.policy').write_text('!compat-4.0')
        other_dir = Path(other_dir_name)

        from unittest import mock
        with mock.patch("qrexec.policy.parser_compat.POLICYPATH_OLD", other_dir):
            (other_dir / "third.service").write_text(
                "dom0 dom0 allow\n"
                "@anyvm @anyvm deny")

            assert api.handle_request(
                "policy.GetFiles", "third.service", b"") == \
                   f"{other_dir / 'third.service'}\nfile2\n".encode('utf-8')

    with pytest.raises(
        PolicyAdminException, match="Service cannot be empty"
    ):
        api.handle_request("policy.GetFiles", "", b"")

    with pytest.raises(
        PolicyAdminException, match="contains invalid characters"
    ):
        api.handle_request("policy.GetFiles", "service+param", b"")
