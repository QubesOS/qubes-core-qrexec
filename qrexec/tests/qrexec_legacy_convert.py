# -*- encoding: utf8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2023 Marta Marczykowska-Górecka
#                               <marmarta@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.
import pathlib
from typing import Tuple
from unittest import mock
import pytest
from pathlib import Path
from types import MappingProxyType as Proxy
from ..tools import qrexec_legacy_convert


@pytest.fixture(autouse=True)
def system_info():
    system_info = {
        "dom0": {
            "icon": "black",
            "template_for_dispvms": False,
            "guivm": None,
            "type": "AdminVM",
            "tags": [],
            "uuid": "00000000-0000-0000-0000-000000000000",
        },
        "work": {
            "icon": "red",
            "template_for_dispvms": False,
            "guivm": None,
            "type": "AppVM",
            "tags": [],
            "uuid": "8079de03-ab79-424c-8fb6-d8adcfda19d1",
        },
        "personal": {
            "icon": "red",
            "template_for_dispvms": False,
            "guivm": None,
            "type": "AppVM",
            "tags": [],
            "uuid": "bf7cdc8a-1dc5-4fcc-b01f-bd648ff8d903",
        },
        "sys-usb": {
            "icon": "red",
            "template_for_dispvms": False,
            "guivm": None,
            "type": "AppVM",
            "tags": [],
            "uuid": "46fd27ac-46e3-44d7-918e-986f095900f9",
        },
        "sys-usb-2": {
            "icon": "red",
            "template_for_dispvms": False,
            "guivm": None,
            "type": "AppVM",
            "tags": [],
            "uuid": "b65fceec-2d84-4665-99cb-50c2e7d91dc6",
        },
        "dvm_template": {
            "icon": "red",
            "template_for_dispvms": True,
            "guivm": None,
            "type": "AppVM",
            "tags": [],
            "uuid": "b41c5829-3ea9-475e-b5e6-b404ea409f29",
        },
    }

    for i, j in list(system_info.items()):
        assert not i.startswith("uuid:")
        j["name"] = i
        j["tags"] = tuple(j["tags"])
        system_info["uuid:" + j["uuid"]] = system_info[i] = Proxy(j)
    for i in system_info.values():
        assert not i["name"].startswith("uuid:")
        assert "uuid" in i
    system_info = Proxy({"domains": system_info})

    with mock.patch("qrexec.utils.get_system_info") as mock_system_info:
        mock_system_info.return_value = system_info
        yield system_info


@pytest.fixture
def new_policy_dir(tmp_path: Path):
    policy_dir = tmp_path / "new_policy"
    policy_dir.mkdir()
    (policy_dir / "35-compat.policy").write_text("!compat-4.0\n")
    return policy_dir


@pytest.fixture
def old_policy_dir(tmp_path: Path):
    policy_dir = tmp_path / "old_policy"
    policy_dir.mkdir()
    return policy_dir


@pytest.fixture()
def mock_policy_dirs(new_policy_dir, old_policy_dir):
    with mock.patch(
        "qrexec.tools.qrexec_legacy_convert.POLICYPATH", new_policy_dir
    ), mock.patch(
        "qrexec.tools.qrexec_legacy_convert.POLICYPATH_OLD", old_policy_dir
    ), mock.patch(
        "qrexec.tools.qrexec_policy_graph.POLICYPATH", new_policy_dir
    ), mock.patch(
        "qrexec.tools.qrexec_policy_graph.POLICYPATH", new_policy_dir
    ), mock.patch(
        "qrexec.policy.parser.POLICYPATH", new_policy_dir
    ), mock.patch(
        "qrexec.policy.parser_compat.POLICYPATH_OLD", old_policy_dir
    ):
        yield new_policy_dir, old_policy_dir


def test_simplest_convert(mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]):

    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.Filecopy").write_text(
        """
dom0 @anyvm ask
work @anyvm ask
personal @anyvm deny"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.Filecopy").exists()

    result = new_policy_dir / "50-config-filecopy.policy"
    assert result.exists()
    assert (
        result.read_text()
        == qrexec_legacy_convert.TOOL_DISCLAIMER
        + """qubes.Filecopy\t*\tdom0\t@anyvm\task
qubes.Filecopy\t*\twork\t@anyvm\task
qubes.Filecopy\t*\tpersonal\t@anyvm\tdeny
"""
    )
    assert not (old_policy_dir / "qubes.Filecopy").exists()
    assert (old_policy_dir / "qubes.Filecopy.rpmsave").exists()


def test_multiple_files(mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]):
    # multiple files + some rules should be ignored
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.Filecopy").write_text(
        """
work @anyvm deny
@anyvm @anyvm allow"""
    )

    (old_policy_dir / "qubes.ClipboardPaste").write_text(
        """
work @anyvm ask
@anyvm @anyvm deny"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.Filecopy").exists()
    assert not (old_policy_dir / "qubes.ClipboardPaste").exists()

    filecopy_result = new_policy_dir / "50-config-filecopy.policy"
    assert filecopy_result.exists()
    assert (
        filecopy_result.read_text()
        == qrexec_legacy_convert.TOOL_DISCLAIMER
        + """qubes.Filecopy\t*\twork\t@anyvm\tdeny
qubes.Filecopy\t*\t@anyvm\t@anyvm\tallow
"""
    )

    paste_result = new_policy_dir / "50-config-clipboard.policy"
    assert paste_result.exists()
    assert (
        paste_result.read_text()
        == qrexec_legacy_convert.TOOL_DISCLAIMER
        + """qubes.ClipboardPaste\t*\twork\t@anyvm\task
"""
    )


def test_complex_rules(mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]):
    # rules that are too complex for the configtool
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.Filecopy").write_text(
        """
work @anyvm ask default_target=personal
@anyvm @anyvm allow"""
    )

    (old_policy_dir / "qubes.ClipboardPaste").write_text(
        """
work @anyvm allow target=personal"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.Filecopy").exists()
    assert not (old_policy_dir / "qubes.ClipboardPaste").exists()

    filecopy_result = new_policy_dir / "50-config-filecopy.policy"
    assert filecopy_result.exists()
    assert (
        filecopy_result.read_text()
        == qrexec_legacy_convert.TOOL_DISCLAIMER
        + """qubes.Filecopy\t*\t@anyvm\t@anyvm\tallow
"""
    )

    paste_result = new_policy_dir / "50-config-clipboard.policy"
    assert not paste_result.exists()

    misc_result = new_policy_dir / "30-user.policy"
    assert misc_result.exists()
    # order here does not matter
    assert sorted(misc_result.read_text().split("\n")) == sorted(
        (
            qrexec_legacy_convert.DISCLAIMER
            + """qubes.ClipboardPaste\t*\twork\t@anyvm\tallow target=personal
qubes.Filecopy\t*\twork\t@anyvm\task default_target=personal
"""
        ).split("\n")
    )


def test_input_rules_simple(
    mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]
):
    # rules that are too complex for the configtool
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.InputKeyboard").write_text(
        """
sys-usb dom0 ask"""
    )
    (old_policy_dir / "qubes.InputMouse").write_text(
        """
sys-usb dom0 allow"""
    )
    (old_policy_dir / "qubes.InputTablet").write_text(
        """
sys-usb dom0 deny"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.InputKeyboard").exists()
    assert not (old_policy_dir / "qubes.InputMouse").exists()
    assert not (old_policy_dir / "qubes.InputTablet").exists()

    input_result = new_policy_dir / "50-config-input.policy"
    assert input_result.exists()
    # order does not matter
    assert set(input_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.TOOL_DISCLAIMER
            + """qubes.InputKeyboard\t*\tsys-usb\tdom0\task
qubes.InputMouse\t*\tsys-usb\tdom0\tallow
qubes.InputTablet\t*\tsys-usb\tdom0\tdeny
"""
        ).split("\n")
    )

    misc_result = new_policy_dir / "30-user.policy"
    assert not misc_result.exists()


def test_input_multiple_rules(
    mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]
):
    # rules that are too complex for the configtool
    new_policy_dir, old_policy_dir = mock_policy_dirs

    # the deny @anyvm should be move to 30-user file
    (old_policy_dir / "qubes.InputKeyboard").write_text(
        """
sys-usb dom0 ask default_target=dom0
sys-usb @anyvm deny
"""
    )

    # the "work" rule should be moved to 30-user file
    (old_policy_dir / "qubes.InputMouse").write_text(
        """
sys-usb dom0 allow
sys-usb work allow"""
    )
    (old_policy_dir / "qubes.InputTablet").write_text(
        """
sys-usb dom0 deny"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.InputKeyboard").exists()
    assert not (old_policy_dir / "qubes.InputMouse").exists()
    assert not (old_policy_dir / "qubes.InputTablet").exists()

    input_result = new_policy_dir / "50-config-input.policy"
    assert input_result.exists()
    # order does not matter
    assert set(input_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.TOOL_DISCLAIMER
            + """qubes.InputKeyboard\t*\tsys-usb\tdom0\task default_target=dom0
qubes.InputMouse\t*\tsys-usb\tdom0\tallow
qubes.InputTablet\t*\tsys-usb\tdom0\tdeny
"""
        ).split("\n")
    )

    misc_result = new_policy_dir / "30-user.policy"
    assert misc_result.exists()
    assert set(misc_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.DISCLAIMER
            + """qubes.InputMouse\t*\tsys-usb\twork\tallow
qubes.InputKeyboard\t*\tsys-usb\t@anyvm\tdeny
"""
        ).split("\n")
    )


def test_input_multiple_sys_usbs(
    mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]
):
    # rules that are too complex for the configtool
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.InputKeyboard").write_text(
        """
sys-usb dom0 ask
sys-usb-2 dom0 deny
"""
    )
    # the sys-usb-2 @anyvm rule should go to 30-user
    (old_policy_dir / "qubes.InputMouse").write_text(
        """
sys-usb @adminvm allow
sys-usb-2 @anyvm deny
sys-usb-2 @adminvm allow
"""
    )
    # first rule goes to 50-config
    (old_policy_dir / "qubes.InputTablet").write_text(
        """
sys-usb dom0 ask
sys-usb dom0 deny"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.InputKeyboard").exists()
    assert not (old_policy_dir / "qubes.InputMouse").exists()
    assert not (old_policy_dir / "qubes.InputTablet").exists()

    input_result = new_policy_dir / "50-config-input.policy"
    assert input_result.exists()
    # order does not matter, only non-default rules get here
    assert set(input_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.TOOL_DISCLAIMER
            + """qubes.InputKeyboard\t*\tsys-usb\tdom0\task
qubes.InputKeyboard\t*\tsys-usb-2\tdom0\tdeny
qubes.InputMouse\t*\tsys-usb\t@adminvm\tallow
qubes.InputMouse\t*\tsys-usb-2\t@adminvm\tallow
qubes.InputTablet\t*\tsys-usb\tdom0\task
"""
        ).split("\n")
    )

    misc_result = new_policy_dir / "30-user.policy"
    assert misc_result.exists()
    assert set(misc_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.DISCLAIMER
            + """qubes.InputMouse\t*\tsys-usb-2\t@anyvm\tdeny
"""
        ).split("\n")
    )


def test_paste_rules(mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]):
    # allow-rules are not supported
    # rules with target / default target are not supported
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.ClipboardPaste").write_text(
        """
personal @anyvm allow
work personal ask default_target=personal
sys-usb work deny
@type:TemplateVM work deny
@anyvm @anyvm deny
"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.ClipboardPaste").exists()

    clipboard_result = new_policy_dir / "50-config-clipboard.policy"
    assert clipboard_result.exists()
    assert set(clipboard_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.TOOL_DISCLAIMER
            + """qubes.ClipboardPaste\t*\tsys-usb\twork\tdeny
qubes.ClipboardPaste\t*\t@type:TemplateVM\twork\tdeny
"""
        ).split("\n")
    )

    misc_result = new_policy_dir / "30-user.policy"
    assert misc_result.exists()
    assert set(misc_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.DISCLAIMER
            + """qubes.ClipboardPaste\t*\tpersonal\t@anyvm\tallow
qubes.ClipboardPaste\t*\twork\tpersonal\task default_target=personal"""
        ).split("\n")
    )


def test_openinvm_rules(mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]):
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.OpenInVM").write_text(
        """
personal @dispvm allow target=@dispvm:dvm_template
work @dispvm ask default_target=@dispvm:dvm_template
work personal deny
"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.OpenInVM").exists()

    result = new_policy_dir / "50-config-openinvm.policy"
    assert result.exists()
    assert set(result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.TOOL_DISCLAIMER
            + """qubes.OpenInVM\t*\tpersonal\t@dispvm\tallow target=@dispvm:dvm_template
qubes.OpenInVM\t*\twork\t@dispvm\task default_target=@dispvm:dvm_template
"""
        ).split("\n")
    )

    misc_result = new_policy_dir / "30-user.policy"
    assert misc_result.exists()
    assert set(misc_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.DISCLAIMER
            + """qubes.OpenInVM\t*\twork\tpersonal\tdeny
"""
        ).split("\n")
    )


def test_u2f_rules(mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]):
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "u2f.Authenticate+123").write_text(
        """
work sys-usb allow
"""
    )

    (old_policy_dir / "u2f.Authenticate").write_text(
        """
personal sys-usb ask
sys-usb-2 @anyvm deny
"""
    )

    (old_policy_dir / "u2f.Register").write_text(
        """
work sys-usb allow
personal sys-usb deny
sys-usb-2 sys-usb deny
"""
    )

    (old_policy_dir / "policy.RegisterArgument+u2f.Authenticate").write_text(
        """
work sys-usb allow
"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.u2f.Authenticate+123").exists()
    assert not (old_policy_dir / "qubes.u2f.Authenticate").exists()
    assert not (old_policy_dir / "u2f.Register").exists()
    assert not (
        old_policy_dir / "policy.RegisterArgument+u2f.Authenticate"
    ).exists()

    result = new_policy_dir / "50-config-u2f.policy"
    assert result.exists()
    assert set(result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.TOOL_DISCLAIMER
            + """u2f.Authenticate\t*\tpersonal\tsys-usb\task
u2f.Register\t*\twork\tsys-usb\tallow
u2f.Register\t*\tpersonal\tsys-usb\tdeny
u2f.Register\t*\tsys-usb-2\tsys-usb\tdeny
policy.RegisterArgument\t+u2f.Authenticate\twork\tsys-usb\tallow
"""
        ).split("\n")
    )

    misc_result = new_policy_dir / "30-user.policy"
    assert misc_result.exists()
    assert set(misc_result.read_text().split("\n")) == set(
        (
            qrexec_legacy_convert.DISCLAIMER
            + """u2f.Authenticate\t+123\twork\tsys-usb\tallow
u2f.Authenticate\t*\tsys-usb-2\t@anyvm\tdeny
"""
        ).split("\n")
    )


def test_merge_files(mock_policy_dirs: Tuple[pathlib.Path, pathlib.Path]):
    new_policy_dir, old_policy_dir = mock_policy_dirs

    (old_policy_dir / "qubes.Filecopy").write_text(
        """
work @anyvm deny
personal work allow
@anyvm @anyvm ask
"""
    )

    (new_policy_dir / "50-config-filecopy.policy").write_text(
        qrexec_legacy_convert.TOOL_DISCLAIMER
        + """
qubes.Filecopy * @anyvm @anyvm ask
"""
    )

    qrexec_legacy_convert.main([])

    assert not (old_policy_dir / "qubes.Filecopy").exists()
    assert not (new_policy_dir / "30-user.policy").exists()

    # order does matter here
    filecopy_result = new_policy_dir / "50-config-filecopy.policy"
    assert filecopy_result.exists()
    assert (
        filecopy_result.read_text()
        == qrexec_legacy_convert.TOOL_DISCLAIMER
        + """qubes.Filecopy\t*\twork\t@anyvm\tdeny
qubes.Filecopy\t*\tpersonal\twork\tallow
qubes.Filecopy * @anyvm @anyvm ask
"""
    )
