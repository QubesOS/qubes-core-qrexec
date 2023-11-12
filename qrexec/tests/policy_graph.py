#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2023 Marek Marczykowski-Górecki
#                           <marmarek@invisiblethingslab.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library; if not, see <https://www.gnu.org/licenses/>.
import os
import tempfile

import pytest
from unittest import mock

from ..tools.qrexec_policy_graph import main

@pytest.fixture(autouse=True)
def system_info():
    system_info = {
        "domains": {
            "dom0": {
                "icon": "black",
                "template_for_dispvms": False,
                "guivm": None,
                "type": "AdminVM",
                "tags": [],
            },
            "work": {
                "icon": "red",
                "template_for_dispvms": False,
                "guivm": None,
                "type": "AppVM",
                "tags": [],
            },
            "personal": {
                "icon": "red",
                "template_for_dispvms": False,
                "guivm": None,
                "type": "AppVM",
                "tags": [],
            },
            "sys-usb": {
                "icon": "red",
                "template_for_dispvms": False,
                "guivm": None,
                "type": "AppVM",
                "tags": [],
            },
            "sys-usb-2": {
                "icon": "red",
                "template_for_dispvms": False,
                "guivm": None,
                "type": "AppVM",
                "tags": [],
            },
            "dvm_template": {
                "icon": "red",
                "template_for_dispvms": True,
                "guivm": None,
                "type": "AppVM",
                "tags": [],
            },
        },
    }
    with mock.patch("qrexec.utils.get_system_info") as mock_system_info:
        mock_system_info.return_value = system_info
        yield system_info

def test_simple_graph():
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "10-test.policy"), "w") as policy:
            policy.write("test.Service * work personal allow\n")
            policy.write("test.Service * sys-usb personal ask\n")
        with tempfile.NamedTemporaryFile() as output:
            main(["--policy-dir", policy_dir, "--output", output.name])
            content = output.read().decode()
            expected = """digraph g {
  "work" -> "personal" [label="test.Service" color=red];
}
"""
            assert content == expected


def test_simple_ask():
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "10-test.policy"), "w") as policy:
            policy.write("test.Service * work personal ask\n")
        with tempfile.NamedTemporaryFile() as output:
            main(["--policy-dir", policy_dir,
                  "--output", output.name,
                  "--include-ask"])
            content = output.read().decode()
            expected = """digraph g {
  "work" -> "personal" [label="test.Service" color=orange];
}
"""
            assert content == expected


def test_simple_service():
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "10-test.policy"), "w") as policy:
            policy.write("test.Service * work personal allow\n")
            policy.write("test.Service2 * sys-usb personal allow\n")
            policy.write("test.Service * sys-usb personal allow\n")
        with tempfile.NamedTemporaryFile() as output:
            main(["--policy-dir", policy_dir,
                  "--output", output.name,
                  "--service", "test.Service"])
            content = output.read().decode()
            expected = """digraph g {
  "work" -> "personal" [label="test.Service" color=red];
  "sys-usb" -> "personal" [label="test.Service" color=red];
}
"""
            assert content == expected


def test_simple_service_arg():
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "10-test.policy"), "w") as policy:
            policy.write("test.Service * work personal allow\n")
            policy.write("test.Service2 * sys-usb personal allow\n")
            policy.write("test.Service +arg sys-usb personal allow\n")
        with tempfile.NamedTemporaryFile() as output:
            main(["--policy-dir", policy_dir,
                  "--output", output.name,
                  "--service", "test.Service+arg"])
            content = output.read().decode()
            expected = """digraph g {
  "work" -> "personal" [label="test.Service" color=red];
  "sys-usb" -> "personal" [label="test.Service" color=red];
}
"""
            assert content == expected

def test_simple_service_arg_single():
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "10-test.policy"), "w") as policy:
            policy.write("test.Service * work personal allow\n")
            policy.write("test.Service2 * sys-usb personal allow\n")
        with tempfile.NamedTemporaryFile() as output:
            main(["--policy-dir", policy_dir,
                  "--output", output.name,
                  "--service", "test.Service+arg"])
            content = output.read().decode()
            expected = """digraph g {
  "work" -> "personal" [label="test.Service" color=red];
}
"""
            assert content == expected


def test_simple_service_no_wildcard():
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "10-test.policy"), "w") as policy:
            policy.write("test.Service +arg work personal allow\n")
            policy.write("test.Service2 +arg sys-usb personal allow\n")
        with tempfile.NamedTemporaryFile() as output:
            main(["--policy-dir", policy_dir,
                  "--output", output.name,
                  "--service", "test.Service"])
            content = output.read().decode()
            expected = """digraph g {
  "work" -> "personal" [label="test.Service" color=red];
}
"""
            assert content == expected


def test_simple_redirect():
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "10-test.policy"), "w") as policy:
            policy.write("test.Service * work personal allow target=dom0\n")
        with tempfile.NamedTemporaryFile() as output:
            main(["--policy-dir", policy_dir,
                  "--output", output.name,
                  "--target", "dom0"])
            content = output.read().decode()
            expected = """digraph g {
  "work" -> "@adminvm" [label="test.Service" color=red];
}
"""
            assert content == expected

