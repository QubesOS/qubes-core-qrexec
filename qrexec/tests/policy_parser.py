# -*- encoding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
# Copyright (C) 2018-2019  Wojtek Porczyk <woju@invisiblethingslab.com>
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

import functools
import socket
import subprocess
import unittest.mock
import asyncio
from copy import deepcopy
from pathlib import Path, PurePosixPath

import pytest
from types import MappingProxyType

from qrexec.utils import FullSystemInfo

from .. import QREXEC_CLIENT, QUBESD_INTERNAL_SOCK
from .. import exc, utils
from ..policy import parser, parser_compat


_SYSTEM_INFO = {
    "domains": {
        "dom0": {
            "tags": ["dom0-tag"],
            "type": "AdminVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "00000000-0000-0000-0000-000000000000",
        },
        "test-vm1": {
            "tags": ["tag1", "tag2"],
            "type": "AppVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "c9024a97-9b15-46cc-8341-38d75d5d421b",
        },
        "test-vm2": {
            "tags": ["tag2"],
            "type": "AppVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "b3eb69d0-f9d9-4c3c-ad5c-454500303ea4",
        },
        "test-vm3": {
            "tags": ["tag3"],
            "type": "AppVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": True,
            "power_state": "Halted",
            "uuid": "fa6d56e8-a89d-4106-aa62-22e172a43c8b",
        },
        "test-vm4": {
            "tags": [],
            "type": "AppVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": True,
            "power_state": "Halted",
            "uuid": "91e4fe8d-083b-4ddf-ad7b-fb4ebac537b9",
        },
        "default-dvm": {
            "tags": [],
            "type": "AppVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": True,
            "power_state": "Halted",
            "uuid": "f3e538bd-4427-4697-bed7-45ef3270df21",
        },
        "default-mgmt-dvm": {
            "internal": True,
            "tags": [],
            "type": "AppVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": True,
            "power_state": "Halted",
            "uuid": "f3e538bd-4427-4697-bed7-45ef3270df22",
        },
        "internal-vm": {
            "internal": True,
            "tags": [],
            "type": "AppVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": False,
            "power_state": "Halted",
            "uuid": "f3e538bd-4427-4697-bed7-45ef3270df23",
        },
        "test-invalid-dvm": {
            "tags": ["tag1", "tag2"],
            "type": "AppVM",
            "default_dispvm": "test-vm1",
            "template_for_dispvms": False,
            "power_state": "Halted",
            "uuid": "c4fa3586-a6b6-4dc4-bdda-c9e7375a12b5",
        },
        "test-no-dvm": {
            "tags": ["tag1", "tag2"],
            "type": "AppVM",
            "default_dispvm": None,
            "template_for_dispvms": False,
            "power_state": "Halted",
            "uuid": "53a450b9-a454-4416-8adb-46812257ad29",
        },
        "test-template": {
            "tags": ["tag1", "tag2"],
            "type": "TemplateVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": False,
            "power_state": "Halted",
            "uuid": "a9fe2b04-9fd5-4e95-be20-162433d64de0",
        },
        "test-standalone": {
            "tags": ["tag1", "tag2"],
            "type": "StandaloneVM",
            "default_dispvm": "default-dvm",
            "template_for_dispvms": False,
            "power_state": "Halted",
            "uuid": "6d7a02b5-532b-467f-b9fb-6596bae03c33",
        },
        "test-remotevm1": {
            "tags": ["relayvm-test-relayvm1"],
            "relayvm": "test-relayvm1",
            "transport_rpc": "qubesair.SSHProxy",
            "type": "RemoteVM",
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "3d225b39-88e9-4696-8978-b27c1360e041",
        },
        "test-relayvm1": {
            "tags": [],
            "type": "AppVM",
            "default_dispvm": None,
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "355304b8-bd5e-4699-9a2b-b6864fc26f6b",
        },
        # qubes on a second (remote) Qubes OS
        "test2-remotevm1": {
            "tags": ["relayvm-test2-relayvm1"],
            "type": "RemoteVM",
            "relayvm": "test2-relayvm1",
            "default_dispvm": None,
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "c7825251-1bb2-4070-aec9-3a8dd13befbf",
        },
        "test2-remotevm2": {
            "tags": ["relayvm-test2-relayvm2"],
            "type": "RemoteVM",
            "relayvm": "test2-relayvm2",
            "transport_rpc": "qubesair.SSHProxy",
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "6cd84a95-4336-445f-b125-6ecca1a40353",
        },
        "test2-vm1": {
            "tags": [],
            "type": "AppVM",
            "default_dispvm": None,
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "c798d6db-360f-473a-b902-1cc58ffd3ab0",
        },
        "test2-relayvm1": {
            "tags": [],
            "type": "AppVM",
            "default_dispvm": None,
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "41435947-21f8-41d9-9079-26df31f03d97",
        },
        "test2-relayvm2": {
            "tags": [],
            "type": "AppVM",
            "default_dispvm": None,
            "template_for_dispvms": False,
            "power_state": "Running",
            "uuid": "044767bb-081e-4260-b7be-35e77c36d510",
        },
    },
}


def patch_system_info(orig_system_info) -> FullSystemInfo:
    """
    We *really* do not want any code to modify SYSTEM_INFO,
    so replace all of its contents with versions that do not
    allow mutation.  Lists are replaced with tuples.

    This also adds keys for uuid:UUID and adds "name"
    fields to all dictionaries that need it.
    """
    patched_system_info = {}
    system_info = deepcopy(orig_system_info["domains"])
    for i, j in list(system_info.items()):
        assert not i.startswith("uuid:")
        j["name"] = i
        j["tags"] = tuple(j["tags"])
        system_info["uuid:" + j["uuid"]] = system_info[i] = MappingProxyType(j)
    patched_system_info["domains"] = MappingProxyType(system_info)
    for i in system_info.values():
        assert not i["name"].startswith("uuid:")
    return MappingProxyType(patched_system_info)  # type: ignore


# async mock
class AsyncMock(unittest.mock.MagicMock):
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)


class ParserTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.system_info = patch_system_info(_SYSTEM_INFO)

        # a generic request helper
        self.gen_req = functools.partial(
            parser.Request,
            "test.Service",
            "+argument",
            system_info=self.system_info,
        )


class TC_00_VMToken(ParserTestCase):
    def test_010_Source(self):
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("")
        parser.Source("test-vm1")
        parser.Source("@adminvm")
        parser.Source("dom0")
        parser.Source("@anyvm")
        parser.Source("*")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@default")
        parser.Source("uuid:d8a249f1-b02b-4944-a9e5-437def2fbe2c")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@uuid:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@uuid:d8a249f1-b02b-4944-a9e5-437def2fbe2c")
        parser.Source("@type:AppVM")
        parser.Source("@tag:tag1")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@dispvm")
        parser.Source("@dispvm:default-dvm")
        parser.Source("@dispvm:@tag:tag3")

        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@invalid")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@dispvm:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@dispvm:@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Source("@type:")

    def test_020_Target(self):
        parser.Target("test-vm1")
        parser.Target("@adminvm")
        parser.Target("dom0")
        parser.Target("@anyvm")
        parser.Target("*")
        parser.Target("@default")
        parser.Target("@type:AppVM")
        parser.Target("@tag:tag1")
        parser.Target("@dispvm")
        parser.Target("@dispvm:default-dvm")
        parser.Target("@dispvm:@tag:tag3")
        parser.Target("uuid:d8a249f1-b02b-4944-a9e5-437def2fbe2c")

        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target("")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target("@invalid")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target("@dispvm:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target("@dispvm:@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target("@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Target("@type:")

    def test_021_Target_expand(self):
        self.assertEqual(
            list(
                parser.Target("test-vm1").expand(system_info=self.system_info)
            ),
            ["test-vm1"],
        )
        self.assertEqual(
            list(
                parser.Target("@adminvm").expand(system_info=self.system_info)
            ),
            ["@adminvm"],
        )
        self.assertEqual(
            list(parser.Target("dom0").expand(system_info=self.system_info)),
            ["dom0"],
        )
        self.assertEqual(
            list(
                parser.Target(
                    "uuid:00000000-0000-0000-0000-000000000000"
                ).expand(system_info=self.system_info)
            ),
            ["dom0"],
        )
        self.assertEqual(
            list(
                parser.Target(
                    "uuid:b3eb69d0-f9d9-4c3c-ad5c-454500303ea4"
                ).expand(system_info=self.system_info)
            ),
            ["test-vm2"],
        )
        self.assertEqual(
            sorted(
                set(
                    parser.Target("@anyvm").expand(system_info=self.system_info)
                )
            ),
            [
                "@dispvm",
                "@dispvm:default-dvm",
                "@dispvm:default-mgmt-dvm",
                "@dispvm:test-vm3",
                "@dispvm:test-vm4",
                "default-dvm",
                "default-mgmt-dvm",
                "internal-vm",
                "test-invalid-dvm",
                "test-no-dvm",
                "test-relayvm1",
                "test-remotevm1",
                "test-standalone",
                "test-template",
                "test-vm1",
                "test-vm2",
                "test-vm3",
                "test-vm4",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-remotevm1",
                "test2-remotevm2",
                "test2-vm1",
            ],
        )
        self.maxDiff = None
        self.assertEqual(
            sorted(
                set(parser.Target("*").expand(system_info=self.system_info))
            ),
            [
                "@dispvm",
                "@dispvm:default-dvm",
                "@dispvm:default-mgmt-dvm",
                "@dispvm:test-vm3",
                "@dispvm:test-vm4",
                "default-dvm",
                "default-mgmt-dvm",
                "dom0",
                "internal-vm",
                "test-invalid-dvm",
                "test-no-dvm",
                "test-relayvm1",
                "test-remotevm1",
                "test-standalone",
                "test-template",
                "test-vm1",
                "test-vm2",
                "test-vm3",
                "test-vm4",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-remotevm1",
                "test2-remotevm2",
                "test2-vm1",
            ],
        )
        self.assertCountEqual(
            parser.Target("@default").expand(system_info=self.system_info), []
        )
        self.assertCountEqual(
            parser.Target("@type:AppVM").expand(system_info=self.system_info),
            [
                "default-dvm",
                "default-mgmt-dvm",
                "internal-vm",
                "test-invalid-dvm",
                "test-no-dvm",
                "test-relayvm1",
                "test-vm1",
                "test-vm2",
                "test-vm3",
                "test-vm4",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-vm1",
            ],
        )
        self.assertCountEqual(
            parser.Target("@type:TemplateVM").expand(
                system_info=self.system_info
            ),
            ["test-template"],
        )
        self.assertCountEqual(
            parser.Target("@tag:tag1").expand(system_info=self.system_info),
            [
                "test-vm1",
                "test-invalid-dvm",
                "test-template",
                "test-standalone",
                "test-no-dvm",
            ],
        )
        self.assertCountEqual(
            parser.Target("@tag:tag2").expand(system_info=self.system_info),
            [
                "test-vm1",
                "test-vm2",
                "test-invalid-dvm",
                "test-template",
                "test-standalone",
                "test-no-dvm",
            ],
        )
        self.assertCountEqual(
            parser.Target("@tag:no-such-tag").expand(
                system_info=self.system_info
            ),
            [],
        )
        self.assertCountEqual(
            parser.Target("@dispvm").expand(system_info=self.system_info),
            ["@dispvm"],
        )
        self.assertCountEqual(
            parser.Target("@dispvm:default-dvm").expand(
                system_info=self.system_info
            ),
            ["@dispvm:default-dvm"],
        )

        # no DispVM from test-vm1 allowed
        self.assertCountEqual(
            parser.Target("@dispvm:test-vm1").expand(
                system_info=self.system_info
            ),
            [],
        )

        self.assertCountEqual(
            parser.Target("@dispvm:test-vm3").expand(
                system_info=self.system_info
            ),
            ["@dispvm:test-vm3"],
        )
        self.assertCountEqual(
            parser.Target("@dispvm:@tag:tag1").expand(
                system_info=self.system_info
            ),
            [],
        )
        self.assertCountEqual(
            parser.Target("@dispvm:@tag:tag3").expand(
                system_info=self.system_info
            ),
            ["@dispvm:test-vm3"],
        )
        self.assertCountEqual(
            parser.Target(
                "@dispvm:uuid:fa6d56e8-a89d-4106-aa62-22e172a43c8b"
            ).expand(system_info=self.system_info),
            ["@dispvm:test-vm3"],
        )

    def test_030_Redirect(self):
        self.assertIs(parser.Redirect(None), None)

        parser.Redirect("test-vm1")
        parser.Redirect("@adminvm")
        parser.Redirect("dom0")
        parser.Redirect("uuid:00000000-0000-0000-0000-000000000000")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@anyvm")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("*")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@default")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@type:AppVM")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@tag:tag1")
        parser.Redirect("@dispvm")
        parser.Redirect("@dispvm:default-dvm")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@dispvm:@tag:tag3")

        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@invalid")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@dispvm:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@dispvm:@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.Redirect("@type:")

    def test_040_IntendedTarget(self):
        parser.IntendedTarget("uuid:00000000-0000-0000-0000-000000000000")
        parser.IntendedTarget("test-vm1")
        parser.IntendedTarget("@adminvm")
        parser.IntendedTarget("dom0")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@anyvm")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("*")
        parser.IntendedTarget("@default")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@type:AppVM")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@tag:tag1")
        parser.IntendedTarget("@dispvm")
        parser.IntendedTarget("@dispvm:default-dvm")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@dispvm:@tag:tag3")

        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@invalid")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@dispvm:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@dispvm:@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@tag:")
        with self.assertRaises(exc.PolicySyntaxError):
            parser.IntendedTarget("@type:")

    def test_100_match_single(self):
        # pytest: disable=no-self-use
        cases = [
            ("uuid:00000000-0000-0000-0000-000000000000", "@adminvm", True),
            ("uuid:00000000-0000-0000-0000-000000000000", "dom0", True),
            (
                "uuid:00000000-0000-0000-0000-000000000000",
                "@dispvm:default-dvm",
                False,
            ),
            ("uuid:00000000-0000-0000-0000-000000000000", "test-vm1", False),
            ("@anyvm", "test-vm1", True),
            ("@anyvm", "@default", True),
            ("@default", "@default", True),
            ("@tag:tag1", "test-vm1", True),
            ("@type:AppVM", "test-vm1", True),
            ("@type:TemplateVM", "test-template", True),
            ("@anyvm", "@dispvm", True),
            ("@anyvm", "@dispvm:default-dvm", True),
            ("@dispvm", "@dispvm", True),
            ("@dispvm:@tag:tag3", "@dispvm:test-vm3", True),
            ("@adminvm", "@adminvm", True),
            ("@adminvm", "dom0", True),
            ("dom0", "@adminvm", True),
            ("@adminvm", "uuid:00000000-0000-0000-0000-000000000000", True),
            ("dom0", "dom0", True),
            ("test-vm3", "dom0", False),
            ("dom0", "test-vm3", False),
            ("test-vm3", "@adminvm", False),
            ("@adminvm", "test-vm3", False),
            ("test-vm3", "uuid:00000000-0000-0000-0000-000000000000", False),
            ("uuid:00000000-0000-0000-0000-000000000000", "test-vm3", False),
            ("@dispvm:default-dvm", "@dispvm:default-dvm", True),
            ("@anyvm", "@dispvm", True),
            ("*", "test-vm1", True),
            ("*", "@dispvm", True),
            ("*", "@adminvm", True),
            ("@default", "no-such-vm", True),
            ("@default", "test-vm1\n", True),
            ("@default", "test-vm1  ", True),
            ("@default", "test-vm1", False),
            ("@tag:tag1", "test-vm3", False),
            # test-vm3 has not tag1
            ("@dispvm:@tag:tag1", "@dispvm:test-vm3", False),
            # default-dvm has no tag3
            ("@dispvm:@tag:tag3", "@dispvm:default-dvm", False),
            ("@anyvm", "dom0", False),
            ("@anyvm", "@adminvm", False),
            ("@tag:dom0-tag", "@adminvm", False),
            ("@type:AdminVM", "@adminvm", False),
            ("@tag:dom0-tag", "dom0", True),
            ("@type:AdminVM", "dom0", True),
            ("@tag:tag1", "dom0", False),
            ("@dispvm", "test-vm1", False),
            ("@dispvm", "default-dvm", False),
            ("@dispvm:default-dvm", "default-dvm", False),
            (
                "uuid:6d7a02b5-532b-467f-b9fb-6596bae03c33",
                "test-standalone",
                True,
            ),
            ("uuid:f3e538bd-4427-4697-bed7-45ef3270df21", "default-dvm", True),
            (
                "@dispvm:uuid:f3e538bd-4427-4697-bed7-45ef3270df21",
                "@dispvm:uuid:f3e538bd-4427-4697-bed7-45ef3270df21",
                True,
            ),
            (
                "@dispvm:uuid:f3e538bd-4427-4697-bed7-45ef3270df21",
                "@dispvm:default-dvm",
                True,
            ),
            (
                "@dispvm:default-dvm",
                "@dispvm:uuid:f3e538bd-4427-4697-bed7-45ef3270df21",
                True,
            ),
            (
                "test-standalone",
                "uuid:6d7a02b5-532b-467f-b9fb-6596bae03c33",
                True,
            ),
        ]

        for token, target, expected_result in cases:
            match_result = parser.VMToken(token).match(
                parser.IntendedTarget(target).verify(
                    system_info=self.system_info
                ),
                system_info=self.system_info,
            )
            assert (
                match_result == expected_result
            ), "{} match {} should be {}".format(token, target, expected_result)

    def test_101_match_single_access_denied(self):
        targets = [
            # test-vm1.template_for_dispvms=False
            "@dispvm:test-vm1",
            "@tag:tag1",
            "@type:AppVM",
            "@invalid",
        ]

        for target in targets:
            with self.assertRaises(
                exc.AccessDenied,
                msg="{} should raise AccessDenied".format(target),
            ):
                parser.IntendedTarget(target).verify(
                    system_info=self.system_info
                )


class TC_01_Request(ParserTestCase):
    def test_000_init(self):
        request = parser.Request(
            "qrexec.Service",
            "+argument",
            "test-vm1",
            "test-vm2",
            system_info=self.system_info,
        )
        self.assertEqual(request.service, "qrexec.Service")
        self.assertEqual(request.argument, "+argument")
        self.assertEqual(request.source, "test-vm1")
        self.assertEqual(request.target, "test-vm2")
        self.assertEqual(request.system_info, self.system_info)

    def test_001_invalid_argument(self):
        with self.assertRaises(AssertionError):
            parser.Request(
                "qrexec.Service",
                "argument",
                "test-vm1",
                "@type:AppVM",
                system_info=self.system_info,
            )

    def test_002_invalid_target(self):
        for invalid_target in [
            "@type:AppVM",
            "@dispvm:test-invalid-dvm",
            "@dispvm:test-vm1",  #'@default',
            "@anyvm",
            "@tag:tag1",
            "@dispvm:@tag:tag1",
            "@invalid",
        ]:
            with self.subTest(invalid_target):
                with self.assertRaises(exc.AccessDenied):
                    parser.Request(
                        "qrexec.Service",
                        "+argument",
                        "test-vm1",
                        invalid_target,
                        system_info=self.system_info,
                    )

    def test_003_non_existing_target(self):
        request = parser.Request(
            "qrexec.Service",
            "+argument",
            "test-vm1",
            "no-such-vm",
            system_info=self.system_info,
        )
        self.assertEqual(request.service, "qrexec.Service")
        self.assertEqual(request.argument, "+argument")
        self.assertEqual(request.source, "test-vm1")
        self.assertEqual(request.target, "@default")
        self.assertEqual(request.system_info, self.system_info)


# class TC_00_Rule(qubes.tests.QubesTestCase):
class TC_10_Rule(ParserTestCase):
    def test_000_init(self):
        line = parser.Rule(
            "test.Service",
            "+argument",
            "@anyvm",
            "@anyvm",
            "allow",
            (),
            policy=None,
            filepath=Path("filename"),
            lineno=12,
        )

        self.assertEqual(line.service, "test.Service")
        self.assertEqual(line.argument, "+argument")
        self.assertEqual(line.source, "@anyvm")
        self.assertIsInstance(line.source, parser.VMToken)
        self.assertEqual(line.target, "@anyvm")
        self.assertIsInstance(line.target, parser.VMToken)
        self.assertIsInstance(line.action, parser.Action.allow.value)

    def test_020_line_simple(self):
        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @anyvm ask",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@anyvm")
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertIsNone(line.action.default_target)

    def test_021_line_simple(self):
        # also check spaces in action field
        line = parser.Rule.from_line(
            None,
            "test.Service +argument @tag:tag1 @type:AppVM ask target=test-vm2 user=user",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@tag:tag1")
        self.assertEqual(line.target, "@type:AppVM")
        self.assertEqual(line.action.target, "test-vm2")
        self.assertEqual(line.action.user, "user")
        self.assertIsNone(line.action.default_target)

    def test_022_line_simple(self):
        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @default allow target=@dispvm:test-vm2",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.allow.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@default")
        self.assertEqual(line.action.target, "@dispvm:test-vm2")
        self.assertIsNone(line.action.user)
        with self.assertRaises(AttributeError):
            line.action.default_target

    def test_023_line_simple(self):
        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @default ask default_target=test-vm1",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@default")
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, "test-vm1")

    def test_024_line_simple(self):
        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @adminvm ask default_target=@adminvm",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@adminvm")
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, "@adminvm")

    def test_030_line_invalid(self):
        invalid_lines = [
            "test.Service +argument @dispvm @default allow",  # @dispvm can't be a source
            "test.Service +argument @default @default allow",  # @default can't be a source
            "test.Service +argument @anyvm @default allow,target=@dispvm:@tag:tag1",  # @dispvm:@tag
            #  as override target
            "test.Service +argument @anyvm @default allow,target=@tag:tag1",  # @tag as override target
            "test.Service +argument @anyvm @default deny,target=test-vm1",  # target= used with deny
            "test.Service +argument @anyvm @anyvm deny,default_target=test-vm1",  # default_target=
            # with deny
            "test.Service +argument @anyvm @anyvm deny,user=user",  # user= with deny
            "test.Service +argument @anyvm @anyvm invalid",  # invalid action
            "test.Service +argument @anyvm @anyvm allow,invalid=xx",  # invalid option
            "test.Service +argument @anyvm @anyvm",  # missing action
            "test.Service +argument @anyvm @anyvm allow,default_target=test-vm1",  # default_target=
            #  with allow
            "test.Service +argument @invalid @anyvm allow",  # invalid source
            "test.Service +argument @anyvm @invalid deny",  # invalid target
            "",  # empty line
            "test.Service +argument @anyvm @anyvm allow extra",  # trailing words
            "test.Service +argument @anyvm @default allow",  # @default allow without target=
            "test.Service +argument @anyvm @anyvm allow notify",  # missing =yes/=no
            "test.Service +argument @anyvm @anyvm allow notify=xx",  # invalid notify
            "* +argument @anyvm @default allow",  # specific argument for * service
        ]
        for line in invalid_lines:
            with self.subTest(line):
                with self.assertRaises(exc.PolicySyntaxError):
                    parser.Rule.from_line(
                        None, line, filepath=Path("filename"), lineno=12
                    )

    def test_050_match(self):
        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @anyvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertTrue(
            line.is_match(
                parser.Request(
                    "test.Service",
                    "+argument",
                    "test-vm1",
                    "test-vm2",
                    system_info=self.system_info,
                )
            )
        )

        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @anyvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertTrue(
            line.is_match(
                parser.Request(
                    "test.Service",
                    "+argument",
                    "no-such-vm",
                    "test-vm2",
                    system_info=self.system_info,
                )
            )
        )

        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @dispvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertTrue(
            line.is_match(
                parser.Request(
                    "test.Service",
                    "+argument",
                    "test-vm1",
                    "@dispvm",
                    system_info=self.system_info,
                )
            )
        )

        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @dispvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertFalse(
            line.is_match(
                parser.Request(
                    "test.Service",
                    "+argument",
                    "test-vm1",
                    "@dispvm:default-dvm",
                    system_info=self.system_info,
                )
            )
        )

        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @dispvm:default-dvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertTrue(
            line.is_match(
                parser.Request(
                    "test.Service",
                    "+argument",
                    "test-vm1",
                    "@dispvm",
                    system_info=self.system_info,
                )
            )
        )

        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @dispvm:default-dvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertTrue(
            line.is_match(
                parser.Request(
                    "test.Service",
                    "+argument",
                    "test-vm1",
                    "@dispvm:default-dvm",
                    system_info=self.system_info,
                )
            )
        )

        line = parser.Rule.from_line(
            None,
            "test.Service +argument @anyvm @dispvm:@tag:tag3 allow",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertTrue(
            line.is_match(
                parser.Request(
                    "test.Service",
                    "+argument",
                    "test-vm1",
                    "@dispvm:test-vm3",
                    system_info=self.system_info,
                )
            )
        )

    def test_060_serialization(self):
        lines = [
            "test.Service\t+argument\t@anyvm\t@anyvm\tallow",
            "test.Service\t+argument\t@anyvm\t@anyvm\task",
            "test.Service\t+argument\t@anyvm\t@anyvm\tdeny",
            "test.Service\t*\t@anyvm\t@anyvm\tdeny",
            "test.Service\t+argument\t@anyvm\t@dispvm:default-dvm\tallow",
            "test.Service\t+argument\t@tag:tag1\t@type:AppVM\task target=test-vm2 user=user",
            "test.Service\t+argument\t@anyvm\t@anyvm\tallow target=@adminvm",
        ]

        for line in lines:
            rule = parser.Rule.from_line(
                None, line, filepath=Path("filename"), lineno=12
            )
            assert str(rule) == line


@pytest.mark.parametrize(
    "action_name,action,default",
    [
        ("deny", parser.Action.deny.value, True),
        ("ask", parser.Action.ask.value, False),
        ("allow", parser.Action.allow.value, False),
    ],
)
def test_line_notify(action_name, action, default):
    line = parser.Rule.from_line(
        None,
        "test.Service +argument @anyvm @adminvm {}".format(action_name),
        filepath=Path("filename"),
        lineno=12,
    )
    assert isinstance(line.action, action)
    assert line.action.notify is default

    line = parser.Rule.from_line(
        None,
        "test.Service +argument @anyvm @adminvm {} notify=yes".format(
            action_name
        ),
        filepath=Path("filename"),
        lineno=12,
    )
    assert isinstance(line.action, action)
    assert line.action.notify is True

    line = parser.Rule.from_line(
        None,
        "test.Service +argument @anyvm @adminvm {} notify=no".format(
            action_name
        ),
        filepath=Path("filename"),
        lineno=12,
    )
    assert isinstance(line.action, action)
    assert line.action.notify is False


@pytest.mark.parametrize(
    "action_name,action",
    [
        ("ask", parser.Action.ask.value),
        ("allow", parser.Action.allow.value),
    ],
)
def test_line_autostart(action_name, action):
    line = parser.Rule.from_line(
        None,
        "test.Service +argument @anyvm @anyvm {}".format(action_name),
        filepath=Path("filename"),
        lineno=12,
    )
    assert isinstance(line.action, action)
    assert line.action.autostart is True

    line = parser.Rule.from_line(
        None,
        "test.Service +argument @anyvm @anyvm {} autostart=yes".format(
            action_name
        ),
        filepath=Path("filename"),
        lineno=12,
    )
    assert isinstance(line.action, action)
    assert line.action.autostart is True

    line = parser.Rule.from_line(
        None,
        "test.Service +argument @anyvm @anyvm {} autostart=no".format(
            action_name
        ),
        filepath=Path("filename"),
        lineno=12,
    )
    assert isinstance(line.action, action)
    assert line.action.autostart is False


class TC_11_Rule_service(ParserTestCase):
    def test_020_line_simple(self):
        line = parser.Rule.from_line_service(
            None,
            "test.Service",
            "+argument",
            "@anyvm @anyvm ask",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@anyvm")
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertIsNone(line.action.default_target)

    def test_021_line_simple(self):
        # also check spaces in action field
        line = parser.Rule.from_line_service(
            None,
            "test.Service",
            "+argument",
            "@tag:tag1 @type:AppVM ask target=test-vm2 user=user",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@tag:tag1")
        self.assertEqual(line.target, "@type:AppVM")
        self.assertEqual(line.action.target, "test-vm2")
        self.assertEqual(line.action.user, "user")
        self.assertIsNone(line.action.default_target)

    def test_022_line_simple(self):
        line = parser.Rule.from_line_service(
            None,
            "test.Service",
            "+argument",
            "@anyvm @default allow target=@dispvm:test-vm2",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.allow.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@default")
        self.assertEqual(line.action.target, "@dispvm:test-vm2")
        self.assertIsNone(line.action.user)
        with self.assertRaises(AttributeError):
            line.action.default_target

    def test_023_line_simple(self):
        line = parser.Rule.from_line_service(
            None,
            "test.Service",
            "+argument",
            "@anyvm @default ask default_target=test-vm1",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@default")
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, "test-vm1")

    def test_024_line_simple(self):
        line = parser.Rule.from_line_service(
            None,
            "test.Service",
            "+argument",
            "@anyvm @adminvm ask default_target=@adminvm",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@adminvm")
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, "@adminvm")

    def test_025_line_simple_compat(self):
        line = parser.Rule.from_line_service(
            None,
            "test.Service",
            "+argument",
            "@anyvm @default ask,default_target=test-vm1",
            filepath=Path("filename"),
            lineno=12,
        )
        self.assertEqual(str(line.filepath), "filename")
        self.assertEqual(line.lineno, 12)
        self.assertIsInstance(line.action, parser.Action.ask.value)
        self.assertEqual(line.source, "@anyvm")
        self.assertEqual(line.target, "@default")
        self.assertIsNone(line.action.target)
        self.assertIsNone(line.action.user)
        self.assertEqual(line.action.default_target, "test-vm1")

    def test_030_line_invalid(self):
        invalid_lines = [
            "@dispvm @default allow",  # @dispvm can't be a source
            "@default @default allow",  # @default can't be a source
            "@anyvm @default allow,target=@dispvm:@tag:tag1",  # @dispvm:@tag
            #  as override target
            "@anyvm @default allow,target=@tag:tag1",  # @tag as override target
            "@anyvm @default deny,target=test-vm1",  # target= used with deny
            "@anyvm @anyvm deny,default_target=test-vm1",  # default_target=
            # with deny
            "@anyvm @anyvm deny,user=user",  # user= with deny
            "@anyvm @anyvm invalid",  # invalid action
            "@anyvm @anyvm allow,invalid=xx",  # invalid option
            "@anyvm @anyvm",  # missing action
            "@anyvm @anyvm allow,default_target=test-vm1",  # default_target=
            #  with allow
            "@invalid @anyvm allow",  # invalid source
            "@anyvm @invalid deny",  # invalid target
            "",  # empty line
            "@anyvm @anyvm allow extra",  # trailing words
            "@anyvm @default allow",  # @default allow without target=
        ]
        for line in invalid_lines:
            with self.subTest(line):
                with self.assertRaises(exc.PolicySyntaxError):
                    parser.Rule.from_line_service(
                        None,
                        "test.Service",
                        "+argument",
                        line,
                        filepath=Path("filename"),
                        lineno=12,
                    )


class TC_20_Policy(ParserTestCase):
    def test_000_load(self):
        policy = parser.StringPolicy(
            policy="""\
* * test-vm1 test-vm2 allow

# comment
* * test-vm2 test-vm3 ask
    # comment with trailing whitespace:    """
            """
* * @anyvm @anyvm ask
"""
        )

        self.assertEqual(len(policy.rules), 3)
        self.assertEqual(policy.rules[0].source, "test-vm1")
        self.assertEqual(policy.rules[0].target, "test-vm2")
        self.assertIsInstance(policy.rules[0].action, parser.Action.allow.value)

    def test_002_include(self):
        policy = parser.StringPolicy(
            policy={
                "__main__": """\
                * * test-vm1 test-vm2 allow
                !include file2
                * * @anyvm @anyvm deny
            """,
                "file2": """\
                * * test-vm3 @default allow target=test-vm2
            """,
            }
        )

        self.assertEqual(len(policy.rules), 3)
        self.assertEqual(policy.rules[0].source, "test-vm1")
        self.assertEqual(policy.rules[0].target, "test-vm2")
        self.assertIsInstance(policy.rules[0].action, parser.Action.allow.value)
        self.assertEqual(
            policy.rules[0].filepath, PurePosixPath("__main__[in-memory]")
        )
        self.assertEqual(policy.rules[0].lineno, 1)
        self.assertEqual(policy.rules[1].source, "test-vm3")
        self.assertEqual(policy.rules[1].target, "@default")
        self.assertIsInstance(policy.rules[1].action, parser.Action.allow.value)
        self.assertEqual(
            policy.rules[1].filepath, PurePosixPath("file2[in-memory]")
        )
        self.assertEqual(policy.rules[1].lineno, 1)
        self.assertEqual(policy.rules[2].source, "@anyvm")
        self.assertEqual(policy.rules[2].target, "@anyvm")
        self.assertIsInstance(policy.rules[2].action, parser.Action.deny.value)
        self.assertEqual(
            policy.rules[2].filepath, PurePosixPath("__main__[in-memory]")
        )
        self.assertEqual(policy.rules[2].lineno, 3)

    def test_003_include_service(self):
        policy = parser.StringPolicy(
            policy={
                "__main__": """\
                !include-service * * new-syntax
                !include-service * * old-syntax
            """,
                "new-syntax": """\
                test-vm2 test-vm3 ask
                # comment with whitespace  """
                """
                @anyvm @dispvm ask default_target=@dispvm
            """,
                "old-syntax": """\
                test-vm2 test-vm3 ask
                # comment with whitespace  """
                """
                $anyvm $dispvm ask,default_target=$dispvm
            """,
            }
        )
        self.assertEqual(len(policy.rules), 4)
        self.assertEqual(policy.rules[1].source, "@anyvm")
        self.assertEqual(policy.rules[1].target, "@dispvm")
        self.assertIsInstance(policy.rules[1].action, parser.Action.ask.value)
        self.assertEqual(policy.rules[1].action.default_target, "@dispvm")
        self.assertEqual(policy.rules[3].source, "@anyvm")
        self.assertEqual(policy.rules[3].target, "@dispvm")
        self.assertIsInstance(policy.rules[3].action, parser.Action.ask.value)
        self.assertEqual(policy.rules[3].action.default_target, "@dispvm")

    def test_010_find_rule(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm1 test-vm2 allow
            * * test-vm1 @anyvm ask
            * * test-vm2 @tag:tag1 deny
            * * test-vm2 @tag:tag2 allow
            * * test-vm2 @dispvm:@tag:tag3 allow
            * * test-vm2 @dispvm:@tag:tag2 allow
            * * test-vm2 @dispvm:default-dvm allow
            * * @type:AppVM @default allow target=test-vm3
            * * @tag:tag1 @type:AppVM allow
        """
        )
        self.assertEqual(
            policy.rules[0],
            policy.find_matching_rule(self.gen_req("test-vm1", "test-vm2")),
        )
        self.assertEqual(
            policy.rules[1],
            policy.find_matching_rule(self.gen_req("test-vm1", "test-vm3")),
        )
        self.assertEqual(
            policy.rules[3],
            policy.find_matching_rule(self.gen_req("test-vm2", "test-vm2")),
        )
        self.assertEqual(
            policy.rules[2],
            policy.find_matching_rule(self.gen_req("test-vm2", "test-no-dvm")),
        )
        # @anyvm matches @default too
        self.assertEqual(
            policy.rules[1],
            policy.find_matching_rule(self.gen_req("test-vm1", "@default")),
        )
        self.assertEqual(
            policy.rules[7],
            policy.find_matching_rule(self.gen_req("test-vm2", "@default")),
        )
        self.assertEqual(
            policy.rules[8],
            policy.find_matching_rule(self.gen_req("test-no-dvm", "test-vm3")),
        )
        self.assertEqual(
            policy.rules[4],
            policy.find_matching_rule(
                self.gen_req("test-vm2", "@dispvm:test-vm3")
            ),
        )
        self.assertEqual(
            policy.rules[6],
            policy.find_matching_rule(self.gen_req("test-vm2", "@dispvm")),
        )

        with self.assertRaises(exc.AccessDenied):
            policy.find_matching_rule(
                self.gen_req("test-no-dvm", "test-standalone")
            )
        with self.assertRaises(exc.AccessDenied):
            policy.find_matching_rule(self.gen_req("test-no-dvm", "@dispvm"))
        with self.assertRaises(exc.AccessDenied):
            policy.find_matching_rule(
                self.gen_req("test-standalone", "@default")
            )

    def test_020_collect_targets_for_ask(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm1 test-vm2 allow
            * * test-vm1 @anyvm ask
            * * test-vm2 @tag:tag1 deny
            * * test-vm2 @tag:tag2 allow
            * * test-no-dvm @type:AppVM deny
            * * @type:AppVM @default allow target=test-vm3
            * * @tag:tag1 @type:AppVM allow
            * * test-no-dvm @dispvm allow
            * * test-standalone @dispvm allow
            * * test-standalone @adminvm allow
            * * uuid:c9024a97-9b15-46cc-8341-38d75d5d421b bogus2 deny
            * * uuid:c798d6db-360f-473a-b902-1cc58ffd3ab0 uuid:6d7a02b5-532b-467f-b9fb-6596bae03c33 ask
            * * test2-vm1 @dispvm:uuid:91e4fe8d-083b-4ddf-ad7b-fb4ebac537b9 ask
        """
        )

        self.assertCountEqual(
            sorted(
                policy.collect_targets_for_ask(
                    self.gen_req("test-vm1", "@default")
                )
            ),
            [
                "@dispvm:default-dvm",
                "@dispvm:test-vm3",
                "@dispvm:test-vm4",
                "default-dvm",
                "test-invalid-dvm",
                "test-no-dvm",
                "test-relayvm1",
                "test-remotevm1",
                "test-standalone",
                "test-template",
                "test-vm2",
                "test-vm3",
                "test-vm4",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-remotevm1",
                "test2-remotevm2",
                "test2-vm1",
            ],
        )
        self.assertEqual(
            policy.collect_targets_for_ask(
                self.gen_req("test-vm2", "@default")
            ),
            {"test-vm3"},
        )
        self.assertCountEqual(
            policy.collect_targets_for_ask(
                self.gen_req("test-vm3", "@default")
            ),
            [],
        )
        self.assertEqual(
            sorted(
                policy.collect_targets_for_ask(
                    self.gen_req("test-standalone", "@default")
                )
            ),
            [
                "@dispvm:default-dvm",
                "default-dvm",
                "dom0",
                "test-invalid-dvm",
                "test-no-dvm",
                "test-relayvm1",
                "test-vm1",
                "test-vm2",
                "test-vm3",
                "test-vm4",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-vm1",
            ],
        )
        self.assertCountEqual(
            policy.collect_targets_for_ask(
                self.gen_req("test-no-dvm", "@default")
            ),
            [],
        )
        self.assertCountEqual(
            policy.collect_targets_for_ask(
                self.gen_req("test2-vm1", "@default")
            ),
            ["test-standalone", "@dispvm:test-vm4", "test-vm3"],
        )


class TC_30_Resolution(ParserTestCase):
    def setUp(self):
        self.request = parser.Request(
            "test.Service",
            "+argument",
            "test-vm1",
            "test-vm2",
            system_info=self.system_info,
        )

    #
    # allow
    #

    def test_000_allow_init(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        resolution = parser.AllowResolution(
            rule, self.request, user=None, target="test-vm2", autostart=True
        )
        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertIs(resolution.target, "test-vm2")
        self.assertFalse(resolution.notify)

    def test_001_allow_notify(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm allow notify=yes",
            filepath=Path("filename"),
            lineno=12,
        )
        resolution = parser.AllowResolution(
            rule, self.request, user=None, target="test-vm2", autostart=True
        )
        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertIs(resolution.target, "test-vm2")
        self.assertTrue(resolution.notify)

    #
    # ask
    #

    def test_100_ask_init(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm @anyvm ask", filepath=Path("filename"), lineno=12
        )
        resolution = parser.AskResolution(
            rule,
            self.request,
            user=None,
            targets_for_ask=["test-vm2"],
            default_target="test-vm2",
            autostart=True,
        )

        with self.assertRaises(AttributeError):
            resolution.target

        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertCountEqual(resolution.targets_for_ask, ["test-vm2"])
        self.assertFalse(resolution.notify)

    def test_101_ask_init(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm @anyvm ask", filepath=Path("filename"), lineno=12
        )
        resolution = parser.AskResolution(
            rule,
            self.request,
            user=None,
            targets_for_ask=["test-vm2", "test-vm3"],
            default_target="test-vm2",
            autostart=True,
        )

        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertEqual(resolution.request.target, "test-vm2")
        self.assertCountEqual(
            resolution.targets_for_ask, ["test-vm2", "test-vm3"]
        )
        self.assertIs(resolution.default_target, "test-vm2")
        self.assertFalse(resolution.notify)

    def test_102_ask_notify(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm ask notify=yes",
            filepath=Path("filename"),
            lineno=12,
        )
        resolution = parser.AskResolution(
            rule,
            self.request,
            user=None,
            targets_for_ask=["test-vm2"],
            default_target="test-vm2",
            autostart=True,
        )

        with self.assertRaises(AttributeError):
            resolution.target

        self.assertIs(resolution.rule, rule)
        self.assertIs(resolution.request, self.request)
        self.assertIs(resolution.user, None)
        self.assertCountEqual(resolution.targets_for_ask, ["test-vm2"])
        self.assertTrue(resolution.notify)

    def test_103_ask_default_target_None(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm @anyvm ask", filepath=Path("filename"), lineno=12
        )
        resolution = parser.AskResolution(
            rule,
            self.request,
            user=None,
            targets_for_ask=["test-vm2", "test-vm3"],
            default_target=None,
            autostart=True,
        )

        self.assertIsNone(resolution.default_target)


class TC_40_evaluate(ParserTestCase):
    def setUp(self):
        self.policy = parser.StringPolicy(
            policy="""\
            * * test-vm1 test-vm2 allow
            * * test-vm1 @default allow target=test-vm2
            * * @tag:tag1 test-vm2 ask
            * * @tag:tag1 test-vm3 ask default_target=test-vm3
            * * @tag:tag2 @anyvm allow
            * * test-vm3 @anyvm deny"""
        )

    def test_000_deny(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm deny"""
        )
        with self.assertRaises(exc.AccessDenied) as e:
            policy.evaluate(self.gen_req("test-vm1", "test-vm2"))
        self.assertTrue(e.exception.notify)

    def test_001_deny_no_notify(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm deny notify=no"""
        )
        with self.assertRaises(exc.AccessDenied) as e:
            policy.evaluate(self.gen_req("test-vm1", "test-vm2"))
        self.assertFalse(e.exception.notify)

    def test_030_eval_simple(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm1 test-vm2 allow"""
        )

        request = self.gen_req("test-vm1", "test-vm2")
        resolution = policy.evaluate(request)

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertIs(resolution.request, request)
        self.assertIs(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "test-vm2")

        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(self.gen_req("test-vm2", "@default"))

    def test_031_eval_default(self):
        resolution = self.policy.evaluate(self.gen_req("test-vm1", "@default"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, self.policy.rules[1])
        self.assertEqual(resolution.target, "test-vm2")
        self.assertEqual(resolution.request.target, "@default")

        with self.assertRaises(exc.AccessDenied):
            # action allow should hit, but no target specified (either by
            # caller or policy)
            self.policy.evaluate(self.gen_req("test-standalone", "@default"))

    def test_032_eval_no_autostart(self):
        # test-vm2 is running, test-vm3 is halted
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm1 test-vm2 allow autostart=no
            * * test-vm1 test-vm3 allow autostart=no"""
        )

        request = self.gen_req("test-vm1", "test-vm2")
        resolution = policy.evaluate(request)
        self.assertIsInstance(resolution, parser.AllowResolution)

        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(self.gen_req("test-vm1", "test-vm3"))

    def test_040_eval_ask(self):
        resolution = self.policy.evaluate(
            self.gen_req("test-standalone", "test-vm2")
        )

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, self.policy.rules[2])
        self.assertEqual(resolution.request.target, "test-vm2")
        self.assertCountEqual(
            sorted(resolution.targets_for_ask),
            sorted(
                [
                    "@dispvm:default-dvm",
                    "@dispvm:test-vm3",
                    "@dispvm:test-vm4",
                    "default-dvm",
                    "test-invalid-dvm",
                    "test-no-dvm",
                    "test-relayvm1",
                    "test-remotevm1",
                    "test-template",
                    "test-vm1",
                    "test-vm2",
                    "test-vm3",
                    "test-vm4",
                    "test2-relayvm1",
                    "test2-relayvm2",
                    "test2-remotevm1",
                    "test2-remotevm2",
                    "test2-vm1",
                ]
            ),
        )

    def test_041_eval_ask(self):
        for i in self.system_info["domains"].values():
            assert not i["name"].startswith("uuid:")
        resolution = self.policy.evaluate(
            self.gen_req(
                "uuid:6d7a02b5-532b-467f-b9fb-6596bae03c33", "test-vm3"
            )
        )

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, self.policy.rules[3])
        self.assertEqual(resolution.default_target, "test-vm3")
        self.assertEqual(resolution.request.target, "test-vm3")
        self.assertEqual(
            [
                "@dispvm:default-dvm",
                "@dispvm:test-vm3",
                "@dispvm:test-vm4",
                "default-dvm",
                "test-invalid-dvm",
                "test-no-dvm",
                "test-relayvm1",
                "test-remotevm1",
                "test-template",
                "test-vm1",
                "test-vm2",
                "test-vm3",
                "test-vm4",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-remotevm1",
                "test2-remotevm2",
                "test2-vm1",
            ],
            sorted(resolution.targets_for_ask),
        )

    def test_042_eval_ask_no_targets(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 @default ask"""
        )
        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(self.gen_req("test-vm3", "@default"))

    def test_043_eval_ask_no_autostart(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm1 @anyvm ask"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm1", "test-vm2"))
        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertCountEqual(
            sorted(resolution.targets_for_ask),
            [
                "@dispvm:default-dvm",
                "@dispvm:test-vm3",
                "@dispvm:test-vm4",
                "default-dvm",
                "test-invalid-dvm",
                "test-no-dvm",
                "test-relayvm1",
                "test-remotevm1",
                "test-standalone",
                "test-template",
                "test-vm2",
                "test-vm3",
                "test-vm4",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-remotevm1",
                "test2-remotevm2",
                "test2-vm1",
            ],
        )

        policy = parser.StringPolicy(
            policy="""\
            * * test-vm1 @anyvm ask autostart=no"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm1", "test-vm2"))
        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertCountEqual(
            sorted(resolution.targets_for_ask),
            [
                "test-relayvm1",
                "test-remotevm1",
                "test-vm2",
                "test2-relayvm1",
                "test2-relayvm2",
                "test2-remotevm1",
                "test2-remotevm2",
                "test2-vm1",
            ],
        )

    def test_043_eval_ask_invalid_default_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 test-vm2 ask default_target=test-vm1"""
        )
        with unittest.mock.patch("qrexec.policy.parser.logging") as mock_log:
            resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm2"))
        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertCountEqual(
            sorted(resolution.targets_for_ask),
            [
                "test-vm2",
            ],
        )
        self.assertIsNone(resolution.default_target)
        mock_log.warning.assert_called_once()

    def test_050_eval_resolve_dispvm(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 @dispvm allow"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "@dispvm"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "@dispvm:default-dvm")
        self.assertEqual(resolution.request.target, "@dispvm")

    def test_051_eval_resolve_dispvm_fail(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-no-dvm @dispvm allow"""
        )
        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(self.gen_req("test-no-dvm", "@dispvm"))

    def test_053_eval_resolve_dispvm_from_any(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @dispvm allow"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "@dispvm"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "@dispvm:default-dvm")
        self.assertEqual(resolution.request.target, "@dispvm")

    def test_054_eval_resolve_dispvm_from_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm allow target=@dispvm"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "@dispvm:default-dvm")
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_055_eval_resolve_dispvm_from_default_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm ask default_target=@dispvm
            * * @anyvm @dispvm ask"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.default_target, "@dispvm:default-dvm")
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_060_eval_to_dom0(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 @adminvm allow"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "dom0"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "dom0")
        self.assertEqual(resolution.request.target, "dom0")

    def test_061_eval_to_dom0_keyword(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 @adminvm allow"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "@adminvm"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "dom0")
        self.assertEqual(resolution.request.target, "@adminvm")

    def test_062_eval_to_dom0_literal(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 dom0 allow"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "dom0"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "dom0")
        self.assertEqual(resolution.request.target, "dom0")

    def test_063_eval_to_dom0_literal_policy(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 dom0 allow"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "@adminvm"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "dom0")
        self.assertEqual(resolution.request.target, "@adminvm")

    def test_064_eval_to_dom0_deny(self):
        names = (
            "dom0",
            "@adminvm",
            "uuid:00000000-0000-0000-0000-000000000000",
        )
        for target in names:
            policy = parser.StringPolicy(policy=f"* * test-vm3 test-vm2 allow")
            with self.assertRaises(exc.AccessDenied):
                policy.evaluate(self.gen_req("test-vm3", target))

            policy = parser.StringPolicy(policy=f"* * test-vm3 {target} allow")
            with self.assertRaises(exc.AccessDenied):
                policy.evaluate(self.gen_req("test-vm3", "test-vm2"))

    def test_070_eval_to_dom0_ask_default_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 dom0 ask default_target=dom0"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "dom0"))

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.default_target, "dom0")
        self.assertEqual(resolution.request.target, "dom0")
        self.assertEqual(resolution.targets_for_ask, ["dom0"])

    def test_071_eval_to_dom0_ask_default_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 dom0 ask default_target=@adminvm"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "dom0"))

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.default_target, "dom0")
        self.assertEqual(resolution.request.target, "dom0")
        self.assertEqual(resolution.targets_for_ask, ["dom0"])

    def test_072_eval_to_dom0_ask_default_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 @adminvm ask default_target=dom0"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "dom0"))

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.default_target, "dom0")
        self.assertEqual(resolution.request.target, "dom0")
        self.assertEqual(resolution.targets_for_ask, ["dom0"])

    def test_073_eval_to_dom0_ask_default_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 @adminvm ask default_target=@adminvm"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "dom0"))

        self.assertIsInstance(resolution, parser.AskResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.default_target, "dom0")
        self.assertEqual(resolution.request.target, "dom0")
        self.assertEqual(resolution.targets_for_ask, ["dom0"])

    def test_074_eval_to_default_dom0(self):
        names = (
            "dom0",
            "@adminvm",
            "uuid:00000000-0000-0000-0000-000000000000",
        )
        for target in names:
            for default_target in names:
                policy = parser.StringPolicy(
                    policy=f"* * test-vm3 @default ask target={target} default_target={default_target}"
                )
                resolution = policy.evaluate(
                    self.gen_req("test-vm3", "@default")
                )

                self.assertIsInstance(resolution, parser.AskResolution)
                self.assertEqual(resolution.rule, policy.rules[0])
                self.assertEqual(resolution.default_target, "dom0")
                self.assertEqual(resolution.request.target, "@default")
                self.assertEqual(resolution.targets_for_ask, ["dom0"])

    def test_080_eval_override_target(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm allow target=test-vm2"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "test-vm2")
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_081_eval_override_target_dispvm(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm allow target=@dispvm"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "@dispvm:default-dvm")
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_082_eval_override_target_dispvm_specific(self):
        policy = parser.StringPolicy(
            policy="""\
                    * * @anyvm @anyvm allow target=@dispvm:test-vm3"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "@dispvm:test-vm3")
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_083_eval_override_target_dispvm_none(self):
        policy = parser.StringPolicy(
            policy="""\
                    * * @anyvm @anyvm allow target=@dispvm"""
        )
        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(self.gen_req("test-no-dvm", "test-vm1"))

    def test_084_eval_override_target_dom0(self):
        policy = parser.StringPolicy(
            policy="""\
                    * * @anyvm @anyvm allow target=dom0"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "dom0")
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_085_eval_override_target_adminvm(self):
        policy = parser.StringPolicy(
            policy="""\
                    * * @anyvm @anyvm allow target=@adminvm"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(resolution.target, "dom0")
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_086_eval_override_target_invalid(self):
        policy = parser.StringPolicy(
            policy="""\
            * * test-vm3 @anyvm allow target=no-such-vm"""
        )
        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(self.gen_req("test-vm3", "@default"))

    def test_087_eval_override_target_uuid(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm allow target=uuid:b3eb69d0-f9d9-4c3c-ad5c-454500303ea4"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(
            resolution.target, "uuid:b3eb69d0-f9d9-4c3c-ad5c-454500303ea4"
        )
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_088_eval_override_target_uuid_dom0(self):
        policy = parser.StringPolicy(
            policy="""\
            * * @anyvm @anyvm allow target=uuid:00000000-0000-0000-0000-000000000000"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(
            resolution.target, "uuid:00000000-0000-0000-0000-000000000000"
        )
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_089_eval_override_target_dispvm_uuid(self):
        policy = parser.StringPolicy(
            policy="""\
                    * * @anyvm @anyvm allow target=@dispvm:uuid:fa6d56e8-a89d-4106-aa62-22e172a43c8b"""
        )
        resolution = policy.evaluate(self.gen_req("test-vm3", "test-vm1"))

        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.rule, policy.rules[0])
        self.assertEqual(
            resolution.target,
            "@dispvm:uuid:fa6d56e8-a89d-4106-aa62-22e172a43c8b",
        )
        self.assertEqual(resolution.request.target, "test-vm1")

    def test_110_handle_user_response_allow(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm @anyvm ask", filepath=Path("filename"), lineno=12
        )
        request = parser.Request(
            "test.service",
            "+",
            "test-vm1",
            "test-vm2",
            system_info=self.system_info,
        )
        resolution = parser.AskResolution(
            rule,
            request,
            user=None,
            targets_for_ask=["test-vm1", "test-vm2"],
            default_target=None,
            autostart=True,
        )
        resolution = resolution.handle_user_response(True, "test-vm2")
        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.target, "test-vm2")
        self.assertFalse(resolution.notify)

    def test_111_handle_user_response_allow_notify(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm ask notify=yes",
            filepath=Path("filename"),
            lineno=12,
        )
        request = parser.Request(
            "test.service",
            "+",
            "test-vm1",
            "test-vm2",
            system_info=self.system_info,
        )
        resolution = parser.AskResolution(
            rule,
            request,
            user=None,
            targets_for_ask=["test-vm1", "test-vm2"],
            default_target=None,
            autostart=True,
        )
        resolution = resolution.handle_user_response(True, "test-vm2")
        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.target, "test-vm2")
        self.assertTrue(resolution.notify)

    def test_112_handle_user_response_deny_invalid(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm @anyvm ask", filepath=Path("filename"), lineno=12
        )
        request = parser.Request(
            "test.service",
            "+",
            "test-vm1",
            "test-vm2",
            system_info=self.system_info,
        )
        resolution = parser.AskResolution(
            rule,
            request,
            user=None,
            targets_for_ask=["test-vm2", "test-vm3"],
            default_target=None,
            autostart=True,
        )
        with self.assertRaises(exc.AccessDenied) as e:
            resolution.handle_user_response(True, "test-no-dvm")
        self.assertTrue(e.exception.notify)

    def test_113_handle_user_response_deny_normal(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm @anyvm ask", filepath=Path("filename"), lineno=12
        )
        request = self.gen_req("test-vm1", "test-vm2")
        resolution = parser.AskResolution(
            rule,
            request,
            user=None,
            targets_for_ask=["test-vm1", "test-vm2"],
            default_target=None,
            autostart=True,
        )
        with self.assertRaises(exc.AccessDenied) as e:
            resolution.handle_user_response(False, "")
        self.assertFalse(e.exception.notify)

    def test_114_handle_user_response_deny_normal_notify(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm ask notify=yes",
            filepath=Path("filename"),
            lineno=12,
        )
        request = self.gen_req("test-vm1", "test-vm2")
        resolution = parser.AskResolution(
            rule,
            request,
            user=None,
            targets_for_ask=["test-vm1", "test-vm2"],
            default_target=None,
            autostart=True,
        )
        with self.assertRaises(exc.AccessDenied) as e:
            resolution.handle_user_response(False, "")
        self.assertTrue(e.exception.notify)

    def test_115_handle_user_response_with_default_target(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm ask default_target=test-vm2",
            filepath=Path("filename"),
            lineno=12,
        )
        request = self.gen_req("test-vm1", "test-vm2")
        resolution = parser.AskResolution(
            rule,
            request,
            user=None,
            targets_for_ask=["test-vm2", "test-vm3"],
            default_target="test-vm2",
            autostart=True,
        )
        resolution = resolution.handle_user_response(True, "test-vm2")
        self.assertIsInstance(resolution, parser.AllowResolution)
        self.assertEqual(resolution.target, "test-vm2")

    def test_120_execute(self):
        asyncio.run(self._test_120_execute())

    async def _test_120_execute(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = self.gen_req("test-vm1", "test-vm2")
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target="test-vm2",
            autostart=True,
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=test-vm2
target_uuid=uuid:b3eb69d0-f9d9-4c3c-ad5c-454500303ea4
autostart=True
requested_target=test-vm2\
""",
        )

    def test_121_execute_dom0(self):
        asyncio.run(self._test_121_execute_dom0())

    async def _test_121_execute_dom0(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm dom0 allow", filepath=Path("filename"), lineno=12
        )
        request = self.gen_req("test-vm1", "dom0")
        resolution = parser.AllowResolution(
            rule, request, user=None, target="dom0", autostart=True
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=dom0
autostart=True
requested_target=dom0\
""",
        )

    def test_121_execute_dom0_keyword(self):
        asyncio.run(self._test_121_execute_dom0_keyword())

    async def _test_121_execute_dom0_keyword(self):
        rule = parser.Rule.from_line(
            None, "* * @anyvm dom0 allow", filepath=Path("filename"), lineno=12
        )
        request = self.gen_req("test-vm1", "@adminvm")
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target="@adminvm",
            autostart=True,
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=dom0
autostart=True
requested_target=@adminvm\
""",
        )

    def test_122_execute_dispvm(self):
        asyncio.run(self._test_122_execute_dispvm())

    async def _test_122_execute_dispvm(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @dispvm:default-dvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = self.gen_req("test-vm1", "@dispvm:default-dvm")
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target=parser.DispVMTemplate("@dispvm:default-dvm"),
            autostart=True,
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=@dispvm:default-dvm
target_uuid=@dispvm:uuid:f3e538bd-4427-4697-bed7-45ef3270df21
autostart=True
requested_target=@dispvm:default-dvm\
""",
        )

    def test_123_execute_already_running(self):
        asyncio.run(self._test_123_execute_already_running())

    async def _test_123_execute_already_running(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @anyvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = self.gen_req("test-vm1", "test-vm2")
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target="test-vm2",
            autostart=True,
        )
        result = await resolution.execute()
        self.assertTrue(result.index("uuid:") != 0)
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=test-vm2
target_uuid=uuid:b3eb69d0-f9d9-4c3c-ad5c-454500303ea4
autostart=True
requested_target=test-vm2\
""",
        )

    def test_124_execute_local_to_remotevm_simple(self):
        asyncio.run(self._test_124_execute_local_to_remotevm_simple())

    async def _test_124_execute_local_to_remotevm_simple(self):
        rule = parser.Rule.from_line(
            None,
            "* * test-vm1 test-remotevm1 allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = self.gen_req("test-vm1", "test-remotevm1")
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target="test-remotevm1",
            autostart=True,
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=test-relayvm1
target_uuid=uuid:355304b8-bd5e-4699-9a2b-b6864fc26f6b
autostart=True
requested_target=test-remotevm1
service=qubesair.SSHProxy+test-remotevm1+test.Service+argument""",
        )

    # Verify that the policy program returns the requested source as policy_source.
    def test_125_valid_remote_to_local_allow_resolution(self):
        asyncio.run(self._test_125_valid_remote_to_local_allow_resolution())

    async def _test_125_valid_remote_to_local_allow_resolution(self):
        rule = parser.Rule.from_line(
            None,
            "* * test2-remotevm1 test2-vm1 allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = parser.Request(
            "qubes.SomeService",
            "+arg",
            "test2-relayvm1",
            "test2-vm1",
            system_info=self.system_info,
            requested_source="test2-remotevm1",
        )
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target="test2-vm1",
            autostart=True,
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=test2-vm1
target_uuid=uuid:c798d6db-360f-473a-b902-1cc58ffd3ab0
autostart=True
requested_target=test2-vm1
policy_source=test2-remotevm1""",
        )

    # Verify that a relay attempting to impersonate another relay raises an error.
    def test_126_relay_impersonating_another_relay_error(self):
        asyncio.run(self._test_126_relay_impersonating_another_relay_error())

    async def _test_126_relay_impersonating_another_relay_error(self):
        with self.assertRaises(exc.RequestError) as exc_info:
            parser.Request(
                "qubes.SomeService",
                "+arg",
                "test2-relayvm2",
                "test2-vm1",
                system_info=self.system_info,
                requested_source="test2-remotevm1",
            )
        self.assertEqual(
            str(exc_info.exception),
            "test2-relayvm2 is not a relay for test2-remotevm1",
        )

    # Verify that a relay attempting to impersonate a local VM raises an error.
    def test_127_relay_impersonating_localvm_error(self):
        asyncio.run(self._test_127_relay_impersonating_localvm_error())

    async def _test_127_relay_impersonating_localvm_error(self):
        with self.assertRaises(exc.RequestError) as exc_info:
            parser.Request(
                "qubes.SomeService",
                "+arg",
                "test2-relayvm1",
                "test2-vm1",
                system_info=self.system_info,
                requested_source="test-vm3",
            )
        self.assertEqual(
            str(exc_info.exception),
            "test-vm3: requested source is only authorized for RemoteVM",
        )

    def test_128_execute_remotevm_to_remotevm(self):
        asyncio.run(self._test_128_execute_remotevm_to_remotevm())

    async def _test_128_execute_remotevm_to_remotevm(self):
        rule = parser.Rule.from_line(
            None,
            "* * test2-remotevm1 test2-remotevm2 allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = parser.Request(
            "qubes.SomeService",
            "+arg",
            "test2-relayvm1",
            "test2-remotevm2",
            system_info=self.system_info,
            requested_source="test2-remotevm1",
        )
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target="test2-remotevm2",
            autostart=True,
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=test2-relayvm2
target_uuid=uuid:044767bb-081e-4260-b7be-35e77c36d510
autostart=True
requested_target=test2-remotevm2
service=qubesair.SSHProxy+test2-remotevm2+qubes.SomeService+arg
policy_source=test2-remotevm1""",
        )

    def test_129_execute_remote_to_dispvm(self):
        asyncio.run(self._test_129_execute_remote_to_dispvm())

    async def _test_129_execute_remote_to_dispvm(self):
        rule = parser.Rule.from_line(
            None,
            "* * @anyvm @dispvm:default-dvm allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = parser.Request(
            "qubes.SomeService",
            "+arg",
            "test-relayvm1",
            "@dispvm:default-dvm",
            system_info=self.system_info,
            requested_source="test-remotevm1",
        )
        resolution = parser.AllowResolution(
            rule,
            request,
            user=None,
            target=parser.DispVMTemplate("@dispvm:default-dvm"),
            autostart=True,
        )
        result = await resolution.execute()
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=@dispvm:default-dvm
target_uuid=@dispvm:uuid:f3e538bd-4427-4697-bed7-45ef3270df21
autostart=True
requested_target=@dispvm:default-dvm
policy_source=test-remotevm1""",
        )

    def test_130_execute_unexistent_source(self):
        asyncio.run(self._test_130_execute_unexistent_source())

    async def _test_130_execute_unexistent_source(self):
        with self.assertRaises(exc.RequestError) as exc_info:
            parser.Request(
                "qubes.SomeService",
                "+arg",
                "test-relayvm1",
                "test-remotevm1",
                system_info=self.system_info,
                requested_source="test-unexistent",
            )
        self.assertEqual(
            str(exc_info.exception),
            "unknown requested source qube 'test-unexistent'",
        )

    def test_131_execute_no_transport_rpc(self):
        asyncio.run(self._test_131_execute_no_transport_rpc())

    async def _test_131_execute_no_transport_rpc(self):
        system_info = deepcopy(_SYSTEM_INFO)
        del system_info["domains"]["test-remotevm1"]["transport_rpc"]

        rule = parser.Rule.from_line(
            None,
            "* * test-vm1 test-remotevm1 allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = parser.Request(
            "test.Service",
            "+argument",
            "test-vm1",
            "test-remotevm1",
            system_info=system_info,
        )
        with self.assertRaises(exc.AccessDenied) as exc_info:
            resolution = parser.AllowResolution(
                rule,
                request,
                user=None,
                target="test-remotevm1",
                autostart=True,
            )
            await resolution.execute()

        self.assertEqual(
            str(exc_info.exception),
            "test-remotevm1: transport RPC is not set",
        )

    def test_132_execute_no_relayvm(self):
        asyncio.run(self._test_132_execute_no_relayvm())

    async def _test_132_execute_no_relayvm(self):
        system_info = deepcopy(_SYSTEM_INFO)
        del system_info["domains"]["test-remotevm1"]["relayvm"]

        rule = parser.Rule.from_line(
            None,
            "* * test-vm1 test-remotevm1 allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = parser.Request(
            "test.Service",
            "+argument",
            "test-vm1",
            "test-remotevm1",
            system_info=system_info,
        )
        with self.assertRaises(exc.AccessDenied) as exc_info:
            resolution = parser.AllowResolution(
                rule,
                request,
                user=None,
                target="test-remotevm1",
                autostart=True,
            )
            await resolution.execute()

        self.assertEqual(
            str(exc_info.exception),
            "test-remotevm1: relayvm is not set",
        )

    def test_133_execute_loopback(self):
        asyncio.run(self._test_133_execute_loopback())

    async def _test_133_execute_loopback(self):
        rule = parser.Rule.from_line(
            None,
            "* * test-vm1 test-remotevm1 allow",
            filepath=Path("filename"),
            lineno=12,
        )
        request = parser.Request(
            "test.Service",
            "+argument",
            "test-vm1",
            "test-vm1",
            system_info=self.system_info,
        )
        with self.assertRaises(exc.AccessDenied) as exc_info:
            resolution = parser.AllowResolution(
                rule,
                request,
                user=None,
                target="test-vm1",
                autostart=True,
            )
            await resolution.execute()

        self.assertEqual(
            str(exc_info.exception),
            "loopback qrexec connection not supported",
        )

    @unittest.mock.patch("qrexec.policy.parser.logging")
    def test_134_execute_localvm_to_remotevm_with_user(self, mock_logger):
        asyncio.run(
            self._test_134_execute_localvm_to_remotevm_with_user(mock_logger)
        )

    async def _test_134_execute_localvm_to_remotevm_with_user(
        self, mock_logger
    ):
        rule = parser.Rule.from_line(
            None,
            "* * test-vm1 test-remotevm1 allow user=toto",
            filepath=Path("filename"),
            lineno=12,
        )
        request = self.gen_req("test-vm1", "test-remotevm1")
        # specify "toto" user
        resolution = parser.AllowResolution(
            rule,
            request,
            user="toto",
            target="test-remotevm1",
            autostart=True,
        )
        result = await resolution.execute()

        # check that we get a warning
        mock_logger.warning.assert_called_once_with(
            "Ignoring user directive in policy. This is not supported in the case of RemoveVM."
        )

        # check that user remains DEFAULT
        self.assertEqual(
            result,
            """\
user=DEFAULT
result=allow
target=test-relayvm1
target_uuid=uuid:355304b8-bd5e-4699-9a2b-b6864fc26f6b
autostart=True
requested_target=test-remotevm1
service=qubesair.SSHProxy+test-remotevm1+test.Service+argument""",
        )


# class TC_30_Misc(qubes.tests.QubesTestCase):
class TC_50_Misc(ParserTestCase):
    @unittest.mock.patch("socket.socket")
    def test_000_qubesd_call(self, mock_socket):
        mock_config = {
            "return_value.makefile.return_value.read.return_value": b"0\x00data"
        }
        mock_socket.configure_mock(**mock_config)
        result = utils.qubesd_call("test", "internal.method")
        self.assertEqual(result, b"data")
        self.assertEqual(
            mock_socket.mock_calls,
            [
                unittest.mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
                unittest.mock.call().connect(QUBESD_INTERNAL_SOCK),
                unittest.mock.call().sendall(
                    b"internal.method+ dom0 name test\0"
                ),
                unittest.mock.call().shutdown(socket.SHUT_WR),
                unittest.mock.call().makefile("rb"),
                unittest.mock.call().makefile().read(),
            ],
        )

    @unittest.mock.patch("socket.socket")
    def test_001_qubesd_call_arg_payload(self, mock_socket):
        mock_config = {
            "return_value.makefile.return_value.read.return_value": b"0\x00data"
        }
        mock_socket.configure_mock(**mock_config)
        result = utils.qubesd_call("test", "internal.method", "arg", b"payload")
        self.assertEqual(result, b"data")
        self.assertEqual(
            mock_socket.mock_calls,
            [
                unittest.mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
                unittest.mock.call().connect(QUBESD_INTERNAL_SOCK),
                unittest.mock.call().sendall(
                    b"internal.method+arg dom0 name test\0"
                ),
                unittest.mock.call().sendall(b"payload"),
                unittest.mock.call().shutdown(socket.SHUT_WR),
                unittest.mock.call().makefile("rb"),
                unittest.mock.call().makefile().read(),
            ],
        )

    @unittest.mock.patch("socket.socket")
    def test_002_qubesd_call_exception(self, mock_socket):
        mock_config = {
            "return_value.makefile.return_value.read.return_value": b"2\x00SomeError\x00traceback\x00message\x00"
        }
        mock_socket.configure_mock(**mock_config)
        with self.assertRaises(exc.QubesMgmtException) as err:
            utils.qubesd_call("test", "internal.method")
        self.assertEqual(err.exception.exc_type, "SomeError")
        self.assertEqual(
            mock_socket.mock_calls,
            [
                unittest.mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
                unittest.mock.call().connect(QUBESD_INTERNAL_SOCK),
                unittest.mock.call().sendall(
                    b"internal.method+ dom0 name test\0"
                ),
                unittest.mock.call().shutdown(socket.SHUT_WR),
                unittest.mock.call().makefile("rb"),
                unittest.mock.call().makefile().read(),
            ],
        )


class TC_90_Compat40(ParserTestCase):
    def test_001_loader(self):
        policy = parser.StringPolicy(
            policy={"__main__": "!compat-4.0"},
            policy_compat={"test.Allow": "$anyvm $anyvm allow"},
        )
        policy.evaluate(
            parser.Request(
                "test.Allow",
                "+",
                "test-vm1",
                "test-vm2",
                system_info=self.system_info,
            )
        )

    def test_100_implicit_deny(self):
        policy = parser.StringPolicy(
            policy={
                "__main__": """
                test.AllowBefore    * @anyvm @anyvm allow
                !compat-4.0
                test.AllowAfter     * @anyvm @anyvm allow
                test.ImplicitDeny   * @anyvm @anyvm allow
            """
            },
            policy_compat={
                "test.AllowAfter": """
                    test-vm1 test-vm2 allow
                """,
                "test.ImplicitDeny+arg": """
                    test-vm1 test-vm2 allow
                """,
            },
        )

        policy.evaluate(
            parser.Request(
                "test.AllowAfter",
                "+",
                "test-vm1",
                "test-vm2",
                system_info=self.system_info,
            )
        )
        policy.evaluate(
            parser.Request(
                "test.AllowAfter",
                "+",
                "test-vm1",
                "test-vm3",
                system_info=self.system_info,
            )
        )

        with self.assertRaises(exc.AccessDenied):
            policy.evaluate(
                parser.Request(
                    "test.ImplicitDeny",
                    "+arg",
                    "test-vm1",
                    "test-vm3",
                    system_info=self.system_info,
                )
            )
