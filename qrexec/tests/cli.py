#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
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
import tempfile
import unittest.mock
from pathlib import PosixPath

from .. import utils
from ..policy import parser
from ..tools import qrexec_policy_exec


class TC_00_qrexec_policy(unittest.TestCase):
    def setUp(self):
        super(TC_00_qrexec_policy, self).setUp()
        self.system_info = {
            'domains': {'dom0': {'icon': 'black', 'template_for_dispvms': False},
                'test-vm1': {'icon': 'red', 'template_for_dispvms': False},
                'test-vm2': {'icon': 'red', 'template_for_dispvms': False},
                'test-vm3': {'icon': 'green', 'template_for_dispvms': True}, }}

        self.policy_patch = unittest.mock.patch(
            'qrexec.policy.parser.FilePolicy')
        self.policy_mock = self.policy_patch.start()
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.return_value.execute.return_value': None
        })

        self.request_patch = unittest.mock.patch(
            'qrexec.policy.parser.Request')
        self.request_mock = self.request_patch.start()
        self.request_mock.configure_mock(**{
            'return_value.source': 'source',
            'return_value.intended_target': 'target',
            'return_value.service': 'service',
            'return_value.argument': 'argument',
            'return_value.system_info': self.system_info,
        })

        self.system_info_patch = unittest.mock.patch(
            'qrexec.utils.get_system_info')
        self.system_info_mock = self.system_info_patch.start()

        self.system_info_mock.return_value = self.system_info

        self.dbus_patch = unittest.mock.patch('pydbus.SystemBus')
        self.dbus_mock = self.dbus_patch.start()

        self.policy_dir = tempfile.TemporaryDirectory()
        self.policydir_patch = unittest.mock.patch('qrexec.POLICYPATH',
            self.policy_dir.name)
        self.policydir_patch.start()

    def tearDown(self):
        self.policydir_patch.stop()
        self.policy_dir.cleanup()
        self.dbus_patch.start()
        self.system_info_patch.stop()
        self.request_patch.stop()
        self.policy_patch.stop()
        super(TC_00_qrexec_policy, self).tearDown()

    def test_000_allow(self):
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.return_value.action':
                parser.Action.allow,
        })
        retval = qrexec_policy_exec.main(
            ['--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 0)
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
            ('().evaluate().execute', ('process_ident,source,source-id', ), {}),
            ('().evaluate().target.__str__', (), {}),
        ])
        # remove call used above:
        del self.request_mock.mock_calls[-1]
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.DBusAskResolution,
                'allow_resolution_type': parser.AllowResolution,
            })
        ])
        self.assertEqual(self.dbus_mock.mock_calls, [])

    def test_010_ask_allow(self):
        rule_mock = unittest.mock.Mock()
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.side_effect':
                lambda req: qrexec_policy_exec.DBusAskResolution(rule_mock, req,
                    targets_for_ask=['test-vm1', 'test-vm2'],
                    default_target=None,
                    user=None),
        })
        self.dbus_mock.configure_mock(**{
            'return_value.get.return_value.Ask.return_value': 'test-vm1'
        })
        retval = qrexec_policy_exec.main(
            ['--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 0)
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
        ])
        # remove call used above:
        del self.request_mock.mock_calls[-1]
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.DBusAskResolution,
                'allow_resolution_type': parser.AllowResolution,
            }),
            ('().allow_resolution_type.from_ask_resolution',
                (unittest.mock.ANY, ), {'target': 'test-vm1'}),
            ('().allow_resolution_type.from_ask_resolution().execute',
                ('process_ident,source,source-id', ), {}),
            ('().allow_resolution_type.from_ask_resolution().execute().target.__str__', (), {})
        ])
        icons = {
            'dom0': 'black',
            'test-vm1': 'red',
            'test-vm2': 'red',
            'test-vm3': 'green',
            '@dispvm:test-vm3': 'green',
        }
        self.assertEqual(self.dbus_mock.mock_calls, [
            ('', (), {}),
            ('().get', ('org.qubesos.PolicyAgent',
                '/org/qubesos/PolicyAgent'), {}),
            ('().get().Ask', ('source', 'service', ['test-vm1', 'test-vm2'],
            '', icons), {}),
        ])

    def test_011_ask_deny(self):
        rule_mock = unittest.mock.Mock()
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.side_effect':
                lambda req: qrexec_policy_exec.DBusAskResolution(rule_mock, req,
                    targets_for_ask=['test-vm1', 'test-vm2'],
                    default_target=None,
                    user=None),
        })
        self.dbus_mock.configure_mock(**{
            'return_value.get.return_value.Ask.return_value': ''
        })
        retval = qrexec_policy_exec.main(
            ['--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 1)
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
        ])
        # remove call used above:
        del self.request_mock.mock_calls[-1]
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.DBusAskResolution,
                'allow_resolution_type': parser.AllowResolution,
            }),
        ])
        icons = {
            'dom0': 'black',
            'test-vm1': 'red',
            'test-vm2': 'red',
            'test-vm3': 'green',
            '@dispvm:test-vm3': 'green',
        }
        self.assertEqual(self.dbus_mock.mock_calls, [
            ('', (), {}),
            ('().get', ('org.qubesos.PolicyAgent',
                '/org/qubesos/PolicyAgent'), {}),
            ('().get().Ask', ('source', 'service', ['test-vm1', 'test-vm2'],
            '', icons), {}),
        ])

    def test_012_ask_default_target(self):
        rule_mock = unittest.mock.Mock()
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.side_effect':
                lambda req: qrexec_policy_exec.DBusAskResolution(rule_mock, req,
                    targets_for_ask=['test-vm1', 'test-vm2'],
                    default_target='test-vm1',
                    user=None),
        })
        self.dbus_mock.configure_mock(**{
            'return_value.get.return_value.Ask.return_value': 'test-vm1'
        })
        retval = qrexec_policy_exec.main(
            ['--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 0)
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
        ])
        # remove call used above:
        del self.request_mock.mock_calls[-1]
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.DBusAskResolution,
                'allow_resolution_type': parser.AllowResolution,
            }),
            ('().allow_resolution_type.from_ask_resolution',
                (unittest.mock.ANY, ), {'target': 'test-vm1'}),
            ('().allow_resolution_type.from_ask_resolution().execute',
                ('process_ident,source,source-id', ), {}),
            ('().allow_resolution_type.from_ask_resolution().execute().target.__str__', (), {})
        ])
        icons = {
            'dom0': 'black',
            'test-vm1': 'red',
            'test-vm2': 'red',
            'test-vm3': 'green',
            '@dispvm:test-vm3': 'green',
        }
        self.assertEqual(self.dbus_mock.mock_calls, [
            ('', (), {}),
            ('().get', ('org.qubesos.PolicyAgent',
                '/org/qubesos/PolicyAgent'), {}),
            ('().get().Ask', ('source', 'service', ['test-vm1', 'test-vm2'],
            'test-vm1', icons), {}),
        ])

    def test_020_deny(self):
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.return_value.action':
                parser.Action.deny,
            'return_value.evaluate.return_value.execute.side_effect':
                parser.AccessDenied,
        })
        retval = qrexec_policy_exec.main(
            ['--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 1)
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
            ('().evaluate().execute', ('process_ident,source,source-id',), {}),
        ])
        # remove call used above:
        del self.request_mock.mock_calls[-1]
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.DBusAskResolution,
                'allow_resolution_type': parser.AllowResolution,
            }),
        ])
        self.assertEqual(self.dbus_mock.mock_calls, [])

    def test_030_just_evaluate_allow(self):
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.return_value.action':
                parser.Action.allow,
        })
        retval = qrexec_policy_exec.main(
            ['--just-evaluate',
             '--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 0)
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
            ('().evaluate().execute', ('process_ident,source,source-id',), {}),
            ('().evaluate().target.__str__', (), {}),
        ])
        # remove call used above:
        del self.request_mock.mock_calls[-1]
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.JustEvaluateAskResolution,
                'allow_resolution_type': qrexec_policy_exec.JustEvaluateAllowResolution,
            }),
        ])
        self.assertEqual(self.dbus_mock.mock_calls, [])

    def test_031_just_evaluate_deny(self):
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.return_value.action':
                parser.Action.deny,
            'return_value.evaluate.return_value.execute.side_effect':
                parser.AccessDenied,
        })
        retval = qrexec_policy_exec.main(
            ['--just-evaluate',
             '--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 1)
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
            ('().evaluate().execute', ('process_ident,source,source-id',), {}),
        ])
        # remove call used above:
        del self.request_mock.mock_calls[-1]
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.JustEvaluateAskResolution,
                'allow_resolution_type': qrexec_policy_exec.JustEvaluateAllowResolution,
            }),
        ])
        self.assertEqual(self.dbus_mock.mock_calls, [])

    def test_032_just_evaluate_ask(self):
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.return_value.action':
                parser.Action.ask,
            'return_value.evaluate.return_value.execute.side_effect':
                parser.AccessDenied,
        })
        retval = qrexec_policy_exec.main(
            ['--just-evaluate',
             '--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 1)
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.JustEvaluateAskResolution,
                'allow_resolution_type': qrexec_policy_exec.JustEvaluateAllowResolution,
            }),
        ])
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
            ('().evaluate().execute', ('process_ident,source,source-id',), {}),
        ])
        self.assertEqual(self.dbus_mock.mock_calls, [])

    def test_033_just_evaluate_ask_assume_yes(self):
        self.policy_mock.configure_mock(**{
            'return_value.evaluate.return_value.action':
                parser.Action.ask,
        })
        retval = qrexec_policy_exec.main(
            ['--just-evaluate', '--assume-yes-for-ask',
             '--path=' + self.policy_dir.name,
             'source-id', 'source', 'target', 'service', 'process_ident'])
        self.assertEqual(retval, 0)
        self.assertEqual(self.request_mock.mock_calls, [
            ('', ('service', '+', 'source', 'target'), {
                'system_info': self.system_info,
                'ask_resolution_type': qrexec_policy_exec.AssumeYesForAskResolution,
                'allow_resolution_type': qrexec_policy_exec.JustEvaluateAllowResolution,
            }),
        ])
        self.assertEqual(self.policy_mock.mock_calls, [
            ('', (), {'policy_path': PosixPath(self.policy_dir.name)}),
            ('().evaluate', (self.request_mock(),), {}),
            ('().evaluate().execute', ('process_ident,source,source-id', ), {}),
            ('().evaluate().target.__str__', (), {}),
        ])
        self.assertEqual(self.dbus_mock.mock_calls, [])
