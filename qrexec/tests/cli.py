#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
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

from unittest import mock
from pathlib import PosixPath

import asynctest
import pytest

from ..exc import AccessDenied
from ..tools import qrexec_policy_exec

# Disable warnings that conflict with Pytest's use of fixtures.
# pylint: disable=redefined-outer-name, unused-argument


class TestPolicy:
    def __init__(self):
        self.resolution_type = None
        self.targets_for_ask = None
        self.default_target = None
        self.target = None
        self.rule = mock.NonCallableMock()
        self.rule.filepath = 'file'
        self.rulelineno = 42

    def set_ask(self, targets_for_ask, default_target=None):
        self.resolution_type = 'ask'
        self.targets_for_ask = targets_for_ask
        self.default_target = default_target

    def set_allow(self, target):
        self.resolution_type = 'allow'
        self.target = target

    def set_deny(self):
        self.resolution_type = 'deny'

    def evaluate(self, request):
        assert self.resolution_type is not None

        if self.resolution_type == 'ask':
            return request.ask_resolution_type(
                self.rule, request, user='user',
                targets_for_ask=self.targets_for_ask,
                default_target=self.default_target)

        if self.resolution_type == 'allow':
            return request.allow_resolution_type(
                self.rule, request, user='user', target=self.target)

        if self.resolution_type == 'deny':
            raise AccessDenied('denied')

        assert False, self.resolution_type
        return None


@pytest.fixture
def policy():
    """
    Mock for FilePolicy object that will evaluate the requests.
    """

    policy = TestPolicy()
    with mock.patch('qrexec.policy.parser.FilePolicy') as mock_policy:
        mock_policy.return_value = policy
        yield policy

    assert mock_policy.mock_calls == [
        mock.call(policy_path=PosixPath('/etc/qubes/policy.d'))
    ]


@pytest.fixture
def system_info():
    system_info = {
        'domains': {
            'dom0': {'icon': 'black', 'template_for_dispvms': False},
            'test-vm1': {'icon': 'red', 'template_for_dispvms': False},
            'test-vm2': {'icon': 'red', 'template_for_dispvms': False},
            'test-vm3': {'icon': 'green', 'template_for_dispvms': True},
        }
    }
    with mock.patch('qrexec.utils.get_system_info') as mock_system_info:
        mock_system_info.return_value = system_info
        yield system_info


@pytest.fixture
def icons(system_info):
    return {
        'dom0': 'black',
        'test-vm1': 'red',
        'test-vm2': 'red',
        'test-vm3': 'green',
        '@dispvm:test-vm3': 'green',
    }


@pytest.fixture
def execute():
    """
    Mock for execute() for allowed action. It is supposed to call the qrexec.
    """

    with mock.patch('qrexec.policy.parser.AllowResolution.execute',
                    asynctest.CoroutineMock()) as mock_execute:
        yield mock_execute


@pytest.fixture
def dbus_ask():
    """
    Mock for Ask() method forwarded to the qrexec-policy-agent.
    """

    dbus_ask = mock.MagicMock()
    with mock.patch('pydbus.SystemBus') as mock_dbus:
        mock_dbus.return_value.get.return_value.Ask = dbus_ask
        yield dbus_ask


def test_000_allow(system_info, policy, execute):
    policy.set_allow('test-vm1')
    retval = qrexec_policy_exec.main(
        ['source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 0
    assert execute.mock_calls == [
        mock.call('process_ident,source,source-id'),
    ]


def test_010_ask_allow(system_info, icons, policy, dbus_ask, execute):
    policy.set_ask(['test-vm1', 'test-vm2'])
    dbus_ask.return_value = 'test-vm1'
    retval = qrexec_policy_exec.main(
        ['source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 0
    assert dbus_ask.mock_calls == [
        mock.call('source', 'service', ['test-vm1', 'test-vm2'], '', icons),
    ]
    assert execute.mock_calls == [
        mock.call('process_ident,source,source-id'),
    ]


def test_011_ask_deny(system_info, icons, policy, dbus_ask, execute):
    policy.set_ask(['test-vm1', 'test-vm2'])
    dbus_ask.return_value = ''
    retval = qrexec_policy_exec.main(
        ['source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 1
    assert dbus_ask.mock_calls == [
        mock.call('source', 'service', ['test-vm1', 'test-vm2'], '', icons),
    ]
    assert execute.mock_calls == []


def test_012_default_target(system_info, icons, policy, dbus_ask, execute):
    policy.set_ask(['test-vm1', 'test-vm2'], 'test-vm1')
    dbus_ask.return_value = 'test-vm1'
    retval = qrexec_policy_exec.main(
        ['source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 0
    assert dbus_ask.mock_calls == [
        mock.call('source', 'service', ['test-vm1', 'test-vm2'], 'test-vm1',
                  icons),
    ]
    assert execute.mock_calls == [
        mock.call('process_ident,source,source-id'),
    ]


def test_020_deny(system_info, policy, execute):
    policy.set_deny()
    retval = qrexec_policy_exec.main(
        ['source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 1
    assert execute.mock_calls == []


def test_030_just_evaluate_allow(system_info, policy, execute):
    policy.set_allow('test-vm1')
    retval = qrexec_policy_exec.main(
        ['--just-evaluate',
         'source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 0
    assert execute.mock_calls == []


def test_031_just_evaluate_deny(system_info, policy, execute):
    policy.set_deny()
    retval = qrexec_policy_exec.main(
        ['--just-evaluate',
         'source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 1
    assert execute.mock_calls == []


def test_032_just_evaluate_ask(system_info, policy, execute):
    policy.set_ask(['test-vm1', 'test-vm2'])
    retval = qrexec_policy_exec.main(
        ['--just-evaluate',
         'source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 1
    assert execute.mock_calls == []


def test_033_just_evaluate_ask_assume_yes(system_info, policy, execute):
    policy.set_ask(['test-vm1', 'test-vm2'])
    retval = qrexec_policy_exec.main(
        ['--just-evaluate', '--assume-yes-for-ask',
         'source-id', 'source', 'test-vm1', 'service', 'process_ident'])
    assert retval == 0
    assert execute.mock_calls == []
