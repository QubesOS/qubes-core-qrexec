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

from ..policy.admin import PolicyAdmin, PolicyAdminException

# Disable warnings that conflict with Pytest's use of fixtures.
# pylint: disable=redefined-outer-name



@pytest.fixture
def policy_dir():
    with tempfile.TemporaryDirectory() as dir_name:
        policy_dir = Path(dir_name)
        (policy_dir / 'include').mkdir()
        yield policy_dir


@pytest.fixture
def api(policy_dir):
    return PolicyAdmin(policy_dir)


def test_api_list(policy_dir, api):
    (policy_dir / 'file1.policy').touch()
    (policy_dir / 'file2.policy').touch()
    (policy_dir / 'file3').touch()

    assert api.handle_request('policy.List', '', b'') == \
        b'file1.policy\nfile2.policy\n'

    (policy_dir / 'include/inc').touch()

    assert api.handle_request('policy.List', '', b'') == \
        b'file1.policy\nfile2.policy\ninclude++inc\n'


def test_api_get(policy_dir, api):
    (policy_dir / 'file1.policy').write_text('policy text')

    assert api.handle_request('policy.Get', 'file1.policy', b'') == \
        b'policy text'

    (policy_dir / 'include/inc').write_text('include text')

    assert api.handle_request('policy.Get', 'include++inc', b'') == \
        b'include text'

    with pytest.raises(PolicyAdminException,
                       match='Not found'):
        api.handle_request('policy.Get', 'nonexistent.policy', b'')


def test_get_path(policy_dir, api):
    (policy_dir / 'file1').touch()
    (policy_dir / 'file1.policy').touch()
    (policy_dir / 'include/inc').touch()

    assert api.get_path('file1.policy') == policy_dir / 'file1.policy'
    assert api.get_path('include++inc') == policy_dir / 'include/inc'

    with pytest.raises(PolicyAdminException,
                       match="File name doesn't end with .policy"):
        api.get_path('file1')

    with pytest.raises(PolicyAdminException,
                       match='Expecting a path inside'):
        api.get_path('..')

    with pytest.raises(PolicyAdminException,
                       match='Expecting a path inside'):
        api.get_path('include++..')


def test_api_replace(policy_dir, api):
    api.handle_request('policy.Replace', 'file1.policy', b'')
    assert (policy_dir / 'file1.policy').read_text() == ''

    api.handle_request('policy.Replace', 'file1.policy', b'rpc.Name * * * deny')
    assert (policy_dir / 'file1.policy').read_text() == 'rpc.Name * * * deny'

    api.handle_request('policy.Replace', 'include++inc', b'rpc.Name * * * deny')
    assert (policy_dir / 'include/inc').read_text() == 'rpc.Name * * * deny'

    api.handle_request('policy.Replace', 'file1.policy', b'!include include/inc')


def test_api_replace_validate(api):
    with pytest.raises(PolicyAdminException,
                       match='wrong number of fields'):
        api.handle_request('policy.Replace', 'file1.policy', b'xxx')

    # Trying to include a nonexistent file
    with pytest.raises(PolicyAdminException,
                       match='not a file'):
        api.handle_request('policy.Replace', 'file1.policy', b'!include include/inc')

    # File that can be included, but not using !include-service
    api.handle_request('policy.Replace', 'include++inc', b'rpc.Name * * * deny')
    api.handle_request('policy.Replace', 'file1.policy', b'!include include/inc')
    with pytest.raises(PolicyAdminException,
                       match='invalid number of params'):
        api.handle_request('policy.Replace', 'file1.policy', b'!include-service include/inc')


def test_api_remove(policy_dir, api):
    (policy_dir / 'file1.policy').touch()
    (policy_dir / 'include/inc').touch()

    api.handle_request('policy.Remove', 'file1.policy', b'')
    assert not (policy_dir / 'file1.policy').exists()

    api.handle_request('policy.Remove', 'include++inc', b'')
    assert not (policy_dir / 'include/inc').exists()


def test_api_remove_validate(policy_dir, api):
    (policy_dir / 'file1.policy').write_text('!include include/inc')
    (policy_dir / 'include/inc').touch()

    with pytest.raises(PolicyAdminException,
                       match='including a file that will be removed'):
        api.handle_request('policy.Remove', 'include++inc', b'')
