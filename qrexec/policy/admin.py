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

from typing import Optional
from pathlib import Path
import contextlib
import fcntl
import os
import string

from .parser import ValidateParser
from ..exc import PolicySyntaxError


class PolicyAdminException(Exception):
    '''
    An exception with message to the user.
    '''


def method(service_name, *, no_arg=False, no_payload=False):
    def decorator(func):
        func.api_service_name = service_name
        func.api_no_arg = no_arg
        func.api_no_payload = no_payload
        return func
    return decorator


# Characters allowed as part of RPC name.
# See sanitize_name() in core-admin-linux/qrexec/qrexec-daemon.c
ALLOWED_CHARS = set(
    string.ascii_uppercase +
    string.ascii_lowercase +
    string.digits +
    '+-._')

RENAME_PREFIX = '!'


class PolicyAdmin:
    '''
    A class that implements Qubes RPC interface for policy administration.

    Paths in include/ directory are supported when the argument has 'include++'
    prefix.

    All changes (Replace / Remove) are be validated to check if they will not
    introduce errors: (syntax error, removing a file that is still included,
    including a file in wrong context, etc.)
    '''

    def __init__(self, policy_path):
        self.policy_path = policy_path
        self.include_path = policy_path / 'include'
        self.include_prefix = 'include++'

    def handle_request(self, service_name: str, arg: str, payload: bytes) \
        -> Optional[bytes]:
        '''
        Handle a QubesRPC request with the right parameters.

        Throws PolicyAdminException in case of user error.
        '''

        assert all(char in ALLOWED_CHARS for char in arg)

        func = self._find_method(service_name)
        if not func:
            raise PolicyAdminException(
                'unrecognized method: {}'.format(service_name))

        args = []

        if func.api_no_arg:
            if arg != '':
                raise PolicyAdminException('Unexpected argument')
        else:
            args.append(arg)

        if func.api_no_payload:
            if payload != b'':
                raise PolicyAdminException('Unexpected payload')
        else:
            args.append(payload)

        with self._lock():
            return func(*args)

    def _find_method(self, service_name):
        for attr in dir(self):
            func = getattr(self, attr)
            if callable(func) and hasattr(func, 'api_service_name'):
                if func.api_service_name == service_name:
                    return func

        return None

    @contextlib.contextmanager
    def _lock(self):
        '''
        Acquire an exclusive lock to policy directory.
        '''

        lock_fd = os.open(str(self.policy_path), os.O_DIRECTORY)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(lock_fd)

    @method('policy.List', no_arg=True, no_payload=True)
    def policy_list(self):
        names = []
        for file_path in self.policy_path.iterdir():
            if file_path.is_file() and file_path.name.endswith('.policy'):
                names.append(file_path.name)

        if self.include_path.is_dir():
            for file_path in self.include_path.iterdir():
                if file_path.is_file():
                    names.append(self.include_prefix + file_path.name)

        names.sort()
        return ''.join(name + '\n' for name in names).encode('ascii')

    @method('policy.Get', no_payload=True)
    def policy_get(self, arg):
        path = self.get_path(arg)

        if not path.is_file():
            raise PolicyAdminException('Not found: {}'.format(path))

        return path.read_bytes()

    @method('policy.Replace')
    def policy_replace(self, arg, payload):
        path = self.get_path(arg)
        temp_path = path.with_name(RENAME_PREFIX + path.name)

        content = payload.decode('utf-8')
        self._validate(path, content)

        temp_path.write_bytes(payload)
        temp_path.rename(path)

    @method('policy.Remove', no_payload=True)
    def policy_remove(self, arg):
        path = self.get_path(arg)
        if not path.is_file:
            raise PolicyAdminException('Not found: {}'.format(path))

        self._validate(path, None)

        path.unlink()

    def get_path(self, arg: str) -> Path:
        if arg.startswith(self.include_prefix):
            path = self.include_path / arg[len(self.include_prefix):]
            path = path.resolve()
            if path.parent != self.include_path:
                raise PolicyAdminException('Expecting a path inside {}'.format(
                    self.include_path))
        else:
            path = self.policy_path / arg
            path = path.resolve()
            if path.parent != self.policy_path:
                raise PolicyAdminException('Expecting a path inside {}'.format(
                    self.policy_path))
            if not path.name.endswith('.policy'):
                raise PolicyAdminException("File name doesn't end with .policy")

        return path

    def _validate(self, path: Path, content: Optional[str]):
        try:
            ValidateParser(
                policy_path=self.policy_path,
                overrides={path: content})
        except PolicySyntaxError as exc:
            raise PolicyAdminException(
                'Policy change validation failed: {}'.format(exc))
