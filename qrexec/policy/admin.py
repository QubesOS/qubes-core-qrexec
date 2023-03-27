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

from __future__ import annotations
from typing import Optional
from pathlib import Path
import contextlib
import fcntl
import os
import hashlib

from .parser import ValidateParser, FilePolicy, get_invalid_characters
from ..exc import PolicySyntaxError
from .. import RPCNAME_ALLOWED_CHARSET


class PolicyAdminException(Exception):
    """
    An exception with message to the user.
    """


class PolicyAdminTokenException(Exception):
    """
    A token check exception, indicating that a file is in unexpected state.
    """


def method(service_name, *, no_arg=False, no_payload=False):
    def decorator(func):
        func.api_service_name = service_name
        func.api_no_arg = no_arg
        func.api_no_payload = no_payload
        return func

    return decorator


RENAME_PREFIX = "!"


class PolicyAdmin:
    """
    A class that implements Qubes RPC interface for policy administration.

    All changes (Replace / Remove) are be validated to check if they will not
    introduce errors: (syntax error, removing a file that is still included,
    including a file in wrong context, etc.)

    The API optionally uses tokens (currently, SHA256 hashes) to prevent race
    conditions when removing or replacing a file. The Get calls returns the
    token as the first output line.  The Remove and Replace calls take token as
    first line of payload, or one of special values: "new" when the file is not
    supposed to be there, "any" when the client doesn't want a token to be
    checked.
    """

    # pylint: disable=no-self-use

    def __init__(self, policy_path):
        self.policy_path = policy_path
        self.include_path = policy_path / "include"

    def handle_request(
        self, service_name: str, arg: str, payload: bytes
    ) -> Optional[bytes]:
        """
        Handle a QubesRPC request with the right parameters.

        Throws PolicyAdminException in case of user error.
        """

        assert all(char in RPCNAME_ALLOWED_CHARSET for char in arg)

        func = self._find_method(service_name)
        if not func:
            raise PolicyAdminException(
                "unrecognized method: {}".format(service_name)
            )

        args = []

        if func.api_no_arg:
            if arg != "":
                raise PolicyAdminException("Unexpected argument")
        else:
            args.append(arg)

        if func.api_no_payload:
            if payload != b"":
                raise PolicyAdminException("Unexpected payload")
        else:
            args.append(payload)

        with self._lock():
            return func(*args)

    def _find_method(self, service_name):
        for attr in dir(self):
            func = getattr(self, attr)
            if callable(func) and hasattr(func, "api_service_name"):
                if func.api_service_name == service_name:
                    return func

        return None

    @contextlib.contextmanager
    def _lock(self):
        """
        Acquire an exclusive lock to policy directory.
        """

        lock_fd = os.open(str(self.policy_path), os.O_DIRECTORY)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(lock_fd)

    # List

    @method("policy.List", no_arg=True, no_payload=True)
    def policy_list(self):
        return self._common_list(self.policy_path, ".policy")

    @method("policy.include.List", no_arg=True, no_payload=True)
    def policy_include_list(self):
        return self._common_list(self.include_path, "")

    def _common_list(self, dir_path: Path, suffix: str) -> bytes:
        names = []
        for file_path in dir_path.iterdir():
            if file_path.is_file():
                name = file_path.name
                if suffix and name.endswith(suffix):
                    name = name[: -len(suffix)]
                    names.append(name)
                elif not suffix:
                    names.append(name)

        names.sort()
        return "".join(name + "\n" for name in names).encode("ascii")

    # Get

    @method("policy.Get", no_payload=True)
    def policy_get(self, arg):
        path = self._get_path(arg, self.policy_path, ".policy")
        return self._common_get(path)

    @method("policy.include.Get", no_payload=True)
    def policy_include_get(self, arg):
        path = self._get_path(arg, self.include_path, "")
        return self._common_get(path)

    def _common_get(self, path: Path) -> bytes:
        if not path.is_file():
            raise PolicyAdminException("Not found: {}".format(path))

        data = path.read_bytes()
        token = compute_token(data)
        return token + b"\n" + data

    # Replace

    @method("policy.Replace")
    def policy_replace(self, arg, payload):
        path = self._get_path(arg, self.policy_path, ".policy")
        return self._common_replace(path, payload)

    @method("policy.include.Replace")
    def policy_include_replace(self, arg, payload):
        path = self._get_path(arg, self.include_path, "")
        return self._common_replace(path, payload)

    def _common_replace(self, path: Path, payload: bytes) -> bytes:
        if b"\n" not in payload:
            raise PolicyAdminException(
                "Payload needs to include first line with token"
            )
        token, data = payload.split(b"\n", 1)
        self._check_token(token, path)

        data_string = data.decode("utf-8")
        self._validate(path, data_string)

        temp_path = path.with_name(RENAME_PREFIX + path.name)
        temp_path.write_bytes(data)
        temp_path.rename(path)

    # Remove

    @method("policy.Remove")
    def policy_remove(self, arg, payload):
        path = self._get_path(arg, self.policy_path, ".policy")
        return self._common_remove(path, payload)

    @method("policy.include.Remove")
    def policy_include_remove(self, arg, payload):
        path = self._get_path(arg, self.include_path, "")
        return self._common_remove(path, payload)

    def _common_remove(self, path: Path, payload: str) -> None:
        self._check_token(payload, path)

        if not path.is_file():
            raise PolicyAdminException("Not found: {}".format(path))

        self._validate(path, None)

        path.unlink()

    # List files

    @method("policy.GetFiles", no_payload=True)
    def policy_get_files(self, arg):
        if not isinstance(arg, str) or not arg:
            raise PolicyAdminException('Service cannot be empty.')
        invalid_chars = get_invalid_characters(arg, disallowed="+")
        if invalid_chars:
            raise PolicyAdminException(
                "Service {!r} contains invalid characters: {!r}".format(
                    arg, invalid_chars))

        service = arg

        policy = FilePolicy(policy_path=self.policy_path)
        rules = policy.find_rules_for_service(service)

        file_list = []
        for rule in rules:
            try:
                rule.filepath.relative_to(self.policy_path)
            except ValueError:
                path_to_append = str(rule.filepath)
            else:
                path_to_append = rule.filepath.stem
            if path_to_append not in file_list:
                file_list.append(path_to_append)

        return ("".join(f"{f}\n" for f in file_list)).encode('utf-8')

    # helpers

    def _get_path(self, arg: str, dir_path, suffix: str) -> Path:
        path = dir_path / (arg + suffix)
        path = path.resolve()
        if path.parent != dir_path:
            raise PolicyAdminException(
                "Expecting a path inside {}".format(dir_path)
            )

        return path

    def _validate(self, path: Path, content: Optional[str]):
        try:
            ValidateParser(
                policy_path=self.policy_path, overrides={path: content}
            )
        except PolicySyntaxError as exc:
            raise PolicyAdminException(
                "Policy change validation failed: {}".format(exc)
            ) from exc

    def _check_token(self, token: bytes, path: Path):
        if token == b"any":
            return

        if token == b"new":
            if path.exists():
                raise PolicyAdminTokenException(
                    "File exists but token is 'new'"
                )
            return

        if not token.startswith(b"sha256:"):
            raise PolicyAdminException("Unrecognized token")

        if not path.exists():
            raise PolicyAdminTokenException(
                "File doesn't exist, but token isn't 'new'"
            )

        current_token = compute_token(path.read_bytes())
        if current_token != token:
            raise PolicyAdminTokenException("Token mismatch")


def compute_token(data: bytes) -> bytes:
    return b"sha256:" + hashlib.sha256(data).hexdigest().encode("ascii")
