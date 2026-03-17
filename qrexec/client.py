# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017-2018 Wojtek Porczyk <woju@invisiblethingslab.com>
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

import pathlib
import subprocess
import asyncio
from typing import Optional

from .utils import prepare_subprocess_kwds

# The PolicyAdmin*Exception is used by issubclass(..., PolicyAdminException).
# pylint: disable=unused-import
from .policy.admin import (
    PolicyAdminException,
    PolicyAdminTokenException,
    PolicyAdminFileNotFoundException,
    PolicyAdminProtocolException,
    PolicyAdminSyntaxException,
    PolicyAdminInvalidFileNameException,
    PolicyAdminInvalidFilePathException,
)

QREXEC_CLIENT_DOM0 = "/usr/bin/qrexec-client"
QREXEC_CLIENT_VM = "/usr/bin/qrexec-client-vm"
# pylint: disable=invalid-name
IN_DOM0 = None

if pathlib.Path(QREXEC_CLIENT_DOM0).is_file():
    IN_DOM0 = True
elif pathlib.Path(QREXEC_CLIENT_VM).is_file():
    IN_DOM0 = False


def call(dest: str, rpcname: str, arg: Optional[str] = None, *, payload=None):
    """Invoke qrexec call

    The `payload` parameter should be either :py:class:`str` or :py:class:`bytes`
    or a *real* file, which has file descriptor (as returned by ``.fileno()``
    method). Other file-like objects are not supported.

    :param str dest: name of the policied call
    :param str rpcname: name of a call from Policy API
    :param str or None arg: argument of the call
    :param str or bytes or file or None payload: an payload to the qrexec call
    :rtype: str
    :raises subprocess.CalledProcessError: on unexpected failure, instance of \
            PolicyAdminException otherwise
    """
    command = make_command(dest=dest, rpcname=rpcname, arg=arg)
    kwds = prepare_subprocess_kwds(payload, for_popen=False)
    try:
        return subprocess.check_output(command, **kwds).decode()
    except subprocess.CalledProcessError as exc:
        stderr_exc = exc.stderr.decode()
        stderr_exc_type = stderr_exc.split(" ")[0]
        if stderr_exc_type in globals():
            exception = globals()[stderr_exc_type]
            if issubclass(exception, PolicyAdminException):
                stderr_exc_msg = stderr_exc[len(exception.__name__ + " ") :]
                raise exception(stderr_exc_msg) from exc
        raise


async def call_async(dest, rpcname, arg=None, *, payload=None):
    """Invoke qrexec call (async version)

    The `payload` parameter should be either :py:class:`str` or :py:class:`bytes`
    or a *real* file, which has file descriptor (as returned by ``.fileno()``
    method). Other file-like objects are not supported.

    :param str dest: name of the policied call
    :param str rpcname: name of a call from Policy API
    :param str or None arg: argument of the call
    :param str or bytes or file or None payload: an payload to the qrexec call
    :rtype: str
    :raises subprocess.CalledProcessError: on failure
    """
    command = make_command(dest=dest, rpcname=rpcname, arg=arg)
    kwds = prepare_subprocess_kwds(payload)
    to_communicate = kwds.pop("input")
    process = await asyncio.create_subprocess_exec(*command, **kwds)
    stdout, _stderr = await process.communicate(to_communicate)
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command)
    return stdout.decode()


def make_command(dest, rpcname, arg):
    assert "+" not in rpcname
    assert " " not in rpcname
    if arg is not None:
        assert " " not in arg
        rpcname = f"{rpcname}+{arg}"

    if IN_DOM0 is True:
        return [
            QREXEC_CLIENT_DOM0,
            "-d",
            dest,
            f"DEFAULT:QUBESRPC {rpcname} dom0",
        ]
    if IN_DOM0 is False:
        return [QREXEC_CLIENT_VM, "--", dest, rpcname]

    assert IN_DOM0 is None
    raise NotImplementedError("qrexec not available")
