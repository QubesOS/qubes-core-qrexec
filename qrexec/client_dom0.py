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

from .utils import prepare_subprocess_kwds

QREXEC_CLIENT = '/usr/bin/qrexec-client'

if not pathlib.Path(QREXEC_CLIENT).is_file():
    raise ImportError('{} not available'.format(QREXEC_CLIENT))

def call(dest, rpcname, arg=None, *, input=None):
    '''Invoke qrexec call from dom0

    The `input` parameter should be either :py:class:`str` or :py:class:`bytes`
    or a *real* file, which has file descriptor (as returned by ``.fileno()``
    method). Other file-like objects are not supported.

    :param str dest: name of the policied call
    :param str rpcname: name of a call from Policy API
    :param str or None arg: argument of the call
    :param str or bytes or file or None input: an input to the qrexec call
    :rtype: bytes
    :raises subprocess.CalledProcessError: on failure
    '''
    # pylint: disable=redefined-builtin

    assert '+' not in rpcname
    if arg is not None:
        rpcname = '{}+{}'.format(rpcname, arg)

    return subprocess.check_output(
        [QREXEC_CLIENT, '-d', dest, 'DEFAULT:QUBESRPC {} dom0'.format(rpcname)],
        **prepare_subprocess_kwds(input)).decode()
