# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2013-2017  Marek Marczykowski-Górecki
#                                   <marmarek@invisiblethingslab.com>
# Copyright (C) 2017 boring-stuff <boring-stuff@users.noreply.github.com>
# Copyright (C) 2019  Wojtek Porczyk <woju@invisiblethingslab.com>
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

import json
import socket
import subprocess

from . import QUBESD_SOCK, QUBESD_INTERNAL_SOCK
from .exc import QubesMgmtException

def _sanitize_char(input_char, extra_allowed_characters):
    input_char_ord = ord(input_char)

    if (ord('a') <= input_char_ord <= ord('z')) \
       or (ord('A') <= input_char_ord <= ord('Z')) \
       or (ord('0') <= input_char_ord <= ord('9')) \
       or (input_char in ['@', '_', '-', '.']) \
       or (input_char in extra_allowed_characters):
        result = input_char
    else:
        result = '_'

    return result


# This function needs to be synchronized with qrexec-daemon.c's sanitize_name()
# from the qubes-core-admin-linux repository.
#
# See https://github.com/QubesOS/qubes-core-admin-linux/blob/
#  4f0878ccbf8a95f8264b54d2b6f4dc433ca0793a/qrexec/qrexec-daemon.c#L627-L646
#
def _sanitize_name(input_string, extra_allowed_characters, assert_sanitized):
    result = ''.join(_sanitize_char(character, extra_allowed_characters)
                    for character in input_string)

    if assert_sanitized and not input_string == result:
        raise ValueError(
            'Input string was expected to be sanitized, but was not.')
    return result


def sanitize_domain_name(input_string, assert_sanitized=False):
    return _sanitize_name(input_string, {}, assert_sanitized)


def sanitize_service_name(input_string, assert_sanitized=False):
    return _sanitize_name(input_string, {'+'}, assert_sanitized)


def qubesd_call(dest, method, arg=None, payload=None):
    if method.startswith('internal.'):
        socket_path = QUBESD_INTERNAL_SOCK
    else:
        socket_path = QUBESD_SOCK
    try:
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.connect(socket_path)
    except IOError: # pylint: disable=try-except-raise
        # TODO:
        raise

    # src, method, dest, arg
    call_header = '{}+{} dom0 name {}\0'.format(method, arg or '', dest)
    client_socket.sendall(call_header.encode('ascii'))
    if payload is not None:
        client_socket.sendall(payload)

    client_socket.shutdown(socket.SHUT_WR)

    return_data = client_socket.makefile('rb').read()
    if return_data.startswith(b'0\x00'):
        return return_data[2:]
    if return_data.startswith(b'2\x00'):
        # pylint: disable=unused-variable
        (_, exc_type, _traceback, _format_string, _args) = \
            return_data.split(b'\x00', 4)
        raise QubesMgmtException(exc_type.decode('ascii'))
    raise AssertionError(
        'invalid qubesd response: {!r}'.format(return_data))


def get_system_info():
    ''' Get system information

    This retrieve information necessary to process qrexec policy. Returned
    data is nested dict structure with this structure:

    - domains:
       - `<domain name>`:
          - tags: list of tags
          - type: domain type
          - template_for_dispvms: should DispVM based on this VM be allowed
          - default_dispvm: name of default AppVM for DispVMs started from here
    '''

    system_info = qubesd_call('dom0', 'internal.GetSystemInfo')
    return json.loads(system_info.decode('utf-8'))

def prepare_subprocess_kwds(input):
    '''Prepare kwds for :py:func:`subprocess.run` for given input
    ''' # pylint: disable=redefined-builtin
    kwds = {}
    if input is None:
        kwds['stdin'] = subprocess.DEVNULL
    elif isinstance(input, bytes):
        kwds['input'] = input
    elif isinstance(input, str):
        kwds['input'] = input.encode()
    else:
        # XXX this breaks on file-like objects that don't have .fileno
        kwds['stdin'] = input
    return kwds
