#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2018  Wojtek Porczyk <woju@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <https://www.gnu.org/licenses/>.
#

'''Policy API in Python

>>> from qrexec import policy
>>> policy.List()
['qubes.Gpg', ...]
>>> policy.Get('qubes.Gpg')
'@anyvm vault allow\n'
>>> policy.Replace('qubes.Gpg', \'\'\'\
... work vault allow
... mail mail-vault allow
... @anyvm @anyvm deny
... \'\'\')

.. seealso::
    https://github.com/QubesOS/qubes-policy-control
'''

from .. import call as _call

QREXEC_CLIENT = '/usr/bin/qrexec-client-vm'

def _qrexec(rpcname, *, name=None, argument=None, input=None):
    '''Invoke qrexec call from Policy Administrator API

    Not all param configuration is valid for all calls, but this function does
    not check for invalid combinations. That's why this function is not public.

    :param str rpcname: name of a call from Policy API
    :param str or None name: name of the policied call
    :param str or None argument: policied argument
    :param str or None input: new policy
    :raises subprocess.CalledProcessError: on failure
    '''
    # pylint: disable=redefined-builtin
    if name is not None:
        rpcname = '{}+{}'.format(rpcname, name)

    if argument is not None or input is not None:
        if argument is None:
            argument = b'\n'
        elif not isinstance(argument, bytes):
            argument = argument.encode()

        if not argument.endswith(b'\n'):
            argument += b'\n'
        assert argument.count(b'\n') <= 1

        if input is None:
            input = b''
        elif not isinstance(input, bytes):
            input = input.encode()

        input = argument + input

    return _call('dom0', rpcname, input=input).decode()

# pylint: disable=invalid-name

class policy:
    '''Do not instantiate'''

    @staticmethod
    def List(name=None):
        '''List calls which have defined policies

        :param str name: if not :obj:`None`, list only policies for this call
        '''
        return _qrexec('policy.List', name=name).rstrip('\n').split('\n')

    @staticmethod
    def Get(name, *, argument=None):
        '''Get content of a policy

        :param str name: qrexec name
        :param str argument: if not :obj:`None`, get policy for specific
            argument
        '''
        return _qrexec('policy.Get', name=name, argument=argument)

    @staticmethod
    def Replace(name, input, *, argument=None):
        '''Replace content of a policy

        :param str name: qrexec name
        :param str input: new policy content
        :param str argument: if not :obj:`None`, replace policy for specific
            argument
        '''
        # pylint: disable=redefined-builtin
        return _qrexec('policy.Replace', name=name, argument=argument,
            input=input)

    @staticmethod
    def Remove(name, *, argument=None):
        '''Remove a policy for file, leaving a call unpolicied

        If argument is not specified, this will result in calls being denied
        for all calls that don't have special policies for particular arguments.
        If argument is specified, a call for that argument will result of
        evaluation of default policy for this qrexec.

        :param str name: qrexec name
        :param str argument: if not :obj:`None`, remove policy for specific
            argument
        '''
        return _qrexec('policy.Remove', name=name, argument=argument)

    class include:
        '''Do not instantiate'''

        @staticmethod
        def List():
            '''List files in ``/etc/qubes-rpc/policy/include``'''
            return _qrexec('policy.include.List').rstrip('\n').split('\n')

        @staticmethod
        def Get(name):
            '''Get content of a file

            :param str name: filename under ``/etc/qubes-rpc/policy/include``
            '''
            return _qrexec('policy.include.Get', name=name)

        @staticmethod
        def Replace(name, input):
            '''Replace content of a file

            :param str name: filename under ``/etc/qubes-rpc/policy/include``
            :param str input: new policy content
            '''
            # pylint: disable=redefined-builtin
            return _qrexec('policy.Replace', name=name, input=input)

        @staticmethod
        def Remove(name):
            '''Remove a file

            :param str name: filename under ``/etc/qubes-rpc/policy/include``
            '''
            return _qrexec('policy.Remove', name=name)
