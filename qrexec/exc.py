#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2013-2015  Joanna Rutkowska <joanna@invisiblethingslab.com>
# Copyright (C) 2013-2017  Marek Marczykowski-Górecki
#                                   <marmarek@invisiblethingslab.com>
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

class AccessDenied(Exception):
    ''' Raised when qrexec policy denied access '''

class PolicySyntaxError(AccessDenied):
    ''' Syntax error in qrexec policy, abort parsing '''
    def __init__(self, filepath, lineno, msg):
        super(PolicySyntaxError, self).__init__(
            '{}:{}: {}'.format(filepath or '<unknown>', lineno, msg))

class PolicyNotFound(AccessDenied):
    ''' Policy was not found for this service '''
    def __init__(self, service_name):
        super(PolicyNotFound, self).__init__(
            'Policy not found for service {}'.format(service_name))

class QubesMgmtException(Exception):
    ''' Exception returned by qubesd '''
    def __init__(self, exc_type):
        super(QubesMgmtException, self).__init__()
        self.exc_type = exc_type
