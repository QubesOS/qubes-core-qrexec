# pylint: disable=anomalous-backslash-in-string
'''
Functions
---------

.. function:: call(dest, rpcname[, arg=None, \*, input=None])

   Execute a qrexec call.

   :param str dest: destination (a qube name or a valid ``@token``)
   :param str rpcname: name of the invoked call
   :param arg: argument of the call
   :type arg: str or None
   :param input: input to the qrexec call
   :type input: str or bytes or file or None
   :rtype: bytes
   :raises subprocess.CalledProcessError: on failure

Constants
---------

.. data:: POLICYPATH

   Path to system policy.

.. data:: POLICYPATH_OLD

   Path to legacy policy, imported via ``!compat-4.0`` statement.

.. data:: INCLUDEPATH

   Path where all includes should be kept.

.. data:: POLICYSUFFIX

   Suffix for policy files. Any file in :const:`POLICYPATH` without this suffix
   is ignored.

.. data:: RPCNAME_ALLOWED_CHARSET

   Allowed characters in name of qrexec calls and in argument, including ``+``.
'''

__version__ = '4.0.0'

import pathlib
import string

# don't import 'qubes.config' please, it takes 0.3s
QREXEC_CLIENT = '/usr/lib/qubes/qrexec-client'
QUBESD_INTERNAL_SOCK = '/var/run/qubesd.internal.sock'
QUBESD_SOCK = '/var/run/qubesd.sock'

POLICYPATH = pathlib.Path('/etc/qubes/policy.d')
INCLUDEPATH = POLICYPATH / 'include'
POLICYSUFFIX = '.policy'
POLICYPATH_OLD = pathlib.Path('/etc/qubes-rpc/policy')

RPCNAME_ALLOWED_CHARSET = frozenset(
    string.ascii_uppercase + string.ascii_lowercase + string.digits + '+-._')

DEFAULT_POLICY = '''\
## Policy file automatically created on first service call.
## Fell free to edit.
## Note that policy parsing stops at the first match

## Please use a single # to start your custom comments

@anyvm  @anyvm  ask
'''

try:
    from .client_dom0 import call
except ImportError:
    try:
        from .client_vm import call
    except ImportError:
        pass
