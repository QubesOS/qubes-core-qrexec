# pylint: disable=anomalous-backslash-in-string
'''
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

RPC_PATH = '/etc/qubes-rpc'
POLICY_AGENT_SOCKET_PATH = '/var/run/qubes/policy-agent.sock'
POLICYPATH = pathlib.Path('/etc/qubes/policy.d')
POLICYSOCKET = pathlib.Path('/var/run/qubes/policy.sock')
POLICY_EVAL_SOCKET = pathlib.Path('/etc/qubes-rpc/policy.EvalSimple')
POLICY_GUI_SOCKET = pathlib.Path('/etc/qubes-rpc/policy.EvalGUI')
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
