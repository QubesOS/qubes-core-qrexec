'''Some package-wide constants'''

__version__ = '4.0.0'

import pathlib
import string

# don't import 'qubes.config' please, it takes 0.3s
QREXEC_CLIENT = '/usr/lib/qubes/qrexec-client'
QUBESD_INTERNAL_SOCK = '/var/run/qubesd.internal.sock'
QUBESD_SOCK = '/var/run/qubesd.sock'

POLICYPATH = pathlib.Path('/etc/qubes/policy.d')
INCLUDEPATH = POLICYPATH / 'include'

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
