'''Some package-wide constants'''

__version__ = '4.0.0'

import pathlib
import string

# don't import 'qubes.config' please, it takes 0.3s
QREXEC_CLIENT = '/usr/lib/qubes/qrexec-client'
POLICY_DIR = '/etc/qubes-rpc/policy'
QUBESD_INTERNAL_SOCK = '/var/run/qubesd.internal.sock'
QUBESD_SOCK = '/var/run/qubesd.sock'

POLICYPATH = pathlib.Path(POLICY_DIR)
INCLUDEPATH = POLICYPATH / 'include'

RPCNAME_ALLOWED_CHARS = (
    string.ascii_uppercase + string.ascii_lowercase + string.digits + '+-._')

DEFAULT_POLICY = '''\
## Policy file automatically created on first service call.
## Fell free to edit.
## Note that policy parsing stops at the first match

## Please use a single # to start your custom comments

@anyvm  @anyvm  ask
'''
