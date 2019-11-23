# pylint: disable=missing-docstring

import unittest
import unittest.mock

try:
    from qrexec import call
except ImportError:
    import qrexec
    qrexec.call = unittest.mock.Mock()
from ..policy.api import policy, _qrexec

POLICY_VALID = '''\
$anyvm $anyvm deny
'''

POLICY_VALID_WITH_INCLUDE = '''\
$anyvm $anyvm deny
$include:include/admin-global-ro
'''

POLICY_INVALID_SYNTAX_ERROR = '''\
!syntax-error
'''

POLICY_INVALID_WRONG_INCLUDE = '''\
$include:/dev/null
'''

# TODO
# - symlinks
# - various problems around argument
# - policy.test.Setup (to be supplied with .Cleanup in auxiliary rpm)

@unittest.skip('TODO')
class TC_00_Integration(unittest.TestCase):
    @property
    def rpcname(self):
        # '$' is a valid character in RPC name, but no one uses it
        return 'policytest.' + self._testMethodName

    def setUp(self):
        self.addCleanup(_qrexec, 'policy.test.Cleanup')

    def test_001_replace(self):
        policy.Replace(self.rpcname, POLICY_VALID)

    def test_002_replace_arg(self):
        policy.Replace(self.rpcname, POLICY_VALID)

    def test_101_get(self):
        policy.Replace(self.rpcname, POLICY_VALID)
        self.assertEqual(policy.Get(self.rpcname), POLICY_VALID)

    def test_201_list(self):
        policy.Replace(self.rpcname, POLICY_VALID)
        self.assertIn(self.rpcname, policy.List())

    def test_301_remove(self):
        policy.Replace(self.rpcname, POLICY_VALID)
        policy.Remove(self.rpcname)

    def test_302_remove_nonexistent(self):
        policy.Remove(self.rpcname)
