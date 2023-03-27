#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2020 Paweł Marczewski <pawel@invisiblethingslab.com>
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

"""
Admin client in Python

>>> from qrexec.policy.admin_client import PolicyClient
>>> client = PolicyClient()
>>> client.policy_list()
['qubes.Gpg', ...]
>>> client.policy_get('qubes.Gpg')
'sha256:...', '@anyvm vault allow\n'
>>> client.policy_replace('qubes.Gpg', \'\'\'\
... work vault allow
... mail mail-vault allow
... @anyvm @anyvm deny
... \'\'\')
"""

from __future__ import annotations
from typing import List, Tuple

from ..client import call


class PolicyClient:
    def policy_list(self) -> List[str]:
        return self.call("policy.List").rstrip("\n").split("\n")

    def policy_include_list(self) -> List[str]:
        return self.call("policy.include.List").rstrip("\n").split("\n")

    def policy_get(self, name: str) -> Tuple[str, str]:
        token, content = self.call("policy.Get", name).split("\n", 1)
        return content, token

    def policy_include_get(self, name: str) -> Tuple[str, str]:
        token, content = self.call("policy.include.Get", name).split("\n", 1)
        return content, token

    def policy_replace(self, name: str, content: str, token="any"):
        self.call("policy.Replace", name, token + "\n" + content)

    def policy_include_replace(self, name: str, content: str, token="any"):
        self.call("policy.Replace", name, token + "\n" + content)

    def policy_remove(self, name: str, token="any"):
        self.call("policy.Remove", name, token)

    def policy_include_remove(self, name: str, token="any"):
        self.call("policy.Remove", name, token)

    def policy_get_files(self, name: str):
        result = self.call("policy.GetFiles", name)
        return [] if result == "" else result.rstrip("\n").split("\n")

    @staticmethod
    def call(service_name, arg=None, payload=""):
        return call("dom0", service_name, arg, input=payload)
