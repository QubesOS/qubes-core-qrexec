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

from typing import List, Tuple
from warnings import warn

from ..client import call


class PolicyClient:
    def policy_list(self, is_include: bool = False) -> List[str]:
        rpc = "List"
        return self.call(rpc, is_include=is_include).rstrip("\n").split("\n")

    def policy_include_list(self) -> List[str]:
        warn(
            "Method 'policy_include_list()' is deprecated, use 'policy_list()' "
            "instead",
            DeprecationWarning,
        )
        return self.policy_list(is_include=True)

    def policy_get(
        self, name: str, is_include: bool = False
    ) -> Tuple[str, str]:
        rpc = "Get"
        token, content = self.call(
            service_name=rpc, arg=name, is_include=is_include
        ).split("\n", 1)
        return content, token

    def policy_include_get(self, name: str) -> Tuple[str, str]:
        warn(
            "Method 'policy_include_get()' is deprecated, use 'policy_get()' "
            "instead",
            DeprecationWarning,
        )
        return self.policy_get(name=name, is_include=True)

    def policy_replace(
        self,
        name: str,
        content: str,
        token: str = "any",
        is_include: bool = False,
    ):
        rpc = "Replace"
        self.call(
            service_name=rpc,
            arg=name,
            payload=token + "\n" + content,
            is_include=is_include,
        )

    def policy_include_replace(self, name: str, content: str, token="any"):
        warn(
            "Method 'policy_include_replace()' is deprecated, use "
            "'policy_replace()' instead",
            DeprecationWarning,
        )
        return self.policy_replace(
            name=name, content=content, token=token, is_include=True
        )

    def policy_remove(
        self, name: str, token: str = "any", is_include: bool = False
    ):
        rpc = "Remove"
        self.call(
            service_name=rpc, arg=name, payload=token, is_include=is_include
        )

    def policy_include_remove(self, name: str, token="any"):
        warn(
            "Method 'policy_include_remove()' is deprecated, use "
            "'policy_remove()' instead",
            DeprecationWarning,
        )
        return self.policy_remove(name=name, token=token, is_include=True)

    def policy_get_files(self, name: str) -> list:
        rpc = "GetFiles"
        result = self.call(service_name=rpc, arg=name)
        return [] if result == "" else result.rstrip("\n").split("\n")

    @staticmethod
    def call(service_name, arg=None, payload="", is_include: bool = False):
        if is_include:
            service_name = "include." + service_name
        service_name = "policy." + service_name
        return call(dest="dom0", rpcname=service_name, arg=arg, input=payload)
