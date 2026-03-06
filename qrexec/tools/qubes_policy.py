#!/usr/bin/env python3

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

"""qubes-policy -- CLI tool for manipulating policy"""

import argparse
import sys
import subprocess

from ..policy.admin_client import PolicyClient
from .. import RPCNAME_ALLOWED_CHARSET
from ..policy.admin import PolicyAdminException

parser = argparse.ArgumentParser(
    usage="qubes-policy {[-l]|-g|-r|-d} [include/][RPCNAME[+ARGUMENT]]"
)

parser.add_argument(
    "-l",
    "--list",
    dest="method",
    action="store_const",
    const="list",
    help="list present policy files",
)

parser.add_argument(
    "-g",
    "--get",
    dest="method",
    action="store_const",
    const="get",
    help="fetch the content of the policy file",
)

parser.add_argument(
    "-r",
    "--replace",
    dest="method",
    action="store_const",
    const="replace",
    help="replace given policy with the one provided on standard input",
)

parser.add_argument(
    "-d",
    "--remove",
    dest="method",
    action="store_const",
    const="remove",
    help="remove a policy file",
)

parser.add_argument(
    "name",
    metavar="[include/][name]",
    nargs="?",
    help="specify qubes RPC name or filename to operate on;"
    ' with "include/", operate on files in include subdirectory',
)

parser.set_defaults(method="list", name="")


def run_method(method, name, is_include, client):
    if method == "list":
        result = client.policy_list(is_include=is_include)
        print("\n".join(result))
    elif method == "get":
        content, _token = client.policy_get(name=name, is_include=is_include)
        print(content.rstrip())
    elif method == "replace":
        content = sys.stdin.read()
        client.policy_replace(name=name, content=content, is_include=is_include)
    elif method == "remove":
        client.policy_remove(name=name, is_include=is_include)
    else:
        assert False, method


def main(args=None):
    args = parser.parse_args(args)
    client = PolicyClient()
    name = args.name

    is_include = False
    if name:
        if name == "include" or name.startswith("include/"):
            name = name[len("include/") :]
            is_include = True

        invalid_chars = set(name) - RPCNAME_ALLOWED_CHARSET
        if invalid_chars:
            parser.error(
                "invalid character(s) in RPCNAME: {!r}".format(
                    "".join(sorted(invalid_chars))
                )
            )

    if args.method == "list" and name:
        parser.error("--list doesn't work with a file name")
    elif args.method != "list" and not name:
        parser.error("you need to provide a file name")

    try:
        run_method(
            method=args.method,
            name=name,
            is_include=is_include,
            client=client,
        )
    except subprocess.CalledProcessError as e:
        print("Command failed", file=sys.stderr)
        output = e.output.decode().rstrip()
        if output:
            print(output, file=sys.stderr)
        sys.exit(1)
    except PolicyAdminException as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
