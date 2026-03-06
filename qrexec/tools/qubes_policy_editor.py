#!/usr/bin/env python3

#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2023  Ben Grande <ben.grande.b@gmail.com>
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
qubes-policy-editor -- CLI tool for editing a policy safely
"""

from __future__ import print_function
import argparse
import os
import subprocess
import sys
import tempfile

from ..policy.admin_client import PolicyClient
from ..policy.admin import (
    PolicyAdminException,
    PolicyAdminFileNotFoundException,
)
from .. import RPCNAME_ALLOWED_CHARSET


def validate_name(name):
    """
    Valid policy file name

    :param name: policy file name
    """
    invalid_chars = set(name) - RPCNAME_ALLOWED_CHARSET
    if invalid_chars:
        print(
            "invalid character(s) in the file name: {!r}".format(
                "".join(sorted(invalid_chars)), file=sys.stderr
            )
        )
        sys.exit(1)

    if name.endswith(".policy"):
        name = name[:-7]

    return name


class PolicyManager:

    def __init__(self, policy: str, is_include: bool = False) -> None:
        self.policy = policy
        self.is_include = is_include
        self.tmpfile_name: str | None = None

    def manage_policy(self) -> None:
        client = PolicyClient()

        # Don't use policy(.include).List to support restricted AdminVMs. Instead,
        # try to policy(.include).Get the file and if it fails because the file is
        # not found, ignore, else abort as the request was refused.
        file_exists = False
        if self.is_include:
            suffix = "_include_" + self.policy
        else:
            suffix = "_" + self.policy + ".policy"

        try:
            original_content, token = client.policy_get(
                policy=self.policy, is_include=self.is_include
            )
            file_exists = True
        except PolicyAdminFileNotFoundException:
            pass
        except subprocess.CalledProcessError as exc:
            print(
                f"Failed to get policy {self.policy!r}: {exc}", file=sys.stderr
            )
            sys.exit(1)

        # pylint: disable=consider-using-with
        tmpfile = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)

        if file_exists:
            with open(tmpfile.name, "w", encoding="utf-8") as current_file:
                current_file.write(original_content)
                current_file.close()
        else:
            token = "new"

        self.tmpfile_name = tmpfile.name
        self.lint_policy()

        with open(tmpfile.name, "r", encoding="utf-8") as current_file:
            content = current_file.read()
            current_file.close()

        try:
            client.policy_replace(
                policy=self.policy,
                content=content,
                token=token,
                is_include=self.is_include,
            )
        except PolicyAdminException as exc:
            print(
                f"Failed to replace policy {self.policy!r} with file {tmpfile.name!r}: "
                f"{exc}",
                file=sys.stderr,
            )
            sys.exit(1)

        tmpfile.close()
        os.remove(self.tmpfile_name)

    def get_reply(self) -> None:
        """
        Get reply from user.
        """
        print("What now? ", end="", file=sys.stderr)
        reply = str(input())
        if reply == "e":
            self.lint_policy()
            return
        if reply == "q":
            sys.exit(0)
        else:
            self.get_reply()

    def lint_policy(self) -> None:
        """
        Open file and lint after closing it. If lint fails, wait for user reply.
        """
        assert isinstance(self.tmpfile_name, str)
        edit_cmd = "${VISUAL:-${EDITOR:-vi}} -- " + self.tmpfile_name
        try:
            subprocess.run(edit_cmd, shell=True, check=True)
        except subprocess.CalledProcessError as exc:
            print(f"Failed to open editor: {exc}", file=sys.stderr)
            sys.exit(1)

        lint_cmd = "qubes-policy-lint "
        if self.is_include:
            lint_cmd += "--include-service "
        lint_cmd += "-- " + self.tmpfile_name

        try:
            subprocess.run(lint_cmd, shell=True, check=True)
        except subprocess.CalledProcessError as exc:
            return_code = exc.returncode
            if return_code == 0:
                return
            if return_code == 127:
                print(
                    "The linting program 'qubes-policy-lint' is not installed",
                    file=sys.stderr,
                )
                sys.exit(1)
            else:
                print(
                    "Linting failed, do you want to:\n"
                    "  (e)dit again\n"
                    "  (q)uit without saving changes?",
                    file=sys.stderr,
                )
                self.get_reply()


def main():
    """
    Main.
    """
    default_file = "30-user"
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "file",
        metavar="[include/]FILE",
        default=default_file,
        help="set file to be edited. The '.policy' suffix "
        "must not be included. Will search for an "
        "editor by looking at $VISUAL, $EDITOR, and if "
        "previous entry is unset or 'vi' if previous "
        "entry is also unset. Defaults to the user file.",
        nargs="?",
    )
    args = parser.parse_args()

    name = args.file
    include_prefix = "include/"
    is_include = False
    if name.startswith(include_prefix):
        name = name[len(include_prefix) :]
        is_include = True

    policy = validate_name(name)
    policy_manager = PolicyManager(policy=policy, is_include=is_include)
    policy_manager.manage_policy()


if __name__ == "__main__":
    main()
