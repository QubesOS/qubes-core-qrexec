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
from .. import RPCNAME_ALLOWED_CHARSET, POLICYPATH, INCLUDEPATH
from ..client import IN_DOM0


def validate_name(name):
    """
    Valid policy file name

    :param name: policy file name
    """
    invalid_chars = set(name) - RPCNAME_ALLOWED_CHARSET
    if invalid_chars:
        print("invalid character(s) in the file name: {!r}".format(
            "".join(sorted(invalid_chars)))
        )
        sys.exit(1)

    if name.endswith(".policy"):
        name = name[:-7]

    return name


def manage_policy(name, is_include=False):
    client = PolicyClient()

    # Don't use policy(.include).List to support restricted AdminVMs. Instead,
    # try to policy(.include).Get the file and if it fails because the file is
    # not found, ignore, else abort as the request was refused.
    file_exists = False
    if is_include:
        try:
            original_content, token = client.policy_include_get(name)
            file_exists = True
        except subprocess.CalledProcessError as e:
            wanted_path = str(INCLUDEPATH) + "/" + name + "\n"
            not_found = "Not found: " + wanted_path
            if e.output.decode() != not_found:
                print("Failed to get file: " + name)
                sys.exit(1)
    else:
        try:
            original_content, token = client.policy_get(name)
            file_exists = True
        except subprocess.CalledProcessError as e:
            wanted_path = str(POLICYPATH) + "/" + name + ".policy\n"
            not_found = "Not found: " + wanted_path
            if e.output.decode() != not_found:
                print("Failed to get file: " + name)
                sys.exit(1)

    if is_include:
        # pylint: disable=consider-using-with
        tmpfile = tempfile.NamedTemporaryFile(suffix="_include_" + name)
    else:
        # pylint: disable=consider-using-with
        tmpfile = tempfile.NamedTemporaryFile(suffix="_" + name)

    if file_exists:
        with open(tmpfile.name, 'w', encoding="utf-8") as current_file:
            current_file.write(original_content)
            current_file.close()
    else:
        token = "new"

    lint_policy(tmpfile.name, is_include=is_include)

    with open(tmpfile.name, "r", encoding="utf-8") as current_file:
        content = current_file.read()
        current_file.close()

    try:
        if is_include:
            client.policy_include_replace(name, content, token)
        else:
            client.policy_replace(name, content, token)
    except subprocess.CalledProcessError as e:
        print("Failed to replace file: " + name)
        sys.exit(1)

    tmpfile.close()


def get_reply(path, is_include=False):
    """
    Get reply from user.

    :param path: path or "-"
    :param is_include: Boolean
    """
    print("What now? ", end='')
    reply = str(input())
    if reply == "e":
        lint_policy(path, is_include=is_include)
        return
    if reply == "q":
        sys.exit(0)
    else:
        get_reply(path, is_include=is_include)


def lint_policy(path, is_include=False):
    """
    Open file and lint after closing it. If lint fails, wait for user reply.

    :param path: path or "-"
    :param is_include: Boolean
    """
    edit_cmd = "${VISUAL:-${EDITOR:-vi}} " + path
    subprocess.run(edit_cmd, shell=True, check=True)

    if is_include:
        lint_cmd = "qubes-policy-lint --include-service " + path
    else:
        lint_cmd = "qubes-policy-lint " + path

    try:
        subprocess.run(lint_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as exc:
        return_code = exc.returncode
        if return_code == 0:
            return
        if return_code == 127:
            print("The linting program 'qubes-policy-lint' is not installed.")
            sys.exit(1)
        else:
            print("Linting failed, do you want to:\n"
                  "  (e)dit again\n"
                  "  (q)uit without saving changes?")
            get_reply(path, is_include=is_include)


def main():
    """
    Main.
    """
    default_file = "30-user"
    parser = argparse.ArgumentParser()
    parser.add_argument("file", metavar="[include/]FILE",
                        default=default_file,
                        help="set file to be edited. The '.policy' suffix "
                             "must not be included. Will search for an "
                             "editor by looking at $EDITOR, $VISUAL if "
                             "previous entry is unset or 'vi' if previous "
                             "entry is also unset. Defaults to the user file.",
                        nargs="?")
    args = parser.parse_args()

    if IN_DOM0 and os.getuid() != 0:
        print("You need to run as root in dom0")
        sys.exit(1)

    name = args.file
    include_prefix = "include/"
    is_include = False
    if name.startswith(include_prefix):
        name = name[len(include_prefix) :]
        is_include = True

    name = validate_name(name)
    manage_policy(name, is_include)

if __name__ == "__main__":
    main()
