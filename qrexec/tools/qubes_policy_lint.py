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
qubes-policy-lint -- CLI tool for linting policies

Useful to test individual policies and does not require them to be at any
specific path.

Paths are not included by the !include* directives on purpose, as we want to
test individual policies.
If the path itself is an included service specified by another policy via
!include-service, then we can lint only files that are services.

You can lint normal policies:
    qubes-policy-lint /etc/qubes/policy.d/*.policy
Or included services:
    qubes-policy-lint -i /etc/qubes/policy.d/include/*
You can't lint both types at the same time.
"""

from __future__ import print_function
import argparse
import sys
from ..exc import PolicySyntaxError
from ..policy.parser import StringPolicy


def retrieve_list(path):
    """Helper function to retrieve data from given path, or stdin if "-"
    specified, then return it as a list of lines.

    :param path: path or "-"
    :return: list of lines
    """
    if path == "-":
        return [x.rstrip() for x in sys.stdin.readlines()]

    try:
        with open(path, "r", encoding="utf-8") as file:
            return [x.rstrip() for x in file.readlines()]
    except FileNotFoundError:
        msg = "File does not exist."
        print(path + ":0: error: " + msg)
        raise


def parse_string_policy(line, included_path="", include_service=False):
    # Do not lint included path.
    # But lint itself as an included service if specified by the user.
    if included_path != "":
        if include_service:
            StringPolicy(
                policy={
                    "__main__": "!include-service * * inc",
                    "inc": line, included_path: ""
                }
            )
        else:
            StringPolicy(
                policy={
                    "__main__": line, included_path: ""
                }
            )
    else:
        if include_service:
            StringPolicy(
                policy={
                    "__main__": "!include-service * * inc",
                    "inc": line
                }
            )
        else:
            StringPolicy(
                policy={
                    "__main__": line
                }
            )


def parse_file(path, show=False, include_service=False):
    """
    Validate file.

    :param path: path or "-"
    :param show: Boolean
    :param include_service: Boolean
    """
    errors = []
    text = retrieve_list(path)

    for lineno, line in enumerate(text, start=1):
        line = line.strip()

        if not line or line[0] == "#":
            lineno += 1
            continue

        throw_exception = False
        exception_msg = ''
        included_path = ''
        if line.startswith("!"):
            directive, *params = line.split()

            if directive == "!include-service":
                if len(params) == 3:
                    # pylint: disable=unused-variable
                    service, argument, included_path = params
            elif directive == "!include":
                if len(params) == 1:
                    (included_path,) = params
            elif directive == "!include-dir":
                if len(params) != 1:
                    throw_exception = True
                    exception_msg = "invalid number of params"
                else:
                    # Not implemented upstream, there is no example in
                    # qrexec/tests/policy_parser.py
                    lineno += 1
                    continue

        try:
            if throw_exception:
                raise PolicySyntaxError(
                    path, lineno, exception_msg
                )

            parse_string_policy(line, included_path, include_service)
        except PolicySyntaxError as exc:
            msg = str(exc).split(":", 2)[-1]
            err = path + ":" + str(lineno) + ": error:" + msg
            if show:
                err += ": " + line
            errors.append(err)

    if errors:
        print("\n".join(errors))
        sys.exit(1)


def main(args=None):
    """
    Parse arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--show-line", action="store_true",
                        default=False,
                        help="show the line that caused the error")
    parser.add_argument("-i", "--include-service", action="store_true",
                        default=False,
                        help="lint a policy that is included by another file "
                             "via !include-service. When this option is "
                             "specified, normal policies cannot be verified")
    parser.add_argument("file", metavar="FILE",
                        help="set file to be read , use \"-\" to read from "
                             "stdin",
                        nargs="+")
    args = parser.parse_args(args)

    exit_code = 0
    for file in args.file:
        try:
            parse_file(file, show=args.show_line,
                       include_service=args.include_service)
        except PolicySyntaxError:
            exit_code = 1

    if exit_code == 1:
        sys.exit(1)


if __name__ == "__main__":
    main()
