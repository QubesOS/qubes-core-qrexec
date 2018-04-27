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

'''qubes-policy-restore -- CLI tool for restoring policy from backup'''

import argparse
import pathlib
import sys

from ..policy import api
from ..policy import parser

argparser = argparse.ArgumentParser()
# TODO mode of operation
# - just replace everything
# - only files that do not exist in dom0
# -
argparser.add_argument('path', metavar='DIRECTORY',
    type=pathlib.Path,
    help='directory with policy files in it (and maybe include/ subdirectory)')

def main(args=None):
    # pylint: disable=missing-docstring
    args = argparser.parse_args(args)

    for file, rpcname, argument in parser.toposort(args.path):
        policy = api.policy
        if filename.startswith('include/'):
            policy = policy.include
        policy.Replace()  # XXX WIP

if __name__ == '__main__':
    sys.exit(main())
