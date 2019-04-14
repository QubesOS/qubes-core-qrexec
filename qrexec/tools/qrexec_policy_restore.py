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

# pylint: skip-file

'''qubes-policy-restore -- CLI tool for restoring policy from backup'''

import argparse
import pathlib
import sys

from .. import POLICYPATH
from ..policy import api, parser

argparser = argparse.ArgumentParser()
# TODO mode of operation
# - just replace everything
# - only files that do not exist in dom0
# -
argparser.add_argument('--dest', metavar='DIRECTORY',
    type=pathlib.Path,
    help='directory with live policy (default: %(default)s)')
argparser.add_argument('path', metavar='DIRECTORY',
    type=pathlib.Path,
    help='directory with policy files in it (and maybe include/ subdirectory)')
argparser.set_defaults(dest=POLICYPATH)

def main(args=None):
    # pylint: disable=missing-docstring
    args = argparser.parse_args(args)

    try:
        (args.dest / 'include').mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.stderr.write(
            'cannot create directory {} [{}]\n'.format(e.filename, e.strerror))
        return 1

    includepath = args.dest / 'include'
    if not includepath.exists():
        includepath.mkdir()
    elif not includepath.is_dir() or includepath.is_symlink():
        sys.stderr.write('{} is not a directory, aborting\n'.format(includepath))

    for srcfile, path in parser.toposort(args.path):
        policypath = args.dest / path
        if policypath.exists():
            # TODO allow overwrite (-f switch?)
            sys.stderr.write('not overwriting {}\n'.format(policypath))
            continue

        with policypath.open('w') as dstfile:
            with srcfile:
                dstfile.write(srcfile.read())

        # TODO
#       policy = api.policy
#       if filename.startswith('include/'):
#           policy = policy.include
#       policy.Replace()

if __name__ == '__main__':
    sys.exit(main())
