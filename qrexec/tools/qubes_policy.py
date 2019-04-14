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

'''qubes-policy -- CLI tool for manipulating policy'''

import argparse
import sys

from ..policy import api
from .. import RPCNAME_ALLOWED_CHARSET

parser = argparse.ArgumentParser(
    usage='qubes-policy {[-l]|-g|-r|-d} [include/][RPCNAME[+ARGUMENT]]')

parser.add_argument('-l', '--list',
    dest='method',
    action='store_const', const='List',
    help='list present policy files')

parser.add_argument('-g', '--get',
    dest='method',
    action='store_const', const='Get',
    help='fetch the content of the policy file')

parser.add_argument('-r', '--replace',
    dest='method',
    action='store_const', const='Replace',
    help='replace given policy with the one provided on standard input')

parser.add_argument('-d', '--remove',
    dest='method',
    action='store_const', const='Remove',
    help='remove a policy file')

parser.add_argument('name', metavar='[include/][RPCNAME[+ARGUMENT]]',
    nargs='?',
    help='specify qubes RPC name or filename to operate on;'
        ' with "include/", operate on files in include subdirectory;'
        ' not all combinations are valid for every call')

parser.set_defaults(method='List', name='')

def main(args=None):
    # pylint: disable=missing-docstring
    args = parser.parse_args(args)
#   print(repr(args))
#   return

    proxy = api.policy
    name = args.name
    kwds = {}

    if name:
        if name == 'include' or name.startswith('include/'):
            name = name[len('include/'):]
            proxy = proxy.include

        invalid_chars = set(name) - RPCNAME_ALLOWED_CHARSET
        if invalid_chars:
            parser.error('invalid character(s) in RPCNAME: {!r}'.format(
                ''.join(sorted(invalid_chars))))

    method = getattr(proxy, args.method)
    varnames = method.__code__.co_varnames

    if '+' in name:
        if not 'argument' in varnames:
            parser.error('argument is inaproppriate for this call')
        name, kwds['argument'] = name.split('+', 1)
        if not name:
            parser.error('empty RPCNAME not allowed')

    if not name:
        name = None
    if 'name' in varnames:
        kwds['name'] = name
    elif name:
        parser.error('RPCNAME not allowed')

    if 'input' in varnames:
        kwds['input'] = sys.stdin.read()
    sys.stdin.close()

    print(method(**kwds))

if __name__ == '__main__':
    sys.exit(main())
