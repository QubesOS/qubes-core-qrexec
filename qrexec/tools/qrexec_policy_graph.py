# -*- encoding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <https://www.gnu.org/licenses/>.

import argparse
import json
import pathlib

import sys

from .. import POLICYPATH
from .. import exc
from .. import utils
from ..policy import parser

argparser = argparse.ArgumentParser(description='Graph qrexec policy')
argparser.add_argument('--include-ask', action='store_true',
    help='Include `ask` action in graph')
argparser.add_argument('--source', action='store', nargs='+',
    help='Limit graph to calls from *source*')
argparser.add_argument('--target', action='store', nargs='+',
    help='Limit graph to calls to *target*')
argparser.add_argument('--service', action='store', nargs='+',
    help='Limit graph to *service*')
argparser.add_argument('--output', action='store',
    help='Write to *output* instead of stdout')
argparser.add_argument('--policy-dir', action='store',
    type=pathlib.Path,
    default=POLICYPATH,
    help='Look for policy in *policy-dir*')
argparser.add_argument('--system-info', action='store',
    help='Load system information from file instead of querying qubesd')
argparser.add_argument('--skip-labels', action='store_true',
    help='Do not include service names on the graph, also deduplicate '
         'connections.')

def handle_single_action(args, action):
    '''Get single policy action and output (or not) a line to add'''
    if args.skip_labels:
        service = ''
    else:
        service = action.request.service
    target = action.request.target
    # handle forced target=
    if action.rule.action.target:
        target = action.rule.action.target
    if args.target and target not in args.target:
        return ''
    if isinstance(action, parser.AskResolution):
        if args.include_ask:
            return '  "{}" -> "{}" [label="{}" color=orange];\n'.format(
                action.request.source, target, service)
    elif isinstance(action, parser.AllowResolution):
        return '  "{}" -> "{}" [label="{}" color=red];\n'.format(
                action.request.source, target, service)
    return ''

def main(args=None):
    args = argparser.parse_args(args)

    output = sys.stdout
    if args.output:
        output = open(args.output, 'w')

    if args.system_info:
        with open(args.system_info) as f_system_info:
            system_info = json.load(f_system_info)
    else:
        system_info = utils.get_system_info()

    sources = list(system_info['domains'].keys())
    if args.source:
        sources = args.source

    targets = list(system_info['domains'].keys())
    targets.append('@dispvm')
    targets.extend('@dispvm:' + dom for dom in system_info['domains']
        if system_info['domains'][dom]['template_for_dispvms'])

    connections = set()

    policy = parser.FilePolicy(policy_path=args.policy_dir)
    output.write('digraph g {\n')
    services = set()
    for rule in policy.rules:
        services.add((rule.service, rule.argument))
    for service, argument in services:
        if args.service and service not in args.service and \
                not service + (argument or '') in args.service:
            continue

        for source in sources:
            for target in targets:
                try:
                    request = parser.Request(
                         service, argument or '+', source, target,
                         system_info=system_info)
                    action = policy.evaluate(request)
                    line = handle_single_action(args, action)
                    if line in connections:
                        continue
                    if line:
                        output.write(line)
                    connections.add(line)
                except exc.AccessDenied:
                    continue

    output.write('}\n')
    if args.output:
        output.close()

if __name__ == '__main__':
    sys.exit(main())
