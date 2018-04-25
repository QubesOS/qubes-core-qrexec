# -*- encoding: utf8 -*-
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
import logging
import logging.handlers
import os

import sys

from ..policy import parser

argparser = argparse.ArgumentParser(description="Evaluate qrexec policy")

argparser.add_argument("--assume-yes-for-ask", action="store_true",
    dest="assume_yes_for_ask", default=False,
    help="Allow run of service without confirmation if policy say 'ask'")
argparser.add_argument("--just-evaluate", action="store_true",
    dest="just_evaluate", default=False,
    help="Do not run the service, only evaluate policy; "
         "retcode=0 means 'allow'")
argparser.add_argument('domain_id', metavar='src-domain-id',
    help='Source domain ID (Xen ID or similar, not Qubes ID)')
argparser.add_argument('domain', metavar='src-domain-name',
    help='Source domain name')
argparser.add_argument('target', metavar='dst-domain-name',
    help='Target domain name')
argparser.add_argument('service_name', metavar='service-name',
    help='Service name')
argparser.add_argument('process_ident', metavar='process-ident',
    help='Qrexec process identifier - for connecting data channel')

DEFAULT_POLICY = '''\
## Policy file automatically created on first service call.
## Fell free to edit.
## Note that policy parsing stops at the first match

## Please use a single # to start your custom comments

@anyvm  @anyvm  ask
'''

def create_default_policy(service_name):
    policy_file = os.path.join(policy.POLICY_DIR, service_name)
    with open(policy_file, "w") as policy:
        policy.write(DEFAULT_POLICY)


def main(args=None):
    args = argparser.parse_args(args)

    # Add source domain information, required by qrexec-client for establishing
    # connection
    caller_ident = args.process_ident + "," + args.domain + "," + args.domain_id
    log = logging.getLogger('policy')
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        log.addHandler(handler)
    log_prefix = 'qrexec: {}: {} -> {}: '.format(
        args.service_name, args.domain, args.target)
    try:
        system_info = policy.get_system_info()
    except policy.QubesMgmtException as e:
        log.error(log_prefix + 'error getting system info: ' + str(e))
        return 1
    try:
        try:
            policy = policy.Policy(args.service_name)
        except policy.PolicyNotFound:
            service_name = args.service_name.split('+')[0]
            import pydbus
            bus = pydbus.SystemBus()
            proxy = bus.get('org.qubesos.PolicyAgent',
                '/org/qubesos/PolicyAgent')
            create_policy = proxy.ConfirmPolicyCreate(
                args.domain, service_name)
            if create_policy:
                create_default_policy(service_name)
                policy = policy.Policy(args.service_name)
            else:
                raise

        action = policy.evaluate(system_info, args.domain, args.target)
        if args.assume_yes_for_ask and action.action == policy.Action.ask:
            action.action = policy.Action.allow
        if args.just_evaluate:
            return {
                policy.Action.allow: 0,
                policy.Action.deny: 1,
                policy.Action.ask: 1,
            }[action.action]
        if action.action == policy.Action.ask:
            # late import to save on time for allow/deny actions
            import pydbus
            bus = pydbus.SystemBus()
            proxy = bus.get('org.qubesos.PolicyAgent',
                '/org/qubesos/PolicyAgent')

            icons = {name: system_info['domains'][name]['icon']
                for name in system_info['domains'].keys()}
            for dispvm_base in system_info['domains']:
                if not (system_info['domains'][dispvm_base]
                        ['template_for_dispvms']):
                    continue
                dispvm_api_name = '@dispvm:' + dispvm_base
                icons[dispvm_api_name] = \
                    system_info['domains'][dispvm_base]['icon']
                icons[dispvm_api_name] = \
                    icons[dispvm_api_name].replace('app', 'disp')

            response = proxy.Ask(args.domain, args.service_name,
                action.targets_for_ask, action.target or '', icons)
            if response:
                action.handle_user_response(True, response)
            else:
                action.handle_user_response(False)
        log.info(log_prefix + 'allowed to {}'.format(action.target))
        action.execute(caller_ident)
    except policy.PolicySyntaxError as e:
        log.error(log_prefix + 'error loading policy: ' + str(e))
        return 1
    except policy.AccessDenied as e:
        log.info(log_prefix + 'denied: ' + str(e))
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
