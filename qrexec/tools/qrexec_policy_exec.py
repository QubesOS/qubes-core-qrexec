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
#

import argparse
import logging
import logging.handlers
import pathlib
import sys
import asyncio
import functools

from .. import DEFAULT_POLICY, POLICYPATH
from .. import exc
from .. import utils
from ..policy import parser

def create_default_policy(service_name):
    with open(str(POLICYPATH / service_name), 'w') as policy:
        policy.write(DEFAULT_POLICY)

class JustEvaluateAllowResolution(parser.AllowResolution):
    async def execute(self, caller_ident):
        sys.exit(0)

class JustEvaluateAskResolution(parser.AskResolution):
    async def execute(self, caller_ident):
        sys.exit(1)

class AssumeYesForAskResolution(parser.AskResolution):
    async def execute(self, caller_ident):
        return await self.handle_user_response(True, self.request.target).execute(
            caller_ident)

class DBusAskResolution(parser.AskResolution):
    async def execute(self, caller_ident):
        import pydbus
        bus = pydbus.SystemBus()
        proxy = bus.get('org.qubesos.PolicyAgent',
            '/org/qubesos/PolicyAgent')

        # prepare icons
        icons = {name: self.request.system_info['domains'][name]['icon']
            for name in self.request.system_info['domains'].keys()}
        for dispvm_base in self.request.system_info['domains']:
            if not (self.request.system_info['domains'][dispvm_base]
                    ['template_for_dispvms']):
                continue
            dispvm_api_name = '@dispvm:' + dispvm_base
            icons[dispvm_api_name] = \
                self.request.system_info['domains'][dispvm_base]['icon']
            icons[dispvm_api_name] = \
                icons[dispvm_api_name].replace('app', 'disp')

        response = proxy.Ask(self.request.source, self.request.service,
            self.targets_for_ask, self.default_target or '', icons)

        if response:
            return await self.handle_user_response(True, response).execute(
                caller_ident)
        return self.handle_user_response(False, None)


class LogAllowedResolution(parser.AllowResolution):
    def __init__(self, log, *args, **kwargs):
        super(LogAllowedResolution, self).__init__(*args, **kwargs)
        self.log = log

    async def execute(self, caller_ident):
        log_prefix = 'qrexec: {request.service}{request.argument}: ' \
                     '{request.source} -> {request.target}:'.format(
                      request=self.request)
        self.log.info('%s allowed to %s', log_prefix, self.target)

        await super(LogAllowedResolution, self).execute(caller_ident)


def prepare_resolution_types(*, just_evaluate, assume_yes_for_ask,
                             allow_resolution_type):
    ret = {
        'ask_resolution_type': DBusAskResolution,
        'allow_resolution_type': allow_resolution_type}
    if just_evaluate:
        ret['ask_resolution_type'] = JustEvaluateAskResolution
        ret['allow_resolution_type'] = JustEvaluateAllowResolution
    if assume_yes_for_ask:
        ret['ask_resolution_type'] = AssumeYesForAskResolution
    return ret

argparser = argparse.ArgumentParser(description='Evaluate qrexec policy')

argparser.add_argument('--assume-yes-for-ask', action='store_true',
    dest='assume_yes_for_ask', default=False,
    help='Allow run of service without confirmation if policy say \'ask\'')
argparser.add_argument('--just-evaluate', action='store_true',
    dest='just_evaluate', default=False,
    help='Do not run the service, only evaluate policy; '
         'retcode=0 means \'allow\'')
argparser.add_argument('--path',
    type=pathlib.Path, default=POLICYPATH,
    help='Use alternative policy path')

argparser.add_argument('domain_id', metavar='src-domain-id',
    help='Source domain ID (Xen ID or similar, not Qubes ID)')
argparser.add_argument('source', metavar='SOURCE',
    help='Source domain name')
argparser.add_argument('intended_target', metavar='TARGET',
    help='Target domain name')
argparser.add_argument('service_and_arg', metavar='SERVICE+ARGUMENT',
    help='Service name')
argparser.add_argument('process_ident', metavar='process-ident',
    help='Qrexec process identifier - for connecting data channel')

def main(args=None):
    args = argparser.parse_args(args)

    log = logging.getLogger('policy')
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        log.addHandler(handler)

    return asyncio.run(handle_request(
        args.domain_id,
        args.source,
        args.intended_target,
        args.service_and_arg,
        args.process_ident,
        log,
        path=args.path,
        just_evaluate=args.just_evaluate,
        assume_yes_for_ask=args.assume_yes_for_ask))

# pylint: disable=too-many-arguments
async def handle_request(domain_id, source, intended_target, service_and_arg,
                   process_ident, log, path=POLICYPATH, just_evaluate=False,
                   assume_yes_for_ask=False, daemon_execution=None):
    # Add source domain information, required by qrexec-client for establishing
    # connection
    caller_ident = process_ident + "," + source + "," + domain_id
    log_prefix = 'qrexec: {}: {} -> {}:'.format(
        service_and_arg, source, intended_target)
    try:
        system_info = utils.get_system_info()
    except exc.QubesMgmtException as err:
        log.error('%s error getting system info: %s', log_prefix, err)
        return 1
    try:
        i = service_and_arg.index('+')
        service, argument = service_and_arg[:i], service_and_arg[i:]
    except ValueError:
        service, argument = service_and_arg, '+'
    try:
        policy = parser.FilePolicy(policy_path=path)

        if daemon_execution:
            allow_resolution_type = daemon_execution
        else:
            allow_resolution_type = functools.partial(LogAllowedResolution, log)

        request = parser.Request(
            service, argument, source, intended_target,
            system_info=system_info,
            **prepare_resolution_types(
                just_evaluate=just_evaluate,
                assume_yes_for_ask=assume_yes_for_ask,
                allow_resolution_type=allow_resolution_type))
        resolution = policy.evaluate(request)
        # await resolution.execute(caller_ident)
        result = await resolution.execute(caller_ident)
        if result is not None:
            resolution = result
        if not daemon_execution:
            log.info('%s allowed to %s', log_prefix, str(resolution.target))

    except exc.PolicySyntaxError as err:
        log.error('%s error loading policy: %s', log_prefix, err)
        return 1
    except exc.AccessDenied as err:
        log.info('%s denied: %s', log_prefix, err)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
