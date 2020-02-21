#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2019 Marta Marczykowska-Górecka
#                               <marmarta@invisiblethingslab.com>
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
import functools
import pathlib
import asyncio
import logging
import os

from .qrexec_policy_exec import handle_request
from .. import POLICYPATH, POLICYSOCKET
from ..policy.parser import AllowResolution
from ..policy.utils import PolicyCache

argparser = argparse.ArgumentParser(description='Evaluate qrexec policy daemon')

argparser.add_argument('--policy-path',
    type=pathlib.Path, default=POLICYPATH,
    help='Use alternative policy path')
argparser.add_argument('--socket-path',
    type=pathlib.Path, default=POLICYSOCKET,
    help='Use alternative policy socket path')

REQUIRED_REQUEST_ARGUMENTS = ('domain_id', 'source', 'intended_target',
                              'service_and_arg', 'process_ident')

OPTIONAL_REQUEST_ARGUMENTS = ('assume_yes_for_ask', 'just_evaluate')

ALLOWED_REQUEST_ARGUMENTS = REQUIRED_REQUEST_ARGUMENTS + \
                            OPTIONAL_REQUEST_ARGUMENTS


class DaemonAllowResolution(AllowResolution):
    async def execute(self, caller_ident):

        log_prefix = 'qrexec: {request.service}+{request.argument}: ' \
                     '{request.source} -> {request.target}:'.format(
                      request=self.request)

        log = logging.getLogger('policy')
        log.info('%s allowed to %s', log_prefix, self.target)

        if hasattr(self.request, "origin_writer"):
            self.request.origin_writer.write(b"result=allow\n")
            await self.request.origin_writer.drain()

        await super(DaemonAllowResolution, self).execute(caller_ident)


async def handle_client_connection(log, policy_cache,
                                   reader, writer):

    args = {}

    try:
        while True:
            line = await reader.readline()
            line = line.decode('ascii').rstrip('\n')

            if not line:
                break

            argument, value = line.split('=', 1)
            if argument in args:
                log.error(
                    'error parsing policy request: '
                    'duplicate argument {}'.format(argument))
                return
            if argument not in ALLOWED_REQUEST_ARGUMENTS:
                log.error(
                    'error parsing policy request: unknown argument {}'.format(
                        argument))
                return

            if argument in ('assume_yes_for_ask', 'just_evaluate'):
                if value == 'yes':
                    value = True
                elif value == 'no':
                    value = False
                else:
                    log.error(
                        'error parsing policy request: invalid bool value '
                        '{} for argument {}'.format(value, argument))
                    return

            args[argument] = value

        if not all(arg in args for arg in REQUIRED_REQUEST_ARGUMENTS):
            log.error(
                'error parsing policy request: required argument missing')
            return

        resolution_handler = DaemonAllowResolution

        result = await handle_request(**args, log=log,
                                      allow_resolution_type=resolution_handler,
                                      origin_writer=writer,
                                      policy_cache=policy_cache)

        if result:
            writer.write(b"result=deny\n")
            await writer.drain()

    finally:
        writer.close()


async def start_serving(args=None):
    args = argparser.parse_args(args)

    logging.basicConfig(format="%(message)s")
    log = logging.getLogger('policy')
    log.setLevel(logging.INFO)

    policy_cache = PolicyCache(args.policy_path)
    policy_cache.initialize_watcher()

    server = await asyncio.start_unix_server(
        functools.partial(
            handle_client_connection, log, policy_cache),
        path=args.socket_path)
    os.chmod(args.socket_path, 0o660)

    await server.serve_forever()


def main(args=None):
    # pylint: disable=no-member
    # due to travis' limitations we have to use python 3.5 in pylint
    asyncio.run(start_serving(args))


if __name__ == '__main__':
    main()
