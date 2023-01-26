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

from ..utils import sanitize_domain_name, get_system_info
from .qrexec_policy_exec import handle_request
from .. import POLICYPATH, POLICYSOCKET, POLICY_EVAL_SOCKET, POLICY_GUI_SOCKET
from ..policy.utils import PolicyCache

argparser = argparse.ArgumentParser(description="Evaluate qrexec policy daemon")

argparser.add_argument(
    "--policy-path",
    type=pathlib.Path,
    default=POLICYPATH,
    help="Use alternative policy path",
)
argparser.add_argument(
    "--socket-path",
    type=pathlib.Path,
    default=POLICYSOCKET,
    help="Use alternative policy socket path",
)
argparser.add_argument(
    "--eval-socket-path",
    type=pathlib.Path,
    default=POLICY_EVAL_SOCKET,
    help="Use alternative policy eval socket path",
)
argparser.add_argument(
    "--gui-socket-path",
    type=pathlib.Path,
    default=POLICY_GUI_SOCKET,
    help="Use alternative policy gui eval socket path",
)

REQUIRED_REQUEST_ARGUMENTS = (
    "domain_id",
    "source",
    "intended_target",
    "service_and_arg",
    "process_ident",
)

OPTIONAL_REQUEST_ARGUMENTS = ("assume_yes_for_ask", "just_evaluate")

ALLOWED_REQUEST_ARGUMENTS = (
    REQUIRED_REQUEST_ARGUMENTS + OPTIONAL_REQUEST_ARGUMENTS
)


async def handle_client_connection(log, policy_cache, reader, writer):

    args = {}

    try:
        while True:
            line = await reader.readline()
            line = line.decode("ascii").rstrip("\n")

            if not line:
                break

            argument, value = line.split("=", 1)
            if argument in args:
                log.error(
                    "error parsing policy request: "
                    "duplicate argument {}".format(argument)
                )
                return
            if argument not in ALLOWED_REQUEST_ARGUMENTS:
                log.error(
                    "error parsing policy request: unknown argument {}".format(
                        argument
                    )
                )
                return

            if argument in ("assume_yes_for_ask", "just_evaluate"):
                if value == "yes":
                    value = True
                elif value == "no":
                    value = False
                else:
                    log.error(
                        "error parsing policy request: invalid bool value "
                        "{} for argument {}".format(value, argument)
                    )
                    return

            args[argument] = value

        if not all(arg in args for arg in REQUIRED_REQUEST_ARGUMENTS):
            log.error("error parsing policy request: required argument missing")
            return

        result = await handle_request(
            **args, log=log, policy_cache=policy_cache
        )

        writer.write(b"result=allow\n" if result == 0 else b"result=deny\n")
        await writer.drain()

    finally:
        writer.close()


async def read_all_up_to_limit(
    stream: asyncio.StreamReader, limit: int
) -> bytes:
    """
    Read up to ``limit`` bytes.  Retries on partial reads.
    """
    untrusted_data = []
    while limit > 0:
        untrusted_data_just_read = await stream.read(limit)
        if not untrusted_data_just_read:
            break
        limit -= len(untrusted_data_just_read)
        untrusted_data.append(untrusted_data_just_read)
    return b"".join(untrusted_data)


async def _extract_qrexec_parameters(reader):
    """
    Extract data from an incoming socket-based qrexec connection.
    FIXME: make this a reusable library.

    Returns the qrexec command (with argument) and the remote domain.
    Both have already been sanitized by qrexec.
    """
    # Qrexec guarantees that this space will be present.
    qrexec_command_with_arg = (await reader.readuntil(b" "))[:-1].split(b"+", 1)
    try:
        invoked_service, service_argument = qrexec_command_with_arg
    except ValueError:
        invoked_service = qrexec_command_with_arg[0]
        service_argument = None
    # Same with this NUL character.
    qrexec_metadata = (await reader.readuntil(b"\0"))[:-1]
    # The space will only be present in dom0.
    remote_domain = qrexec_metadata.split(b" ", 1)[0].decode("ascii", "strict")
    return invoked_service, service_argument, remote_domain


# pylint: disable=too-many-return-statements,too-many-arguments
async def qrexec_policy_eval(
    log,
    policy_cache,
    check_gui,
    service_name,
    reader,
    writer,
    remote_domain,
    service_queried,
):
    if service_queried is None:
        log.warning(
            "%s requires an argument (the service to query), but"
            "%s did not provide one",
            service_name,
            remote_domain,
        )
        return
    untrusted_data = await read_all_up_to_limit(reader, 96)
    try:
        ### SANITIZE BEGIN
        untrusted_source, untrusted_target = untrusted_data.split(b"\0", 1)
        del untrusted_data

        # Check that qube name lengths are reasonable
        # pylint: disable=superfluous-parens
        if not (1 <= len(untrusted_target) <= 63):
            log.warning(
                "%s: %s sent a target of length %d, but the limit is 63",
                service_name,
                remote_domain,
                len(untrusted_target),
            )
            return
        # pylint: disable=superfluous-parens
        if not (1 <= len(untrusted_source) <= 31):
            log.warning(
                "%s: %s sent a source of length %d, but the limit is 31",
                service_name,
                remote_domain,
                len(untrusted_source),
            )
            return
        untrusted_source = untrusted_source.decode("ascii", "strict")
        untrusted_target = untrusted_target.decode("ascii", "strict")

        # these throw exceptions if the domain name is not valid
        sanitize_domain_name(untrusted_source, True)
        sanitize_domain_name(untrusted_target, True)
        ### SANITIZE END
        source, intended_target = untrusted_source, untrusted_target
    except (ValueError, UnicodeError):
        log.warning(
            "%s: invalid data from qube %s", service_name, remote_domain
        )
        return

    system_info = get_system_info()
    if check_gui:
        domains = system_info["domains"]
        tag = "guivm-" + remote_domain
        for i in (source, intended_target):
            if i not in domains or tag not in domains[i]["tags"]:
                log.warning(
                    "%s can only be invoked by a "
                    "domain that provides GUI to both the source "
                    "and target domains, not %s",
                    service_name,
                    remote_domain,
                )
                return

    result = await handle_request(
        source=source,
        intended_target=intended_target,
        service_and_arg=service_queried.decode("ascii", "strict"),
        domain_id="dummy_id",
        process_ident="0",
        assume_yes_for_ask=True,
        just_evaluate=True,
        log=log,
        policy_cache=policy_cache,
        system_info=system_info,
    )

    writer.write(b"result=allow\n" if result == 0 else b"result=deny\n")
    await writer.drain()


# pylint: disable=too-many-arguments
async def handle_qrexec_connection(
    log, policy_cache, check_gui, service_name, reader, writer
):

    """
    Handle a connection to the qrexec policy socket.
    """
    try:
        (
            invoked_service,
            service_queried,
            remote_domain,
        ) = await _extract_qrexec_parameters(reader)
        if invoked_service != service_name:
            # This is an error because qrexec should forbid this.
            log.error(
                "%s invoked with incorrect name %s by %s",
                service_name,
                invoked_service,
                remote_domain,
            )
            return
        await qrexec_policy_eval(
            log,
            policy_cache,
            check_gui,
            service_name,
            reader,
            writer,
            remote_domain,
            service_queried,
        )
    finally:
        writer.close()


async def start_serving(args=None):
    args = argparser.parse_args(args)

    logging.basicConfig(format="%(message)s")
    log = logging.getLogger("policy")
    log.setLevel(logging.INFO)

    for i in (args.eval_socket_path, args.gui_socket_path, args.socket_path):
        try:
            os.unlink(i)
        except FileNotFoundError:
            pass
    policy_cache = PolicyCache(args.policy_path)
    policy_cache.initialize_watcher()
    policy_server = await asyncio.start_unix_server(
        functools.partial(handle_client_connection, log, policy_cache),
        path=args.socket_path,
    )

    eval_server = await asyncio.start_unix_server(
        functools.partial(
            handle_qrexec_connection,
            log,
            policy_cache,
            False,
            b"policy.EvalSimple",
        ),
        path=args.eval_socket_path,
    )

    gui_eval_server = await asyncio.start_unix_server(
        functools.partial(
            handle_qrexec_connection, log, policy_cache, True, b"policy.EvalGUI"
        ),
        path=args.gui_socket_path,
    )

    for i in (args.eval_socket_path, args.gui_socket_path, args.socket_path):
        os.chmod(i, 0o660)

    await asyncio.wait(
        [
            asyncio.create_task(server.serve_forever())
            for server in (policy_server, eval_server, gui_eval_server)
        ]
    )


def main(args=None):
    import grp

    os.umask(0o007)
    if os.getuid() == 0:
        os.setgid(grp.getgrnam("qubes").gr_gid)
    # pylint: disable=no-member
    # due to travis' limitations we have to use python 3.5 in pylint
    asyncio.run(start_serving(args))


if __name__ == "__main__":
    main()
