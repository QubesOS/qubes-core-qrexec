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
import subprocess
from typing import Optional, List, Union, Dict, Type

from .. import DEFAULT_POLICY, QREXEC_CLIENT, POLICYPATH
from .. import exc
from .. import utils
from ..policy import parser
from ..policy.utils import PolicyCache
from ..server import call_socket_service


def create_default_policy(service_name):
    with open(str(POLICYPATH / service_name), "w", encoding='utf-8') as policy:
        policy.write(DEFAULT_POLICY)


class JustEvaluateAllowResolution(parser.AllowResolution):
    async def execute(self) -> str:
        return "result=allow"


class JustEvaluateAskResolution(parser.AskResolution):
    async def execute(self) -> str:
        return "result=deny"


class AssumeYesForAskResolution(parser.AskResolution):
    async def execute(self) -> str:
        return await self.handle_user_response(
            True, self.request.target
        ).execute()


class AgentAskResolution(parser.AskResolution):
    async def execute(self) -> str:
        domains = self.request.system_info["domains"]
        guivm = domains[self.request.source]["guivm"]
        if not guivm:
            log = logging.getLogger("policy")
            log.error(
                '%s not allowed from %s: the resolution was "ask", '
                "but source domain has no GuiVM",
                self.request.service,
                self.request.source,
            )
            self.handle_user_response(False, None)
            assert False, "handle_user_response should throw"

        # prepare icons
        icons = {name: domains[name]["icon"] for name in domains.keys()
                 if not name.startswith("uuid:")}
        for dispvm_base in domains:
            if (dispvm_base.startswith("uuid:")
                or not domains[dispvm_base]["template_for_dispvms"]):
                continue
            dispvm_api_name = "@dispvm:" + dispvm_base
            icons[dispvm_api_name] = domains[dispvm_base]["icon"]
            icons[dispvm_api_name] = icons[dispvm_api_name].replace(
                "app", "disp"
            )

        params = {
            "source": self.request.source,
            "service": self.request.service,
            "argument": self.request.argument,
            "targets": self.targets_for_ask,
            "default_target": self.default_target or "",
            "icons": icons,
        }

        service = "policy.Ask"
        source_domain = "dom0"
        ask_response = await call_socket_service(
            guivm, service, source_domain, params
        )

        if ask_response == "deny":
            self.handle_user_response(False, None)
            assert False, "handle_user_response should throw"

        if ask_response.startswith("allow:"):
            target = ask_response[len("allow:") :]
            resolution = self.handle_user_response(True, target)
            return await resolution.execute()

        log = logging.getLogger("policy")
        log.error(
            "invalid ask response for %s: %s",
            self.request.service,
            ask_response,
        )
        self.handle_invalid_response()
        # pylint: disable=unreachable
        assert False, "handle_invalid_response should throw"


class NotifyAllowedResolution(parser.AllowResolution):
    async def execute(self) -> str:
        try:
            guivm = self.request.system_info["domains"][self.request.source][
                "guivm"
            ]
        except KeyError:
            guivm = None

        if self.notify:
            if guivm:
                await notify(
                    guivm,
                    {
                        "resolution": "allow",
                        "service": self.request.service,
                        "argument": self.request.argument,
                        "source": self.request.source,
                        "target": self.target,
                    },
                )
        return await super().execute()


async def notify(guivm, params):
    service = "policy.Notify"
    source_domain = "dom0"
    try:
        await call_socket_service(guivm, service, source_domain, params)
    # pylint: disable=broad-except
    except Exception:
        # qrexec-policy-agent might be dead or malfunctioning, log exception
        # but do not fail the whole operation
        log = logging.getLogger("policy")
        log.exception("error calling qrexec-policy-agent in %s", guivm)


class LogAllowedResolution(NotifyAllowedResolution):
    async def execute(self) -> str:
        log_prefix = (
            "qrexec: {request.service}{request.argument}: "
            "{request.source} -> {request.target}:".format(request=self.request)
        )

        log = logging.getLogger("policy")
        log.info("%s allowed to %s", log_prefix, self.target)

        return await super().execute()


def prepare_resolution_types(
    *, just_evaluate, assume_yes_for_ask, allow_resolution_type
):
    ret = {
        "ask_resolution_type": AgentAskResolution,
        "allow_resolution_type": allow_resolution_type,
    }
    if just_evaluate:
        ret["ask_resolution_type"] = JustEvaluateAskResolution
        ret["allow_resolution_type"] = JustEvaluateAllowResolution
    if assume_yes_for_ask:
        ret["ask_resolution_type"] = AssumeYesForAskResolution
    return ret


argparser = argparse.ArgumentParser(usage="""qrexec-policy-exec -h
usage: qrexec-policy-exec [--assume-yes-for-ask] [--just-evaluate] [--path PATH] SOURCE TARGET service+argument
usage: qrexec-policy-exec [--assume-yes-for-ask] [--just-evaluate] [--path PATH] domain-id SOURCE TARGET service+argument process-ident

To evaluate policy, pass 3 positional arguments:

- Source domain name
- Target domain name
- Service name and argument separated by "+"

To actually run a qrexec call, pass 5 positional arguments:

- Source domain ID (Xen or similar, not Qubes ID)
- Source domain name
- Target domain name
- Service name and argument separated by "+"
- Qrexec process identifier (for data channel connection)

Note that this usage is deprecated.
""")

argparser.add_argument(
    "--assume-yes-for-ask",
    action="store_true",
    dest="assume_yes_for_ask",
    default=False,
    help="Allow run of service without confirmation if policy say 'ask'",
)
argparser.add_argument(
    "--just-evaluate",
    action="store_true",
    dest="just_evaluate",
    default=False,
    help="Do not run the service, only evaluate policy; "
    "retcode=0 means 'allow'",
)
argparser.add_argument(
    "--path",
    type=pathlib.Path,
    default=POLICYPATH,
    help="Use alternative policy path",
)
argparser.add_argument(
    "args",
    nargs="*",
)

# pylint: disable=too-many-locals
def get_result(args: Optional[List[str]]) -> Union[str, int]:
    parsed_args = argparser.parse_args(args)

    log = logging.getLogger("policy")
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.handlers.SysLogHandler(address="/dev/log")
        log.addHandler(handler)

    policy_cache = PolicyCache(parsed_args.path)

    just_evaluate: bool = parsed_args.just_evaluate
    args: List[str] = parsed_args.args
    arglen = len(args)
    no_exec = not just_evaluate
    if arglen == 3:
        source, intended_target, service_and_arg = args
    elif arglen == 5:
        domain_id, source, intended_target, service_and_arg, process_ident = args
        no_exec = False
    else:
        argparser.error(f"Must have 3 or 5 positional arguments, not {arglen!r}")
        assert False, "argparser.error should raise"
    result_str = asyncio.run(
        handle_request(
            source,
            intended_target,
            service_and_arg,
            log,
            just_evaluate=just_evaluate,
            assume_yes_for_ask=parsed_args.assume_yes_for_ask,
            policy_cache=policy_cache,
        )
    )

    if no_exec:
        return result_str
    result: Dict[str, str] = {}
    for i in result_str.split("\n"):
        assert "=" in i, f"bad policy response {result_str!r}"
        k, value = i.split("=", 1)
        assert k not in result, f"key {k!r} already parsed"
        result[k] = value
    if result["result"] != "allow":
        return 1
    if just_evaluate:
        return 0
    target = result["target"]
    dispvm = target.startswith("@dispvm:")
    cmd = f"QUBESRPC {service_and_arg} {source}"
    if target in ("dom0", "@adminvm"):
        target_type = "name"
        if intended_target[0] == '@':
            target_type = "keyword"
            intended_target = intended_target[1:]
        cmd += f" {target_type} {intended_target}"
    else:
        target = result["target_uuid"]
        cmd = f"{result['user'] or 'DEFAULT'}:" + cmd
        if dispvm:
            target = (utils.qubesd_call(target, "admin.vm.CreateDisposable", payload=b"uuid")
                           .decode("ascii", "strict"))
        utils.qubesd_call(target, "admin.vm.Start")
    # pylint: disable=possibly-used-before-assignment
    return subprocess.call((
        QREXEC_CLIENT,
        "-EWkd" if dispvm else "-Ed",
        target,
        "-c",
        ",".join((process_ident, source, domain_id)),
        "--",
        cmd,
    ))

def main(args=None) -> int:
    result = get_result(args)
    if isinstance(result, str):
        sys.stdout.write(result)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return 0 if (
            "\nresult=allow\n" in result or
            result == "result=allow"
        ) else 1
    return result

# pylint: disable=too-many-arguments,too-many-locals
async def handle_request(
    source: str,
    intended_target: str,
    service_and_arg: str,
    log,
    just_evaluate: bool = False,
    assume_yes_for_ask: bool = False,
    allow_resolution_type: Optional[type]=None,
    policy_cache=None,
    system_info=None,
) -> str:
    # Add source domain information, required by qrexec-client for establishing
    # connection
    log_prefix = f"qrexec: {service_and_arg}: {source} -> {intended_target}:"
    if system_info is None:
        try:
            system_info = utils.get_system_info()
        except exc.QubesMgmtException as err:
            log.error("%s error getting system info: %s", log_prefix, err)
            return "result=deny"
    try:
        i = service_and_arg.index("+")
        service, argument = service_and_arg[:i], service_and_arg[i:]
    except ValueError:
        service, argument = service_and_arg, "+"

    try:
        if policy_cache:
            policy = policy_cache.get_policy()
        else:
            policy = parser.FilePolicy(policy_path=POLICYPATH)

        allow_resolution_class: Type[parser.AllowResolution]
        if allow_resolution_type is None:
            allow_resolution_class = LogAllowedResolution
        else:
            allow_resolution_class = allow_resolution_type

        request = parser.Request(
            service,
            argument,
            source,
            intended_target,
            system_info=system_info,
            **prepare_resolution_types(
                just_evaluate=just_evaluate,
                assume_yes_for_ask=assume_yes_for_ask,
                allow_resolution_type=allow_resolution_class,
            )
        )
        resolution = policy.evaluate(request)
        return await resolution.execute()

    except exc.PolicySyntaxError as err:
        log.error("%s error loading policy: %s", log_prefix, err)
        return "result=deny"
    except exc.AccessDenied as err:
        log.info("%s denied: %s", log_prefix, err)

        if err.notify and not just_evaluate:
            guivm = system_info["domains"][source]["guivm"]
            if guivm:
                await notify(
                    guivm,
                    {
                        "resolution": "deny",
                        "service": service,
                        "argument": argument,
                        "source": source,
                        "target": intended_target,
                    },
                )

        return "result=deny"


if __name__ == "__main__":
    sys.exit(main())
