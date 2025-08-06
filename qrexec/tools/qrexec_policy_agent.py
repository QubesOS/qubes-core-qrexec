#!/usr/bin/python
#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017 boring-stuff <boring-stuff@users.noreply.github.com>
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

""" Agent running in user session, responsible for asking the user about policy
decisions."""

import argparse
import asyncio

# pylint: disable=import-error,wrong-import-position
import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gio

try:
    from gi.events import GLibEventLoopPolicy

    HAS_GBULB = False
except ImportError:
    import gbulb

    HAS_GBULB = True

from .. import POLICY_AGENT_SOCKET_PATH
from ..server import SocketService

from ..rpcconfirmation.generic import RPCConfirmationWindow
from ..rpcconfirmation.in_vm_admin_access import (
    InVMAdminAccessRPCConfirmationWindow,
)

# pylint: enable=wrong-import-position


async def confirm_rpc(
    entries_info, source, service, argument, targets_list, target=None
):
    # pylint: disable=too-many-positional-arguments
    for win_class in [
        InVMAdminAccessRPCConfirmationWindow,
        RPCConfirmationWindow,  # matches every request
    ]:
        if win_class.match(
            entries_info, source, service, argument, targets_list, target
        ):
            window = win_class(
                entries_info, source, service, argument, targets_list, target
            )
            break

    return await window.confirm_rpc()


class PolicyAgent(SocketService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._app = Gtk.Application()
        self._app.set_application_id("qubes.qrexec-policy-agent")
        self._app.register()

    async def handle_request(self, params, service, source_domain):
        if service == "policy.Ask":
            return await self.handle_ask(params)
        if service == "policy.Notify":
            return await self.handle_notify(params)
        raise ValueError("unknown service name: {}".format(service))

    @staticmethod
    async def handle_ask(params):
        source = params["source"]
        service = params["service"]
        argument = params["argument"]
        targets = params["targets"]
        default_target = params["default_target"]

        entries_info = {}
        for domain_name, icon in params["icons"].items():
            entries_info[domain_name] = {"icon": icon}

        target = await confirm_rpc(
            entries_info,
            source,
            service,
            argument,
            targets,
            default_target or None,
        )

        if target:
            return f"allow:{target}"
        return "deny"

    async def handle_notify(self, params):
        resolution = params["resolution"]
        service = params["service"]
        argument = params["argument"]
        source = params["source"]
        target = params["target"]

        assert resolution in ["allow", "deny", "fail"], resolution

        self.notify(resolution, service, argument, source, target)
        return ""

    def notify(self, resolution, service, argument, source, target):
        # pylint: disable=too-many-arguments,too-many-positional-arguments
        if argument == "+":
            rpc = service
        else:
            rpc = service + argument

        if resolution == "allow":
            app_icon = None
            summary = "Allowed: {service}"
            body = (
                "Allowed <b>{rpc}</b> "
                "from <b>{source}</b> to <b>{target}</b>"
            )
        elif resolution == "deny":
            app_icon = "dialog-error"
            summary = "Denied: {service}"
            body = "Denied <b>{rpc}</b> from <b>{source}</b> to <b>{target}</b>"
        elif resolution == "fail":
            app_icon = "dialog-warning"
            summary = "Failed: {service}"
            body = (
                "Failed to execute <b>{rpc}</b> "
                "(from <b>{source}</b> to <b>{target}</b>)"
            )
        else:
            assert False, resolution

        # summary is plain text, body is markup
        summary = summary.format(service=service)
        body = body.format(
            rpc=GLib.markup_escape_text(rpc),
            source=GLib.markup_escape_text(source),
            target=GLib.markup_escape_text(target),
        )

        notification = Gio.Notification.new(summary)
        notification.set_priority(Gio.NotificationPriority.NORMAL)
        notification.set_body(body)
        if app_icon:
            icon = Gio.ThemedIcon.new(app_icon)
            notification.set_icon(icon)

        self._app.send_notification(None, notification)


parser = argparse.ArgumentParser()

parser.add_argument(
    "-s",
    "--socket-path",
    metavar="DIR",
    type=str,
    default=POLICY_AGENT_SOCKET_PATH,
    help="path to socket",
)


def main():
    args = parser.parse_args()

    if HAS_GBULB:
        # pylint: disable=used-before-assignment
        gbulb.install()
    else:
        asyncio.set_event_loop_policy(GLibEventLoopPolicy())
    loop = asyncio.get_event_loop()
    agent = PolicyAgent(args.socket_path)

    loop.run_until_complete(agent.run())


if __name__ == "__main__":
    main()
