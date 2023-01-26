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

import itertools
import os
import argparse
import asyncio

import pkg_resources

# pylint: disable=import-error,wrong-import-position
import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GdkPixbuf, GLib, Gio

# pylint: enable=import-error

# pylint: disable=wrong-import-order
import gbulb

from .. import POLICY_AGENT_SOCKET_PATH
from ..utils import sanitize_domain_name, sanitize_service_name
from ..server import SocketService

# pylint: enable=wrong-import-position


class VMListModeler:
    def __init__(self, domains_info=None):
        self._entries = {}
        self._domains_info = domains_info
        self._icons = {}
        self._icon_size = 16
        self._theme = Gtk.IconTheme.get_default()
        self._create_entries()

    def _get_icon(self, name):
        if name not in self._icons:
            try:
                icon = self._theme.load_icon(name, self._icon_size, 0)
            except GLib.Error:  # pylint: disable=catching-non-exception
                icon = self._theme.load_icon("edit-find", self._icon_size, 0)

            self._icons[name] = icon

        return self._icons[name]

    def _create_entries(self):
        for name, vm in self._domains_info.items():
            if name.startswith("@dispvm:"):
                vm_name = name[len("@dispvm:") :]
                dispvm = True
            else:
                vm_name = name
                dispvm = False
            sanitize_domain_name(vm_name, assert_sanitized=True)

            icon = self._get_icon(vm.get("icon", None))

            if dispvm:
                display_name = "Disposable VM ({})".format(vm_name)
            else:
                display_name = vm_name
            self._entries[display_name] = {
                "api_name": name,
                "icon": icon,
                "vm": vm,
            }

    def _get_valid_qube_name(self, combo, entry_box, whitelist):
        name = None

        if combo and combo.get_active_id():
            selected = combo.get_active_id()

            if (
                selected in self._entries
                and self._entries[selected]["api_name"] in whitelist
            ):
                name = selected

        if not name and entry_box:
            typed = entry_box.get_text()

            if (
                typed in self._entries
                and self._entries[typed]["api_name"] in whitelist
            ):
                name = typed

        return name

    def _combo_change(self, selection_trigger, combo, entry_box, whitelist):
        data = None
        name = self._get_valid_qube_name(combo, entry_box, whitelist)

        if name:
            entry = self._entries[name]

            data = entry["api_name"]

            if entry_box:
                entry_box.set_icon_from_pixbuf(
                    Gtk.EntryIconPosition.PRIMARY, entry["icon"]
                )
        else:
            if entry_box:
                entry_box.set_icon_from_stock(
                    Gtk.EntryIconPosition.PRIMARY, "gtk-find"
                )

        if selection_trigger:
            selection_trigger(data)

    def _entry_activate(self, activation_trigger, combo, entry_box, whitelist):
        name = self._get_valid_qube_name(combo, entry_box, whitelist)

        if name:
            activation_trigger(entry_box)

    def apply_model(
        self,
        destination_object,
        vm_list,
        selection_trigger=None,
        activation_trigger=None,
    ):
        if isinstance(destination_object, Gtk.ComboBox):
            list_store = Gtk.ListStore(int, str, GdkPixbuf.Pixbuf, str)

            for entry_no, display_name in zip(
                itertools.count(), sorted(self._entries)
            ):
                entry = self._entries[display_name]
                if entry["api_name"] in vm_list:
                    list_store.append(
                        [
                            entry_no,
                            display_name,
                            entry["icon"],
                            entry["api_name"],
                        ]
                    )

            destination_object.set_model(list_store)
            destination_object.set_id_column(1)

            icon_column = Gtk.CellRendererPixbuf()
            destination_object.pack_start(icon_column, False)
            destination_object.add_attribute(icon_column, "pixbuf", 2)
            destination_object.set_entry_text_column(1)

            if destination_object.get_has_entry():
                entry_box = destination_object.get_child()

                area = Gtk.CellAreaBox()
                area.pack_start(icon_column, False, False, False)
                area.add_attribute(icon_column, "pixbuf", 2)

                completion = Gtk.EntryCompletion.new_with_area(area)
                completion.set_inline_selection(True)
                completion.set_inline_completion(True)
                completion.set_popup_completion(True)
                completion.set_popup_single_match(False)
                completion.set_model(list_store)
                completion.set_text_column(1)

                entry_box.set_completion(completion)
                if activation_trigger:
                    entry_box.connect(
                        "activate",
                        lambda entry: self._entry_activate(
                            activation_trigger,
                            destination_object,
                            entry,
                            vm_list,
                        ),
                    )

                # A Combo with an entry has a text column already
                text_column = destination_object.get_cells()[0]
                destination_object.reorder(text_column, 1)
            else:
                entry_box = None

                text_column = Gtk.CellRendererText()
                destination_object.pack_start(text_column, False)
                destination_object.add_attribute(text_column, "text", 1)

            changed_function = lambda combo: self._combo_change(
                selection_trigger, combo, entry_box, vm_list
            )

            destination_object.connect("changed", changed_function)
            changed_function(destination_object)

        else:
            raise TypeError(
                "Only expecting Gtk.ComboBox objects to want our model."
            )

    def apply_icon(self, entry, qube_name):
        if isinstance(entry, Gtk.Entry):
            if qube_name in self._entries:
                entry.set_icon_from_pixbuf(
                    Gtk.EntryIconPosition.PRIMARY,
                    self._entries[qube_name]["icon"],
                )
            else:
                raise ValueError("The specified source qube does not exist!")
        else:
            raise TypeError(
                "Only expecting Gtk.Entry objects to want our icon."
            )


class GtkOneTimerHelper:
    # pylint: disable=too-few-public-methods
    def __init__(self, wait_seconds):
        self._wait_seconds = wait_seconds
        self._current_timer_id = 0
        self._timer_completed = False

    def _invalidate_timer_completed(self):
        self._timer_completed = False

    def _invalidate_current_timer(self):
        self._current_timer_id += 1

    def _timer_check_run(self, timer_id):
        if self._current_timer_id == timer_id:
            self._timer_run(timer_id)
            self._timer_completed = True
        else:
            pass

    def _timer_run(self, timer_id):
        raise NotImplementedError("Not yet implemented")

    def _timer_schedule(self):
        self._invalidate_current_timer()
        GLib.timeout_add(
            int(round(self._wait_seconds * 1000)),
            self._timer_check_run,
            self._current_timer_id,
        )

    def _timer_has_completed(self):
        return self._timer_completed


class FocusStealingHelper(GtkOneTimerHelper):
    def __init__(self, window, target_button, wait_seconds=1):
        GtkOneTimerHelper.__init__(self, wait_seconds)
        self._window = window
        self._target_button = target_button

        self._window.connect("window-state-event", self._window_state_event)

        self._target_sensitivity = False
        self._target_button.set_sensitive(self._target_sensitivity)

    def _window_changed_focus(self, window_is_focused):
        self._target_button.set_sensitive(False)
        self._invalidate_timer_completed()

        if window_is_focused:
            self._timer_schedule()
        else:
            self._invalidate_current_timer()

    def _window_state_event(self, window, event):
        assert (
            window == self._window
        ), "Window state callback called with wrong window"

        changed_focus = event.changed_mask & Gdk.WindowState.FOCUSED
        window_focus = event.new_window_state & Gdk.WindowState.FOCUSED

        if changed_focus:
            self._window_changed_focus(window_focus != 0)

        # Propagate event further
        return False

    def _timer_run(self, timer_id):
        self._target_button.set_sensitive(self._target_sensitivity)

    def request_sensitivity(self, sensitivity):
        if self._timer_has_completed() or not sensitivity:
            self._target_button.set_sensitive(sensitivity)

        self._target_sensitivity = sensitivity

    def can_perform_action(self):
        return self._timer_has_completed()


class RPCConfirmationWindow:
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
    _source_file = pkg_resources.resource_filename(
        "qrexec", os.path.join("glade", "RPCConfirmationWindow.glade")
    )
    _source_id = {
        "window": "RPCConfirmationWindow",
        "ok": "okButton",
        "cancel": "cancelButton",
        "source": "sourceEntry",
        "rpc_label": "rpcLabel",
        "target": "TargetCombo",
        "error_bar": "ErrorBar",
        "error_message": "ErrorMessage",
    }

    def _clicked_ok(self, source):
        assert (
            source is not None
        ), "Called the clicked ok callback from no source object"

        if self._can_perform_action():
            self._confirmed = True
            self._close()

    def _clicked_cancel(self, button):
        assert (
            button == self._rpc_cancel_button
        ), "Called the clicked cancel callback through the wrong button"

        if self._can_perform_action():
            self._confirmed = False
            self._close()

    def _key_pressed(self, window, key):
        assert (
            window == self._rpc_window
        ), "Key pressed callback called with wrong window"

        if self._can_perform_action():
            if key.keyval == Gdk.KEY_Escape:
                self._confirmed = False
                self._close()

    def _update_ok_button_sensitivity(self, data):
        valid = data is not None

        if valid:
            self._target_name = data
        else:
            self._target_name = None

        self._focus_helper.request_sensitivity(valid)

    def _show_error(self, error_message):
        self._error_message.set_text(error_message)
        self._error_bar.set_visible(True)

    def _close_error(self, error_bar, response):
        assert (
            error_bar == self._error_bar
        ), "Closed the error bar with the wrong error bar as parameter"
        assert (
            response is not None
        ), "Closed the error bar with None as a response"

        self._error_bar.set_visible(False)

    def _set_initial_target(self, source, target):
        if target is not None:
            if target == source:
                self._show_error(
                    "Source and target domains must not be the same."
                )
            else:
                model = self._rpc_combo_box.get_model()

                found = False
                for item in model:
                    if item[3] == target:
                        found = True

                        self._rpc_combo_box.set_active_iter(
                            model.get_iter(item.path)
                        )

                        break

                if not found:
                    self._show_error("Domain '%s' doesn't exist." % target)

    def _can_perform_action(self):
        return self._focus_helper.can_perform_action()

    def _connect_events(self):
        self._rpc_window.connect("key-press-event", self._key_pressed)
        self._rpc_ok_button.connect("clicked", self._clicked_ok)
        self._rpc_cancel_button.connect("clicked", self._clicked_cancel)

        self._error_bar.connect("response", self._close_error)

    def __init__(
        self, entries_info, source, service, argument, targets_list, target=None
    ):
        # pylint: disable=too-many-arguments
        sanitize_domain_name(source, assert_sanitized=True)
        sanitize_service_name(source, assert_sanitized=True)

        self._gtk_builder = Gtk.Builder()
        self._gtk_builder.add_from_file(self._source_file)
        self._rpc_window = self._gtk_builder.get_object(
            self._source_id["window"]
        )
        self._rpc_ok_button = self._gtk_builder.get_object(
            self._source_id["ok"]
        )
        self._rpc_cancel_button = self._gtk_builder.get_object(
            self._source_id["cancel"]
        )
        self._rpc_label = self._gtk_builder.get_object(
            self._source_id["rpc_label"]
        )
        self._source_entry = self._gtk_builder.get_object(
            self._source_id["source"]
        )
        self._rpc_combo_box = self._gtk_builder.get_object(
            self._source_id["target"]
        )
        self._error_bar = self._gtk_builder.get_object(
            self._source_id["error_bar"]
        )
        self._error_message = self._gtk_builder.get_object(
            self._source_id["error_message"]
        )
        self._target_name = None

        self._focus_helper = self._new_focus_stealing_helper()

        self._rpc_label.set_markup(
            escape_and_format_rpc_text(service, argument)
        )

        self._entries_info = entries_info
        list_modeler = self._new_vm_list_modeler()

        list_modeler.apply_model(
            self._rpc_combo_box,
            targets_list,
            selection_trigger=self._update_ok_button_sensitivity,
            activation_trigger=self._clicked_ok,
        )

        self._source_entry.set_text(source)
        list_modeler.apply_icon(self._source_entry, source)

        self._confirmed = None

        self._set_initial_target(source, target)

        self._connect_events()

    def _close(self):
        self._rpc_window.close()

    async def _wait_for_close(self):
        await gbulb.wait_signal(self._rpc_window, "delete-event")

    def _show(self):
        self._rpc_window.set_keep_above(True)
        self._rpc_window.show_all()

    def _new_vm_list_modeler(self):
        return VMListModeler(self._entries_info)

    def _new_focus_stealing_helper(self):
        return FocusStealingHelper(self._rpc_window, self._rpc_ok_button, 1)

    async def confirm_rpc(self):
        self._show()
        await self._wait_for_close()

        if self._confirmed:
            return self._target_name
        return False


async def confirm_rpc(
    entries_info, source, service, argument, targets_list, target=None
):
    # pylint: disable=too-many-arguments
    window = RPCConfirmationWindow(
        entries_info, source, service, argument, targets_list, target
    )

    return await window.confirm_rpc()


def escape_and_format_rpc_text(service, argument=""):
    service = GLib.markup_escape_text(service)
    argument = GLib.markup_escape_text(argument)

    domain, dot, name = service.partition(".")
    if dot and name:
        result = "{}.<b>{}</b>".format(domain, name)
    else:
        result = "<b>{}</b>".format(service)

    if argument != "+":
        result += argument

    return result


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
        raise Exception("unknown service name: {}".format(service))

    async def handle_ask(self, params):
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
            return "allow:{}".format(target)
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
        # pylint: disable=too-many-arguments
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
            body = (
                "Denied <b>{rpc}</b> from <b>{source}</b> to <b>{target}</b>"
            )
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

    gbulb.install()
    agent = PolicyAgent(args.socket_path)

    loop = asyncio.get_event_loop()
    tasks = [
        asyncio.create_task(agent.run()),
    ]
    loop.run_until_complete(asyncio.wait(tasks))


if __name__ == "__main__":
    main()
