# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017 boring-stuff <boring-stuff@users.noreply.github.com>
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
# Copyright (C) 2025 Simon Gaiser <simon@invisiblethingslab.com>
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

import os
import importlib.resources

from .base import BaseRPCConfirmationWindow


class RPCConfirmationWindow(BaseRPCConfirmationWindow):
    _source_file_ref = importlib.resources.files("qrexec").joinpath(
        os.path.join("glade", "RPCConfirmationWindow.glade")
    )

    @staticmethod
    def match(entries_info, source, service, argument, targets_list, target):
        # pylint: disable=too-many-positional-arguments,unused-argument
        return True

    def __init__(
        self, entries_info, source, service, argument, targets_list, target=None
    ):
        # pylint: disable=too-many-positional-arguments
        assert self.match(
            entries_info, source, service, argument, targets_list, target
        )

        self._init_gtk_builder()
        self._rpc_combo_box = self._gtk_builder.get_object("TargetCombo")
        self._error_bar = self._gtk_builder.get_object("ErrorBar")
        self._error_message = self._gtk_builder.get_object("ErrorMessage")

        super().__init__(
            entries_info, source, service, argument, targets_list, target
        )

        self._list_modeler.apply_model(
            self._rpc_combo_box,
            targets_list,
            selection_trigger=self._update_ok_button_sensitivity,
            activation_trigger=self._clicked_ok,
        )

        self._set_initial_target(source, target)

    def _connect_events(self):
        super()._connect_events()

        self._error_bar.connect("response", self._close_error)

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
