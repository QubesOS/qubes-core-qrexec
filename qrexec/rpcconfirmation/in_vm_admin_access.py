# The Qubes OS Project, https://www.qubes-os.org/
#
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

from .base import BaseRPCConfirmationWindow, FocusStealingHelper


class InVMAdminAccessRPCConfirmationWindow(BaseRPCConfirmationWindow):
    _source_file_ref = importlib.resources.files("qrexec").joinpath(
        os.path.join("glade", "InVMAdminAccessRPCConfirmationWindow.glade")
    )

    @staticmethod
    def match(entries_info, source, service, argument, targets_list, target):
        # pylint: disable=too-many-positional-arguments
        return (
            service == "qubes.AuthorizeInVMAdminAccess"
            and argument == "+"
            and targets_list == ["dom0"]
            and target == "dom0"
        )

    def __init__(
        self, entries_info, source, service, argument, targets_list, target=None
    ):
        # pylint: disable=too-many-positional-arguments
        assert self.match(
            entries_info, source, service, argument, targets_list, target
        )

        super().__init__(
            entries_info, source, service, argument, targets_list, target
        )

        self._update_ok_button_sensitivity(target)

        self._target_entry = self._gtk_builder.get_object("targetEntry")
        self._target_entry.set_text(self._target_name)
        self._list_modeler.apply_icon(self._target_entry, self._target_name)

        self._rpc_ok_button.grab_focus()

    def _new_focus_stealing_helper(self):
        return FocusStealingHelper(
            self._rpc_window, self._rpc_ok_button, 1, True
        )
