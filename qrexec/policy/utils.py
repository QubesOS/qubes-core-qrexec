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
import asyncio
import os.path
import pyinotify
from qrexec import POLICYPATH, POLICYPATH_OLD, RUNTIME_POLICY_PATH
from . import parser


class PolicyCache:
    def __init__(
        self, path=(RUNTIME_POLICY_PATH, POLICYPATH), use_legacy=True, lazy_load=False
    ) -> None:
        self.paths = list(path)
        self.outdated = lazy_load
        if lazy_load:
            self.policy = None
        else:
            self.policy = parser.FilePolicy(policy_path=self.paths)

        # default policy paths are listed manually, for compatibility with R4.0
        # to be removed in Qubes 5.0
        if use_legacy:
            self.default_policy_paths = [str(POLICYPATH), str(POLICYPATH_OLD)]
        else:
            self.default_policy_paths = []

        self.watch_manager = None
        self.watches = []
        self.notifier = None

    def initialize_watcher(self):
        self.watch_manager = pyinotify.WatchManager()

        # pylint: disable=no-member
        mask = (
            pyinotify.IN_CREATE |
            pyinotify.IN_DELETE |
            pyinotify.IN_MODIFY |
            pyinotify.IN_MOVED_FROM |
            pyinotify.IN_MOVED_TO
        )

        loop = asyncio.get_event_loop()

        self.notifier = pyinotify.AsyncioNotifier(
            self.watch_manager, loop, default_proc_fun=PolicyWatcher(self)
        )

        for path in self.paths:
            str_path = str(path)
            if str_path not in self.default_policy_paths and os.path.exists(str_path):
                self.watches.append(
                    self.watch_manager.add_watch(
                        str_path, mask, rec=True, auto_add=True
                    )
                )

        for path in self.default_policy_paths:
            if not os.path.exists(path):
                continue
            self.watches.append(
                self.watch_manager.add_watch(str(path), mask, rec=True, auto_add=True)
            )

    def cleanup(self):
        for wdd in self.watches:
            self.watch_manager.rm_watch(list(wdd.values()))
        self.watches = []

        if self.notifier is not None:
            self.notifier.stop()
        self.notifier = None
        self.watch_manager = None

    def get_policy(self):
        if self.outdated:
            self.policy = parser.FilePolicy(policy_path=self.paths)
            self.outdated = False

        return self.policy


class PolicyWatcher(pyinotify.ProcessEvent):
    def __init__(self, cache):
        self.cache = cache
        super().__init__()

    def process_IN_CREATE(self, _):
        self.cache.outdated = True

    def process_IN_DELETE(self, _):
        self.cache.outdated = True

    def process_IN_MODIFY(self, _):
        self.cache.outdated = True

    def process_IN_MOVED_TO(self, _):
        self.cache.outdated = True

    def process_IN_MOVED_FROM(self, _):
        self.cache.outdated = True
