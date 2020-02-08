# -*- encoding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2020  Paweł Marczewski  <pawel@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

import time


def wait_until(func, message, n_tries=10, delay=0.1):
    for _ in range(n_tries):
        if func():
            return
        time.sleep(delay)
    raise Exception('Timed out waiting: ' + message)


def sort_messages(messages):
    '''
    Sort a list of messages (message_type, data) by message type.
    Useful because the order of messages from multiple streams is not
    deterministic wrt stdout/stderr.
    '''
    # Python sort is stable, so it will not reorder messages with the same
    # type.
    return sorted(messages, key=lambda m: m[0])
