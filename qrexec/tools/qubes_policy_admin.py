#!/usr/bin/env python3

#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2018  Wojtek Porczyk <woju@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <https://www.gnu.org/licenses/>.
#

"""
qubes-policy-admin - a QubesRPC script for policy API
"""

import os
import sys
import logging

from ..policy.admin import PolicyAdmin, PolicyAdminException
from .. import POLICYPATH


def main():
    logging.basicConfig(
        level=logging.INFO,
        filename="/var/log/qubes/policy-admin.log",
        format="%(asctime)s %(message)s",
    )

    service_full_name = os.environ["QREXEC_SERVICE_FULL_NAME"]
    source = os.environ["QREXEC_REMOTE_DOMAIN"]

    if "+" in service_full_name:
        service_name, argument = service_full_name.split("+", 1)
    else:
        service_name, argument = service_full_name, ""

    payload = sys.stdin.buffer.read()

    admin = PolicyAdmin(POLICYPATH)
    try:
        response = admin.handle_request(service_name, argument, payload)
    except PolicyAdminException as exc:
        logging.warning(
            "%s+%s (%s): error: %s", service_name, argument, source, exc
        )
        print(exc)
        sys.exit(1)
    except Exception:  # pylint: disable=broad-except
        logging.exception(
            "%s+%s (%s): exception", service_name, argument, source
        )
        print(
            "Internal error. See /var/log/qubes/policy-admin.log in dom0 for details."
        )
        sys.exit(2)
    else:
        logging.info("%s+%s (%s)", service_name, argument, source)
        if response is not None:
            sys.stdout.buffer.write(response)


if __name__ == "__main__":
    main()
