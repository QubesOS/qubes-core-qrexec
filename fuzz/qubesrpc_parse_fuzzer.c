/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2020 Paweł Marczewski <pawel@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "libqrexec-utils.h"

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *cmdline = malloc(size+1);
    if (!cmdline)
        return;
    memcpy(cmdline, data, size);
    cmdline[size] = '\0';

    struct qrexec_parsed_command *cmd = parse_qubes_rpc_command(cmdline, true);

    if (!cmd) {
        free(cmdline);
        return;
    }

    assert(strlen(cmd->username) < size);
    assert(strlen(cmd->command) < size);
    if (cmd->service_descriptor) {
        assert(cmd->service_name);
        assert(cmd->source_domain);
        assert(strlen(cmd->service_descriptor) < size);
        assert(strlen(cmd->service_name) <= strlen(cmd->service_descriptor));
        assert(strlen(cmd->source_domain) < size);
    }
    destroy_qrexec_parsed_command(cmd);
    free(cmdline);
}
