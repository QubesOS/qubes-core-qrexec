/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <libvchan.h>
#include <assert.h>

#include "libqrexec-utils.h"

int pselect_vchan(libvchan_t *ctrl, int nfds, fd_set *rdset, fd_set *wrset,
                  struct timespec *timeout, const sigset_t *sigmask) {
    struct timespec zero_timeout = { 0, 0 };
    int vchan_fd;
    int ret;

    vchan_fd = libvchan_fd_for_select(ctrl);
    assert(vchan_fd < FD_SETSIZE);
    FD_SET(vchan_fd, rdset);
    if (vchan_fd + 1 > nfds)
        nfds = vchan_fd + 1;

    if (libvchan_data_ready(ctrl) > 0) {
        /* check for other FDs, but exit immediately */
        ret = pselect(nfds, rdset, wrset, NULL, &zero_timeout, sigmask);
    } else {
        ret = pselect(nfds, rdset, wrset, NULL, timeout, sigmask);
    }

    /* clear event pending flag, this shouldn't block */
    if (ret > 0 && FD_ISSET(vchan_fd, rdset))
        libvchan_wait(ctrl);

    return ret;
}

int write_vchan_all(libvchan_t *vchan, const void *data, size_t size) {
    size_t pos;
    int ret;

    pos = 0;
    while (pos < size) {
        ret = libvchan_write(vchan, data+pos, size-pos);
        if (ret < 0)
            return 0;
        pos += ret;
    }
    return 1;
}

int read_vchan_all(libvchan_t *vchan, void *data, size_t size) {
    size_t pos;
    int ret;

    pos = 0;
    while (pos < size) {
        ret = libvchan_read(vchan, data+pos, size-pos);
        if (ret < 0)
            return 0;
        pos += ret;
    }
    return 1;
}
