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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <limits.h>
#include <assert.h>

#include "libqrexec-utils.h"

int handle_remote_data(
    libvchan_t *data_vchan, int stdin_fd, int *status,
    struct buffer *stdin_buf, int data_protocol_version,
    bool replace_chars_stdout, bool replace_chars_stderr)
{
    struct msg_header hdr;
    const size_t max_len = max_data_chunk_size(data_protocol_version);
    char *buf;
    int rc = REMOTE_ERROR;

    /* do not receive any data if we have something already buffered */
    switch (flush_client_data(stdin_fd, stdin_buf)) {
        case WRITE_STDIN_OK:
            break;
        case WRITE_STDIN_BUFFERED:
            return REMOTE_OK;
        case WRITE_STDIN_ERROR:
            PERROR("write");
            return REMOTE_EOF;
    }

    buf = malloc(max_len);
    if (!buf) {
        PERROR("malloc");
        return REMOTE_ERROR;
    }

    while (libvchan_data_ready(data_vchan) > 0) {
        if (libvchan_recv(data_vchan, &hdr, sizeof(hdr)) < 0)
            goto out;
        if (hdr.len > max_len) {
            LOG(ERROR, "Too big data chunk received: %" PRIu32 " > %zu",
                hdr.len, max_len);
            goto out;
        }
        if (!read_vchan_all(data_vchan, buf, hdr.len))
            goto out;

        switch (hdr.type) {
            /* handle both directions because this can be either server or client
             * of VM-VM connection */
            case MSG_DATA_STDIN:
            case MSG_DATA_STDOUT:
                if (stdin_fd < 0)
                    /* discard the data */
                    continue;
                if (hdr.len == 0) {
                    rc = REMOTE_EOF;
                    goto out;
                } else {
                    if (replace_chars_stdout)
                        do_replace_chars(buf, hdr.len);
                    switch (write_stdin(stdin_fd, buf, hdr.len, stdin_buf)) {
                        case WRITE_STDIN_OK:
                            break;
                        case WRITE_STDIN_BUFFERED:
                            rc = REMOTE_OK;
                            goto out;
                        case WRITE_STDIN_ERROR:
                            if (!(errno == EPIPE || errno == ECONNRESET)) {
                                PERROR("write");
                            }
                            rc = REMOTE_EOF;
                            goto out;
                    }
                }
                break;
            case MSG_DATA_STDERR:
                if (replace_chars_stderr)
                    do_replace_chars(buf, hdr.len);
                /* stderr of remote service, log locally */
                if (!write_all(2, buf, hdr.len)) {
                    PERROR("write");
                    /* only log the error */
                }
                break;
            case MSG_DATA_EXIT_CODE:
                /* remote process exited, so there is no sense to send any data
                 * to it */
                if (hdr.len < sizeof(*status))
                    *status = 255;
                else
                    memcpy(status, buf, sizeof(*status));
                rc = REMOTE_EXITED;
                goto out;
            default:
                LOG(ERROR, "unknown msg %d", hdr.type);
                rc = REMOTE_ERROR;
                goto out;
        }
    }
    rc = REMOTE_OK;
out:
    free(buf);
    return rc;
}

int handle_input(
    libvchan_t *vchan, int fd, int msg_type,
    int data_protocol_version)
{
    const size_t max_len = max_data_chunk_size(data_protocol_version);
    char *buf;
    ssize_t len;
    struct msg_header hdr;
    int rc = REMOTE_ERROR;

    buf = malloc(max_len);
    if (!buf) {
        PERROR("malloc");
        return REMOTE_ERROR;
    }

    static_assert(SSIZE_MAX >= INT_MAX, "can't happen on Linux");
    hdr.type = msg_type;
    while (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
        len = libvchan_buffer_space(vchan)-sizeof(struct msg_header);
        if ((size_t)len > max_len)
            len = max_len;
        len = read(fd, buf, len);
        /* If the other side of the socket is a process that is already dead,
         * read from such socket could fail with ECONNRESET instead of
         * just 0. */
        if (len < 0 && errno == ECONNRESET)
            len = 0;
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                rc = REMOTE_OK;
            /* otherwise keep rc = REMOTE_ERROR */
            goto out;
        }
        hdr.len = (uint32_t)len;
        /* do not fail on sending EOF (think: close()), it will be handled just below */
        if (libvchan_send(vchan, &hdr, sizeof(hdr)) < 0 && hdr.len != 0)
            goto out;

        if (len && !write_vchan_all(vchan, buf, len))
            goto out;

        if (len == 0) {
            rc = REMOTE_EOF;
            goto out;
        }
    }
    rc = REMOTE_OK;
out:
    free(buf);
    return rc;
}

int send_exit_code(libvchan_t *vchan, int status)
{
    struct msg_header hdr;

    hdr.type = MSG_DATA_EXIT_CODE;
    hdr.len = sizeof(int);
    if (libvchan_send(vchan, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        PERROR("send_exit_code hdr");
        return -1;
    }
    if (libvchan_send(vchan, &status, sizeof(status)) != sizeof(status)) {
        PERROR("send_exit_code status");
        return -1;
    }
    return 0;
}
