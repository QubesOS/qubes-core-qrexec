/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 * Copyright (C) 2013  Marek Marczykowski  <marmarek@invisiblethingslab.com>
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

#include <stdbool.h>
#include <libvchan.h>

#pragma GCC visibility push(hidden)

/*
 * Handle data from vchan. Sends MSG_DATA_STDIN and MSG_DATA_STDOUT to
 * specified FD (unless it's -1), and MSG_DATA_STDERR to our stderr.
 *
 * Return codes:
 *   REMOTE_EXITED - remote process terminated, do not send more data to it
 *     ("status" will be set)
 *   REMOTE_ERROR - vchan error occured
 *   REMOTE_EOF - EOF received, do not access this FD again
 *   REMOTE_OK - maybe some data processed, call again when buffer space and
 *     more data available
 *
 * Options:
 *   replace_chars_stdout, replace_chars_stderr - remove non-printable
 *     characters from stdout/stderr
 *
 * stdin_buf is the buffer holding data to be written to stdin, and may
 * be modified or reallocated.  Its content must be valid data, and on
 * return it will be a valid buffer pointing to valid (generally different)
 * data.
 *
 * buffer is scratch space _only_.  Its size must be the maximum data
 * chunk size.  Its contents (the data pointed to) does _not_ need to be
 * initialized, and will _not_ be anything meaningful on return.  The
 * buffer pointer and length will not be changed and will remain valid,
 * though.  In Rust terms: this is an &mut [MaybeUninit<u8>].
 */
int handle_remote_data_v2(
    libvchan_t *data_vchan, int stdin_fd, int *status,
    struct buffer *stdin_buf,
    bool replace_chars_stdout, bool replace_chars_stderr, bool is_service,
    const struct buffer *buffer);

/*
 * Handle data from the specified FD (cannot be -1) and send it over vchan
 * with a given message type (MSG_DATA_STDIN/STDOUT/STDERR).
 *
 * Return codes:
 *   REMOTE_ERROR - vchan error occured
 *   REMOTE_EOF - EOF received, do not access this FD again
 *   REMOTE_OK - some data processed, call it again when buffer space and
 *     more data availabla
 *
 * buffer is scratch space _only_.  Its size must be the maximum data
 * chunk size.  Its contents (the data pointed to) does _not_ need to be
 * initialized, and will _not_ be anything meaningful on return.  The
 * buffer pointer and length will not be freed or reallocated, though.
 * In Rust terms: this is an &mut [MaybeUninit<u8>].
 *
 * If out_fd is not -1, all data written is duplicated to it.
 */
int handle_input_v2(
    libvchan_t *vchan, int fd, int msg_type,
    struct prefix_data *prefix_data,
    const struct buffer *buffer,
    int out_fd);
#pragma GCC visibility pop
