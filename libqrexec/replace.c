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

void do_replace_chars(char *buf, int len) {
    int i;
    unsigned char c;

    for (i = 0; i < len; i++) {
        c = buf[i];
        if ((c < '\040' || c > '\176') &&  /* not printable ASCII */
            (c != '\t') &&                 /* not tab */
            (c != '\n') &&                 /* not newline */
            (c != '\r') &&                 /* not return */
            (c != '\b') &&                 /* not backspace */
            (c != '\a'))                   /* not bell */
            buf[i] = '_';
    }
}
