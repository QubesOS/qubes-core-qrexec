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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "libqrexec-utils.h"

#define BUFFER_LIMIT 50000000
static int total_mem;
static char *limited_malloc(int len)
{
    char *ret;
    if (__builtin_add_overflow(len, total_mem, &total_mem) ||
        (total_mem > BUFFER_LIMIT) || (len <= 0))
    {
        LOG(ERROR, "attempt to allocate >BUFFER_LIMIT");
        exit(1);
    }
    ret = malloc((size_t)len);
    if (!ret) {
        PERROR("malloc");
        exit(1);
    }
    return ret;
}

static void limited_free(char *ptr, int len)
{
    if (len < 0 || total_mem < len)
        abort();
    free(ptr);
    total_mem -= len;
}

void buffer_init(struct buffer *b)
{
    b->buflen = 0;
    b->data = NULL;
}

void buffer_free(struct buffer *b)
{
    if (b->buflen)
        limited_free(b->data, b->buflen);
    buffer_init(b);
}

#if BUFFER_LIMIT >= INT_MAX / 2
#error BUFFER_LIMIT too large
#endif

/*
   The following two functions can be made much more efficient.
   Yet the profiling output show they are not significant CPU hogs, so
   we keep them so simple to make them obviously correct.
   */

void buffer_append(struct buffer *b, const char *data, int len)
{
    int newsize;
    char *qdata;
    assert(data != NULL && "NULL data");
    if (b->buflen < 0 || b->buflen > BUFFER_LIMIT) {
        LOG(ERROR, "buffer_append buflen %d", len);
        exit(1);
    }
    if (len < 0 || len > BUFFER_LIMIT) {
        LOG(ERROR, "buffer_append %d", len);
        exit(1);
    }
    if (len == 0)
        return;
    newsize = len + b->buflen;
    qdata = limited_malloc(len + b->buflen);
    if (b->data != 0) {
        memcpy(qdata, b->data, (size_t)b->buflen);
    }
    memcpy(qdata + b->buflen, data, (size_t)len);
    buffer_free(b);
    b->buflen = newsize;
    b->data = qdata;
}

void buffer_remove(struct buffer *b, int len)
{
    int newsize;
    char *qdata = NULL;
    if (len < 0 || len > b->buflen) {
        LOG(ERROR, "buffer_remove %d/%d", len, b->buflen);
        exit(1);
    }
    newsize = b->buflen - len;
    if (newsize > 0) {
        qdata = limited_malloc(newsize);
        memcpy(qdata, b->data + len, (size_t)newsize);
    }
    buffer_free(b);
    b->buflen = newsize;
    b->data = qdata;
}

int buffer_len(struct buffer *b)
{
    return b->buflen;
}

void *buffer_data(struct buffer *b)
{
    return b->data;
}
