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
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "libqrexec-utils.h"
#include "ioall.h"

#define QUBESD_SOCK "/run/qubesd.sock"

void set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 && errno == EBADF)
        abort();
    if (fl & O_NONBLOCK)
        return;
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void set_block(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (!(fl & O_NONBLOCK))
        return;
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
}

int write_all(int fd, const void *buf, int size)
{
    int written = 0;
    int ret;
    while (written < size) {
        ret = write(fd, (char *) buf + written, size - written);
        if (ret == -1 && errno == EINTR)
            continue;
        if (ret <= 0) {
            return 0;
        }
        written += ret;
    }
    //      fprintf(stderr, "sent %d bytes\n", size);
    return 1;
}

int read_all(int fd, void *buf, int size)
{
    int got_read = 0;
    int ret;
    while (got_read < size) {
        ret = read(fd, (char *) buf + got_read, size - got_read);
        if (ret == -1 && errno == EINTR)
            continue;
        if (ret == 0) {
            errno = 0;
            LOG(INFO, "EOF");
            return 0;
        }
        if (ret < 0) {
            if (errno != EAGAIN)
                PERROR("read");
            return 0;
        }
        if (got_read == 0) {
            // force blocking operation on further reads
            set_block(fd);
        }
        got_read += ret;
    }
    //      fprintf(stderr, "read %d bytes\n", size);
    return 1;
}

// FIXME: this code is seemingly-correct but needs careful review
void *qubes_read_all_to_malloc(int fd, size_t initial_buffer_size, size_t max_bytes, size_t *len)
{
    size_t buf_size = initial_buffer_size;
    size_t offset = 0;
#if PTRDIFF_MAX < INT_MAX
#error unsupported platform
#endif
    if (max_bytes > (size_t)INT_MAX) {
        LOG(ERROR,
            "Maximum buffer size %zu exceeds INT_MAX (%d)",
            max_bytes,
            INT_MAX);
        abort();
    }
    if (buf_size < 2 || buf_size > max_bytes) {
        LOG(ERROR,
            "Minimum buffer size must between 2 and maximum buffer size (%zu) inclusive, got %zu",
            max_bytes,
            buf_size);
        abort();
    }
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        LOG(ERROR, "malloc() for %zu bytes failed!", buf_size);
        abort();
    }
    *len = 0;
    for (;;) {
        assert(buf_size > offset);
        size_t to_read = buf_size - offset;
        ssize_t res = read(fd, buf + offset, to_read);
        if (res < 0) {
            // save errno as PERROR() and free() might clobber it
            int e = errno;
            if (res != -1)
                abort(); // kernel bug or some sort of corruption
            if (e == EINTR || e == EAGAIN || e == EWOULDBLOCK)
                continue;
            PERROR("recv");
            free(buf);
            errno = e;
            buf = NULL;
            break;
        }
        size_t const bytes_read_this_time = (size_t)res;
        if (bytes_read_this_time == 0) {
            /* EOF */
            buf[offset] = 0;
            *len = offset;
            break;
        }
        if (bytes_read_this_time > to_read)
            abort(); // kernel bug or some sort of corruption
        if (bytes_read_this_time == to_read) {
            /* Buffer full.  See if a new buffer can be allocated. */
            if (buf_size >= max_bytes) {
                /* Nope, limit reached. */
                LOG(ERROR, "Too many bytes read (limit %zu)", max_bytes - 1);
                free(buf);
                errno = ENOBUFS;
                buf = NULL;
                break;
            }
            /* Grow by a factor of 1.5 if possible, but do not exceed the buffer limit. */
            if (max_bytes - buf_size > buf_size / 2)
                buf_size += buf_size / 2;
            else
                buf_size = max_bytes;
            char *new_buf = realloc(buf, buf_size);
            if (new_buf == NULL) {
                /*
                 * Out of memory!  While calling abort() here would be acceptable,
                 * callers need to handle a NULL return _anyway_, so propagating
                 * the error will not make callers more complex.  Therefore, free
                 * the buffer, set errno to ENOMEM, and return NULL.
                 */
                PERROR("realloc()");
                free(buf);
                errno = ENOMEM;
                buf = NULL;
                break;
            } else {
                /*
                 * Old buffer has been freed, so using it is undefined behavior.
                 * Overwrite the pointer to it with the pointer to the new buffer.
                 */
                buf = new_buf;
            }
        }

        /* Advance the offset past the already-read bytes */
        offset += bytes_read_this_time;
    }
    close(fd);
    return buf;
}

int copy_fd_all(int fdout, int fdin)
{
    int ret;
    char buf[4096];
    for (;;) {
        ret = read(fdin, buf, sizeof(buf));
        if (ret == -1 && errno == EINTR)
            continue;
        if (!ret)
            break;
        if (ret < 0) {
            PERROR("read");
            return 0;
        }
        if (!write_all(fdout, buf, ret)) {
            PERROR("write");
            return 0;
        }
    }
    return 1;
}

bool qubes_sendmsg_all(struct msghdr *const msg, int const sock)
{
    while (msg->msg_iovlen > 0) {
        ssize_t const res = sendmsg(sock, msg, MSG_NOSIGNAL);
        if (res < 0) {
            int const i = errno;
            assert(res == -1);
            if (i == EAGAIN || i == EWOULDBLOCK || i == EINTR)
                continue;
            LOG(ERROR, "sendmsg(): %m");
            errno = i;
            return false;
        }

        size_t unsigned_res = (size_t)res;
        for (;;) {
            struct iovec *const v = msg->msg_iov;
            if (unsigned_res < v->iov_len) {
                v->iov_base += unsigned_res;
                v->iov_len -= unsigned_res;
                break;
            }
            unsigned_res -= v->iov_len;
            msg->msg_iovlen--;
            msg->msg_iov++;
            if (msg->msg_iovlen == 0)
                return true;
        }
    }
    return true;
}

char *qubesd_call(const char *dest, char *method, char *arg, size_t *out_len)
{
    return qubesd_call2(dest, method, arg, "", 0, out_len);
}

char *qubesd_call2(const char *dest, char *method, char *arg, const char *payload, size_t len, size_t *out_len)
{
    char *buf = NULL;
    char *word;
    int sock = -1;
    size_t wordlen;
    if (dest[0] == '@') {
        word = " dom0 keyword ";
        wordlen = sizeof(" dom0 keyword ") - 1;
        dest++;
        // assert(valid_keyword(dest + 1));
    } else {
        word = " dom0 name ";
        wordlen = sizeof(" dom0 name ") - 1;
        // assert(valid_qube_name(dest));
    }

    char plus[1] = {'+'};
    struct iovec v[] = {
        { .iov_base = method, .iov_len = strlen(method) },
        { .iov_base = plus, .iov_len = sizeof plus },
        { .iov_base = arg, .iov_len = arg ? strlen(arg) : 0 },
        { .iov_base = word, .iov_len = wordlen },
        { .iov_base = (void *)dest, .iov_len = strlen(dest) + 1 },
        { .iov_base = (void *)payload, .iov_len = len },
    };

    struct sockaddr_un qubesd_sock = {
        .sun_family = AF_UNIX,
        .sun_path = QUBESD_SOCK,
    };

    sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        int i = errno;
        PERROR("socket");
        errno = i;
        goto fail;
    }

    if (connect(sock,
                (struct sockaddr *)&qubesd_sock,
                offsetof(struct sockaddr_un, sun_path) + sizeof(QUBESD_SOCK))) {
        LOG(ERROR, "connect(): %m");
        goto fail;
    }

    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = v,
        .msg_iovlen = sizeof(v)/sizeof(v[0]),
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };

    if (!qubes_sendmsg_all(&msg, sock))
        goto fail;

    if (shutdown(sock, SHUT_WR)) {
        PERROR("shutdown()");
        goto fail;
    }

#define BUF_SIZE 35
#define BUF_MAX 65535
    buf = qubes_read_all_to_malloc(sock, BUF_SIZE, BUF_MAX, out_len);
    if (buf && (*out_len < 2 || strlen(buf) >= *out_len)) {
        LOG(ERROR,
            "Truncated response to %s: got %zu bytes",
            method,
            *out_len);
        goto fail;
    }
out:
    if (sock != -1)
        close(sock);
    return buf;
fail:
    *out_len = 0;
    free(buf);
    buf = 0;
    goto out;
}
