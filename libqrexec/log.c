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
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "libqrexec-utils.h"

static const char *qrexec_program_name = "qrexec";

static void log_time() {
    const size_t buf_len = 32;
    char buf[buf_len];
    struct tm tm_buf;
    struct tm *tm;
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0)
        return;

    if (!(tm = localtime_r(&tv.tv_sec, &tm_buf)))
        return;

    strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S", tm);
    fprintf(stderr, "%s.%03d ", buf, (int)(tv.tv_usec / 1000));
}

static void qrexec_logv(__attribute__((unused)) int level, int errnoval,
                        const char *file, int line,
                        const char *func, const char *fmt, va_list ap) {
    const size_t buf_len = 64;
    char buf[buf_len];
    char *err;
    int _errno = errno;

    log_time();
    fprintf(stderr, "%s[%d]: ", qrexec_program_name, getpid());
    fprintf(stderr, "%s:%d:%s: ", file, line, func);
    vfprintf(stderr, fmt, ap);
    if (errnoval >= 0 && (err = strerror_r(errnoval, buf, buf_len)))
        fprintf(stderr, ": %s", err);
    fprintf(stderr, "\n");
    fflush(stderr);
    errno = _errno;
}

void qrexec_log(int level, int errnoval, const char *file, int line,
                const char *func, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    qrexec_logv(level, errnoval, file, line, func, fmt, ap);
    va_end(ap);
}

void setup_logging(const char *program_name) {
    qrexec_program_name = program_name;
}
