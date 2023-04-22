#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include "fuzz.h"

#define MAX_FILES 16

#define MARKER_SIZE 4

static fuzz_file_t files[MAX_FILES];

static void panic(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    abort();
}

static void file_read(fuzz_file_t *file, void *buf, size_t count) {
    assert (count <= file->input_size);
    memcpy(buf, file->input_data, count);
    file->input_data += count;
    file->input_size -= count;
}

static bool file_input_eof(fuzz_file_t *file) {
    return file->input_size == 0;
}

fuzz_file_t *fuzz_file_create(int fd, const void *input_data, size_t input_size) {
    fuzz_file_t *file = &files[fd];
    if (file->allocated) {
        panic("fuzz_file_create: file already allocated");
    }

    file->allocated = true;
    file->fd = fd;
    file->open_read = true;
    file->open_write = true;

    file->input_data = input_data;
    file->input_size = input_size;
    return file;
}

void fuzz_file_destroy(fuzz_file_t *file) {
    file->allocated = false;
}

int fuzz_libvchan_write(fuzz_file_t *file, const void *data, size_t size) {
    return fuzz_write(file->fd, data, size);
}

int fuzz_libvchan_send(fuzz_file_t *file, const void *data, size_t size) {
    return fuzz_write(file->fd, data, size);
}

int fuzz_libvchan_read(fuzz_file_t *file, void *data, size_t size) {
    if (!file->allocated || !file->open_read)
        panic("libvchan_read() from a closed file");

    if (size == 0)
        return 0;

    if (file_input_eof(file))
        return -1;

    if (size > file->input_size)
        size = file->input_size;
    file_read(file, data, size);
    return size;
}

int fuzz_libvchan_recv(fuzz_file_t *file, void *data, size_t size) {
    return fuzz_libvchan_read(file, data, size);
}

int fuzz_libvchan_wait(fuzz_file_t *file) {
    return 0;
}

void fuzz_libvchan_close(fuzz_file_t *file) {
    file->open_read = false;
    file->open_write = false;
}

int fuzz_libvchan_fd_for_select(fuzz_file_t *file) {
    return file->fd;
}

int fuzz_libvchan_is_open(fuzz_file_t *file) {
    return file->open_read && file->open_write;
}

int fuzz_libvchan_data_ready(fuzz_file_t *file) {
    return file->input_size;
}

int fuzz_libvchan_buffer_space(fuzz_file_t *file) {
    return 1024;
}

ssize_t fuzz_read(int fd, void *buf, size_t count) {
    if (!files[fd].allocated || !files[fd].open_read)
        panic("invalid read()");

    if (count == 0)
        return 0;

    if (file_input_eof(&files[fd]))
        return 0;

    if (count > files[fd].input_size)
        count = files[fd].input_size;

    if (count > 0)
        file_read(&files[fd], buf, count);

    return count;
}

volatile char output[256];

ssize_t fuzz_write(int fd, const void *buf, size_t count) {
    if (!files[fd].allocated || !files[fd].open_write)
        panic("invalid write()");

    if (count == 0)
        return 0;

    // Ensure all bytes of buf are accessed
    for (int i = 0; i < count; i += sizeof(output)) {
        size_t n = count - i < sizeof(output) ? count - i : sizeof(output);
        memcpy((void*) output, buf, n);
    }

    return count;
}

fuzz_file_t *fuzz_libvchan_client_init(int domain, int port) {
    /* not implemented yet */
    abort();
}
