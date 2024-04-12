#ifndef _FUZZ_H
#define _FUZZ_H

#include <stdint.h>
#include <signal.h>
#include <poll.h>

struct fuzz_file {
    bool allocated;

    const void *input_data;
    size_t input_size;

    int fd;
    bool open_read, open_write;
};

typedef struct fuzz_file fuzz_file_t;

fuzz_file_t *fuzz_file_create(int fd, const void *input_data, size_t input_size);
void fuzz_file_destroy(fuzz_file_t *file);

int fuzz_libvchan_write(fuzz_file_t *file, const void *data, size_t size);
int fuzz_libvchan_send(fuzz_file_t *file, const void *data, size_t size);
int fuzz_libvchan_read(fuzz_file_t *file, void *data, size_t size);
int fuzz_libvchan_recv(fuzz_file_t *file, void *data, size_t size);
int fuzz_libvchan_wait(fuzz_file_t *file);
void fuzz_libvchan_close(fuzz_file_t *file);
int fuzz_libvchan_fd_for_select(fuzz_file_t *file);
int fuzz_libvchan_is_open(fuzz_file_t *file);
int fuzz_libvchan_data_ready(fuzz_file_t *file);
int fuzz_libvchan_buffer_space(fuzz_file_t *file);
fuzz_file_t *fuzz_libvchan_client_init(int domain, int port);
fuzz_file_t *fuzz_libvchan_client_init_async(int domain, int port, int *fd);
int fuzz_libvchan_client_init_async_finish(fuzz_file_t *file, bool blocking);

ssize_t fuzz_read(int fd, void *buf, size_t count);
ssize_t fuzz_write(int fd, const void *buf, size_t count);

void _Noreturn fuzz_exit(int status);

extern fuzz_file_t *vchan;
extern int protocol_version;
void handle_message_from_agent(void);

#endif
