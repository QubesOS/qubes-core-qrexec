
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "libqrexec-utils.h"
#include "remote.h"
#include "fuzz.h"

void _Noreturn fuzz_exit(int status) {
    abort();
}

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_file_t *vchan_file, *stdin_file, *local_stderr_file;
    const size_t max_chunk_size = max_data_chunk_size(QREXEC_PROTOCOL_V2);
    struct buffer stdin_buf  = {
        .data = NULL,
        .buflen = 0,
    };
    struct buffer remote_buf = {
        .data = malloc(max_chunk_size),
        .buflen = max_chunk_size,
    };
    if (remote_buf.data == NULL)
        abort();
    int status;

    stdin_file = fuzz_file_create(0, NULL, 0);
    vchan_file = fuzz_file_create(1, data, size);
    local_stderr_file = fuzz_file_create(2, NULL, 0);

    stdin_file->open_read = false;
    local_stderr_file->open_read = false;

    handle_remote_data_v2(
        vchan_file, stdin_file->fd, &status,
        &stdin_buf, false, true, (bool)false,
        &remote_buf);

    fuzz_file_destroy(stdin_file);
    fuzz_file_destroy(vchan_file);
    fuzz_file_destroy(local_stderr_file);
    free(remote_buf.data);
}
