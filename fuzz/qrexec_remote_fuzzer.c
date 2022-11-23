
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "libqrexec-utils.h"
#include "fuzz.h"


void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_file_t *vchan_file, *stdin_file, *local_stderr_file;
    struct buffer stdin_buf;
    int status;

    stdin_file = fuzz_file_create(0, NULL, 0);
    vchan_file = fuzz_file_create(1, data, size);
    local_stderr_file = fuzz_file_create(2, NULL, 0);

    stdin_file->open_read = false;
    local_stderr_file->open_read = false;

    buffer_init(&stdin_buf);

    handle_remote_data(
        vchan_file, stdin_file->fd, &status,
        &stdin_buf, QREXEC_PROTOCOL_V2,
        false, true, false);

    fuzz_file_destroy(stdin_file);
    fuzz_file_destroy(vchan_file);
    fuzz_file_destroy(local_stderr_file);
}
