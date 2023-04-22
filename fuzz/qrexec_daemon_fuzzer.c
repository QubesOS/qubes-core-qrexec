#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <setjmp.h>

#include "libqrexec-utils.h"
#include "fuzz.h"

extern fuzz_file_t *vchan;
extern int protocol_version;
extern void handle_message_from_agent(void);

jmp_buf exit_jmp;

void _Noreturn fuzz_exit(int status) {
    longjmp(exit_jmp, status);
}

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_file_t *vchan_file;

    if (!size)
        return;

    protocol_version = data[0];
    if (protocol_version < QREXEC_PROTOCOL_V2 ||
            protocol_version > QREXEC_PROTOCOL_V3)
        return;

    vchan_file = fuzz_file_create(1, data+1, size-1);
    vchan = vchan_file;

    if (setjmp(exit_jmp)) {
        /* clean rejection of invalid data */
        fuzz_file_destroy(vchan_file);
        return;
    }

    handle_message_from_agent();

    /* when reached here, it was correct message */
    fuzz_file_destroy(vchan_file);
}
