#ifndef _MOCK_FUZZ_H
#define _MOCK_FUZZ_H

#include "fuzz.h"

#define libvchan_t fuzz_file_t

#define libvchan_write fuzz_libvchan_write
#define libvchan_send fuzz_libvchan_send
#define libvchan_read fuzz_libvchan_read
#define libvchan_recv fuzz_libvchan_recv
#define libvchan_wait fuzz_libvchan_wait
#define libvchan_close fuzz_libvchan_close
#define libvchan_fd_for_select fuzz_libvchan_fd_for_select
#define libvchan_is_open fuzz_libvchan_is_open
#define libvchan_data_ready fuzz_libvchan_data_ready
#define libvchan_buffer_space fuzz_libvchan_buffer_space

#define read fuzz_read
#define write fuzz_write

#endif
