#include <libqrexec-utils.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>

static const long BILLION_NANOSECONDS = 1000000000L;

int qubes_wait_for_vchan_connection_with_timeout(
        libvchan_t *conn, int wait_fd, bool is_server, time_t timeout) {
    struct timespec end_tp, now_tp, timeout_tp;

    if (clock_gettime(CLOCK_MONOTONIC, &end_tp)) {
        PERROR("clock_gettime");
        return -1;
    }
    assert(end_tp.tv_nsec >= 0 && end_tp.tv_nsec < BILLION_NANOSECONDS);
    end_tp.tv_sec += timeout;
    for (;;) {
        bool did_timeout = true;
        struct pollfd fds = { .fd = wait_fd, .events = POLLIN | POLLHUP, .revents = 0 };

        /* calculate how much time left until connection timeout expire */
        if (clock_gettime(CLOCK_MONOTONIC, &now_tp)) {
            PERROR("clock_gettime");
            return -1;
        }
        assert(now_tp.tv_nsec >= 0 && now_tp.tv_nsec < BILLION_NANOSECONDS);
        if (now_tp.tv_sec <= end_tp.tv_sec) {
            timeout_tp.tv_sec = end_tp.tv_sec - now_tp.tv_sec;
            timeout_tp.tv_nsec = end_tp.tv_nsec - now_tp.tv_nsec;
            if (timeout_tp.tv_nsec < 0) {
                timeout_tp.tv_nsec += BILLION_NANOSECONDS;
                timeout_tp.tv_sec--;
            }
            did_timeout = timeout_tp.tv_sec < 0;
        }
        switch (did_timeout ? 0 : ppoll(&fds, 1, &timeout_tp, NULL)) {
            case -1:
                if (errno == EINTR)
                    break;
                LOG(ERROR, "vchan connection error");
                return -1;
            case 0:
                LOG(ERROR, "vchan connection timeout");
                return -1;
            case 1:
                break;
            default:
                abort();
        }
        if (fds.revents & POLLIN) {
            if (is_server) {
                libvchan_wait(conn);
                return 0;
            } else {
                int connect_ret = libvchan_client_init_async_finish(conn, true);

                if (connect_ret < 0) {
                    LOG(ERROR, "vchan connection error");
                    return -1;
                } else if (connect_ret == 0) {
                    return 0;
                }
            }
        }
    }
}
