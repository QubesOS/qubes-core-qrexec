/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 * Copyright (C) 2013  Marek Marczykowski  <marmarek@invisiblethingslab.com>
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

#ifndef _LIBQREXEC_UTILS_H
#define _LIBQREXEC_UTILS_H

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE 1
#include <signal.h>
#include <stdbool.h>
#include <libvchan.h>
#include <errno.h>
#include <poll.h>

#include <qrexec.h>

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include "mock-fuzz.h"
#endif

struct buffer {
    char *data;
    int buflen;
};

/* return codes for buffered writes */
#define WRITE_STDIN_OK        0 /* all written */
#define WRITE_STDIN_BUFFERED  1 /* something still in the buffer */
#define WRITE_STDIN_ERROR     2 /* write error, errno set */

/* Parsed Qubes RPC or legacy command. */
struct qrexec_parsed_command {
    const char *cmdline;

    /* Username ("user", NULL when strip_username is false) */
    char *username;

    /* Override to disable "wait for session" */
    bool nogui;

    /* Command (the part after "user:") */
    const char *command;

    /* The below parameters are NULL for legacy (non-"QUBESRPC") commands. */

    /* Service descriptor ("qubes.Service+arg").
     * At most MAX_SERVICE_NAME_LEN long.
     */
    char *service_descriptor;

    /* Service name ("qubes.Service").
     * At most NAME_MAX long.
     */
    char *service_name;

    /* Source domain (the part after service name). */
    char *source_domain;
};

/* Parse a command, return NULL on failure. Uses cmd->cmdline
   (do not free until destroy is called) */
struct qrexec_parsed_command *parse_qubes_rpc_command(
    const char *cmdline, bool strip_username);
void destroy_qrexec_parsed_command(struct qrexec_parsed_command *cmd);

/* Load service configuration, currently only wait-for-session option
 * supported.
 *
 * Return:
 *  1  - config successfuly loaded
 *  0  - config not found
 *  -1 - other error
 */
int load_service_config(const struct qrexec_parsed_command *cmd_name,
                        int *wait_for_session);

typedef void (do_exec_t)(const char *cmdline, const char *user);
void register_exec_func(do_exec_t *func);
/*
 * exec() qubes-rpc-multiplexer if *prog* starts with magic "QUBESRPC" keyword,
 * do not return in that case; pass *envp* to execve() as en environment
 * otherwise, return false without any action
 */
void exec_qubes_rpc_if_requested(const char *prog, char *const envp[]);

int exec_wait_for_session(const char *source_domain);

void buffer_init(struct buffer *b);
void buffer_free(struct buffer *b);
void buffer_append(struct buffer *b, const char *data, int len);
void buffer_remove(struct buffer *b, int len);
int buffer_len(struct buffer *b);
void *buffer_data(struct buffer *b);

int flush_client_data(int fd, struct buffer *buffer);
int write_stdin(int fd, const char *data, int len, struct buffer *buffer);
int fork_and_flush_stdin(int fd, struct buffer *buffer);

/**
 * @param cmdline Null-terminated command to execute.
 * @param pid On return, holds the PID of the child process.
 * @param stdin_fd On return, holds a file descriptor connected to the child's
 * stdin.
 * @param stdout_fd On return, holds a file descriptor connected to the child's
 * stdout.
 * @param stderr_fd On return, holds a file descriptor connected to the child's
 * stderr.
 * @param strip_username True if the username needs to be stripped from the
 * command.  Only the fork server should set this to false.
 * @param buffer This buffer will need to be prepended to the child process’s
 * stdin.
 * @return 0 if it spawned (or might have spawned) an external process,
 * a (positive) errno value otherwise.
 */
int execute_qubes_rpc_command(const char *cmdline, int *pid, int *stdin_fd,
                              int *stdout_fd, int *stderr_fd,
                              bool strip_username, struct buffer *buffer);
/*
 * A version of ppoll() that also correctly handles vchan's event pending
 * flag.  fds[0] is used internally and fds[0].fd must be equal to -1 on entry.
 */
int ppoll_vchan(libvchan_t *ctrl, struct pollfd *fds, size_t nfds,
                struct timespec *timeout, const sigset_t *sigmask);

/*
 * A version of pselect() that also correctly handles vchan's event pending
 * flag.
 */
int pselect_vchan(libvchan_t *ctrl, int nfds, fd_set *rdset, fd_set *wrset,
                  struct timespec *timeout, const sigset_t *sigmask);

int read_vchan_all(libvchan_t *vchan, void *data, size_t size);
int write_vchan_all(libvchan_t *vchan, const void *data, size_t size);
int read_all(int fd, void *buf, int size);
int write_all(int fd, const void *buf, int size);
void fix_fds(int fdin, int fdout, int fderr);
void set_nonblock(int fd);
void set_block(int fd);

int get_server_socket(const char *);
int do_accept(int s);

void set_nonblock(int fd);

static inline size_t max_data_chunk_size(int protocol_version) {
    if (protocol_version < QREXEC_PROTOCOL_V3)
        return MAX_DATA_CHUNK_V2;
    else
        return MAX_DATA_CHUNK_V3;
}
#define ARRAY_SIZE(s) (sizeof(s)/sizeof(s[0]))

/* Replace all non-printable characters by '_' */
void do_replace_chars(char *buf, int len);

/* return codes for handle_remote_data and handle_input */
#define REMOTE_EXITED -2
#define REMOTE_ERROR  -1
#define REMOTE_EOF     0
#define REMOTE_OK      1

/*
 * Handle data from vchan. Sends MSG_DATA_STDIN and MSG_DATA_STDOUT to
 * specified FD (unless it's -1), and MSG_DATA_STDERR to our stderr.
 *
 * Return codes:
 *   REMOTE_EXITED - remote process terminated, do not send more data to it
 *     ("status" will be set)
 *   REMOTE_ERROR - vchan error occured
 *   REMOTE_EOF - EOF received, do not access this FD again
 *   REMOTE_OK - maybe some data processed, call again when buffer space and
 *     more data available
 *
 * Options:
 *   replace_chars_stdout, replace_chars_stderr - remove non-printable
 *     characters from stdout/stderr
 */
int handle_remote_data(
    libvchan_t *data_vchan, int stdin_fd, int *status,
    struct buffer *stdin_buf, int data_protocol_version,
    bool replace_chars_stdout, bool replace_chars_stderr, bool is_service);

struct prefix_data {
    const char *data;
    size_t len;
};

/*
 * Handle data from the specified FD (cannot be -1) and send it over vchan
 * with a given message type (MSG_DATA_STDIN/STDOUT/STDERR).
 *
 * Return codes:
 *   REMOTE_ERROR - vchan error occured
 *   REMOTE_EOF - EOF received, do not access this FD again
 *   REMOTE_OK - some data processed, call it again when buffer space and
 *     more data availabla
 */
int handle_input(
    libvchan_t *vchan, int fd, int msg_type,
    int data_protocol_version, struct prefix_data *data);

int send_exit_code(libvchan_t *vchan, int status);

/* Set of options for process_io(). */
struct process_io_request {
    libvchan_t *vchan;
    struct buffer *stdin_buf;

    // stderr_fd can be -1
    int stdin_fd, stdout_fd, stderr_fd;
    // 0 if no child process
    pid_t local_pid;

    /*
      is_service true (this is a service):
        - send local data as MSG_DATA_STDOUT
        - send exit code
        - wait just for local end
        - return local exit code

      is_service false (this is a client):
        - send local data as MSG_DATA_STDIN
        - don't send exit code
        - wait for local and remote end
        - return remote exit code
     */
    bool is_service;

    bool replace_chars_stdout;
    bool replace_chars_stderr;
    int data_protocol_version;

    volatile sig_atomic_t *sigchld;
    // can be NULL
    volatile sig_atomic_t *sigusr1;
    struct prefix_data prefix_data;
};

/*
 * Pass IO between vchan and local FDs. See the comments for
 * process_io_request.
 *
 * Returns intended exit code (local or remote), but calls exit() on errors.
 */
int process_io(const struct process_io_request *req);

// Logging

#define DEBUG    1
#define INFO     2
#define WARNING  3
#define ERROR    4

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define LOG(...)
#define LOGE(...)
#define PERROR(...)
#else

#define LOG(level, fmt, args...) \
    qrexec_log(level, -1, __FILE__, __LINE__, __func__, fmt, ##args)
#define LOGE(level, fmt, args...) \
    qrexec_log(level, errno, __FILE__, __LINE__, __func__, fmt, ##args)
#define PERROR(fmt, args...) \
    qrexec_log(ERROR, errno, __FILE__, __LINE__, __func__, fmt, ##args)

#endif


void qrexec_log(int level, int errnoval, const char *file, int line,
                const char *func, const char *fmt, ...);

void setup_logging(const char *program_name);

#endif /* _LIBQREXEC_UTILS_H */
