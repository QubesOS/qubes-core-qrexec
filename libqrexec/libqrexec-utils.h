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

#ifndef LIBQREXEC_UTILS_H
#define LIBQREXEC_UTILS_H

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE 1
#include <signal.h>
#include <stdbool.h>
#include <libvchan.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

#include <libvchan.h>
#include <qrexec.h>

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include "mock-fuzz.h"
#endif

/** A (usually) heap-allocated buffer type.  The buffer_* functions
 * assume the buffer is heap-allocated. */
struct buffer {
    /** Pointer to the data. */
    char *data;
    /* Length of the data; never negative. */
    int buflen;
};

/* return codes for buffered writes */
#define WRITE_STDIN_OK        0 /* all written */
#define WRITE_STDIN_BUFFERED  1 /* something still in the buffer */
#define WRITE_STDIN_ERROR     2 /* write error, errno set */

/* Parsed Qubes RPC or legacy command.
 * The size of this structure is not part of the public API or ABI.
 * Only use instances allocated by libqrexec-utils. */
struct qrexec_parsed_command {
    const char *cmdline;

    /* Username ("user", NULL when strip_username is false).
     * Always safe to pass to free(). */
    char *username;

    /* Override to disable "wait for session" */
    bool nogui;

    /* Command (the part after "user:").  If this is an RPC command
     * then the "QUBESRPC " prefix is not included. */
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

    /* Should a session be waited for? */
    bool wait_for_session;

    /* For socket-based services: Should the service descriptor be sent? */
    bool send_service_descriptor;

    /* Remaining fields are private to libqrexec-utils.  Do not access them
     * directly - they may change in any update. */

    /* For socket-based services: Should the event loop exit on EOF from
     * the client? */
    bool exit_on_stdin_eof;

    /* For socket-based services: Should the event loop exit on EOF from
     * the service? */
    bool exit_on_stdout_eof;

    /* Pointer to the argument, or NULL if there is no argument.
     * Same buffer as "service_descriptor". */
    char *arg;
    /* length of the command */
    size_t service_descriptor_len;
};

/* Parse a command, return NULL on failure. Uses cmd->cmdline
   (do not free until destroy is called) */
__attribute__((visibility("default")))
struct qrexec_parsed_command *parse_qubes_rpc_command(
    const char *cmdline, bool strip_username);
/* Free a parsed command */
__attribute__((visibility("default")))
void destroy_qrexec_parsed_command(struct qrexec_parsed_command *cmd);

/* Load service configuration.
 *
 * Return:
 *  1  - config successfuly loaded
 *  0  - config not found
 *  -1 - other error
 *
 * Deprecated, use load_service_config_v2() instead.
 */
int load_service_config(struct qrexec_parsed_command *cmd_name,
                        int *wait_for_session, char **user)
    __attribute__((deprecated("use load_service_config_v2() instead"), visibility("default")));
/* Load service configuration.
 *
 * Return:
 *  1  - config successfuly loaded
 *  0  - config not found
 *  -1 - other error
 */
__attribute__((visibility("default")))
int load_service_config_v2(struct qrexec_parsed_command *cmd_name);

typedef void (do_exec_t)(const char *program, const char *cmd, const char *user);
__attribute__((visibility("default")))
void register_exec_func(do_exec_t *func);

/**
 * \param program Full path to program to execute.
 * \param cmd RPC command, excluding "QUBESRPC " prefix.
 * \param envp Environment passed to execve().
 * \param use_shell If true, use a login shell to spawn the program.
 *
 * Execute *program* as an RPC service or call _exit() on failure.
 * *cmd* is used to set the argument (if any) and "QREXEC_*" environment variables.
 * Environment variables in *envp* that start with "QREXEC" are ignored, except for
 * "QREXEC_SERVICE_PATH" and "QREXEC_AGENT_PID", which are inherited.
 */
__attribute__((visibility("default")))
_Noreturn void exec_qubes_rpc2(const char *program, const char *cmd, char *const envp[],
                               bool use_shell);

/* Execute `qubes.WaitForSession` service, do not return on success, return -1
 * (maybe setting errno) on failure. */
__attribute__((visibility("default")))
int exec_wait_for_session(const char *source_domain);

/* Initialize a buffer */
__attribute__((visibility("default")))
void buffer_init(struct buffer *b);
/* Free a buffer, setting its pointer to NULL and length to zero. */
void buffer_free(struct buffer *b);
void buffer_append(struct buffer *b, const char *data, int len);
void buffer_remove(struct buffer *b, int len);
int buffer_len(struct buffer *b);
void *buffer_data(struct buffer *b);

int flush_client_data(int fd, struct buffer *buffer);
int write_stdin(int fd, const char *data, int len, struct buffer *buffer);

/**
 * @brief Execute an already-parsed Qubes RPC command.
 * @param cmd Already-parsed command to execute.
 * @param pid On return, holds the PID of the child process.
 * @param stdin_fd On return, holds a file descriptor connected to the child's
 * stdin.
 * @param stdout_fd On return, holds a file descriptor connected to the child's
 * stdout.
 * @param stderr_fd On return, holds a file descriptor connected to the child's
 * stderr.
 * @param buffer This buffer will need to be prepended to the child process’s
 * stdin.
 * @return 0 if it spawned (or might have spawned) an external process,
 * nonzero on failure.
 */
__attribute__((visibility("default")))
int execute_parsed_qubes_rpc_command(
        struct qrexec_parsed_command *cmd, int *pid, int *stdin_fd,
        int *stdout_fd, int *stderr_fd, struct buffer *stdin_buffer);

/**
 * @brief Find the implementation of a Qubes RPC command. If it is a socket,
 *        connect to it.
 * @param[in] cmdline Null-terminated command to execute.
 * @param[out] socket_fd On successful return, holds a file descriptor connected to
 * the socket, or -1 for executable services.
 * @param stdin_buffer This buffer will need to be prepended to the child process’s
 * stdin.
 * @param path_buffer This buffer (NUL-terminated) holds the service's path.  On
 * entry it must be at least NAME_MAX bytes.  It will not be freed or reallocated.
 * Its contents should be ignored if stdout_fd is not -1.
 * @return 0 if the implementation is found (and, for sockets, connected to)
 * successfully, -1 if not found, -2 if problem.
 */
__attribute__((visibility("default")))
int find_qrexec_service(
        struct qrexec_parsed_command *cmd,
        int *socket_fd, struct buffer *stdin_buffer,
        struct buffer *path_buffer);

/** Suggested buffer size for the path buffer of find_qrexec_service. */
#define QUBES_SOCKADDR_UN_MAX_PATH_LEN 1024

/**
 * @brief Execute a Qubes RPC command.
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
 * nonzero on failure.
 */
__attribute__((visibility("default")))
int execute_qubes_rpc_command(const char *cmdline, int *pid, int *stdin_fd,
                              int *stdout_fd, int *stderr_fd,
                              bool strip_username, struct buffer *buffer);
/*
 * A version of ppoll() that also correctly handles vchan's event pending
 * flag.  fds[0] is used internally and fds[0].fd must be equal to -1 on entry.
 */
__attribute__((visibility("default")))
int ppoll_vchan(libvchan_t *ctrl, struct pollfd *fds, size_t nfds,
                struct timespec *timeout, const sigset_t *sigmask);

__attribute__((visibility("default")))
int read_vchan_all(libvchan_t *vchan, void *data, size_t size);
__attribute__((visibility("default")))
int write_vchan_all(libvchan_t *vchan, const void *data, size_t size);
__attribute__((visibility("default")))
int read_all(int fd, void *buf, int size);
__attribute__((visibility("default")))
int write_all(int fd, const void *buf, int size);
__attribute__((visibility("default")))
void fix_fds(int fdin, int fdout, int fderr);
void set_nonblock(int fd);
void set_block(int fd);

__attribute__((visibility("default")))
int get_server_socket(const char *);
__attribute__((visibility("default")))
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

struct prefix_data {
    const char *data;
    size_t len;
};

__attribute__((visibility("default")))
int send_exit_code(libvchan_t *vchan, int status);

/* Set of options for process_io(). */
struct process_io_request {
    libvchan_t *vchan;
    struct buffer *stdin_buf;

    /* Note that stdin_fd, stdout_fd, and stderr_fd are named assuming a
     * *local* process.  For a *remote* process, stdin_fd is the standard
     * *output*, stdout_fd is the standard *input*, and stderr_fd must be -1. */
    // stderr_fd can be -1
    int stdin_fd, stdout_fd, stderr_fd, logger_fd;
    // 0 if no child process
    pid_t local_pid;

    /*
      is_service true (this is a service):
        - send local data as MSG_DATA_STDOUT
        - send local stderr as MSG_DATA_STDERR, unless in dom0
        - send exit code
        - wait just for local end
        - return local exit code

      is_service false (this is a client):
        - send local data as MSG_DATA_STDIN
        - stderr_fd is always -1
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
/** Open an FD to a logger */
__attribute__((visibility("default")))
int open_logger(struct qrexec_parsed_command *command, int *pid);

/*
 * Pass IO between vchan and local FDs. See the comments for
 * process_io_request.
 *
 * Returns intended exit code (local or remote), but calls exit() on errors.
 *
 * Deprecated, use qrexec_process_io() instead.
 */
__attribute__((visibility("default"), warn_unused_result))
int process_io(const struct process_io_request *req);

/*
 * Pass IO between vchan and local FDs. See the comments for
 * process_io_request.
 *
 * Returns intended exit code (local or remote), but calls exit() on errors.
 *
 * cmd may be NULL to use the default behavior.
 */
__attribute__((visibility("default"), warn_unused_result))
int qrexec_process_io(const struct process_io_request *req,
                      const struct qrexec_parsed_command *cmd);

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

__attribute__((visibility("default")))
void qrexec_log(int level, int errnoval, const char *file, int line,
                const char *func, const char *fmt, ...) __attribute__((format(printf, 6, 7)));

__attribute__((visibility("default")))
void setup_logging(const char *program_name);

/**
 * Make an Admin API call to qubesd with no payload.  The returned buffer must be released by
 * the caller using free().
 *
 * @param[in] dest The destination VM name.
 * @param[in] method The method name.
 * @param[in] arg The service argument
 * @param[in] payload The payload of the API call.
 * @return The value on success.  On failure returns NULL and sets errno.
 */
char *qubesd_call(const char *dest, char *method, char *arg, size_t *out_len);

/**
 * Make an Admin API call to qubesd.  The returned buffer must be released by
 * the caller using free().
 *
 * @param[in] dest The destination VM name.
 * @param[in] method The method name.
 * @param[in] arg The service argument
 * @param[in] payload The payload of the API call.
 * @param[in] len The length of the payload.
 * @param[out] len The length of the data returned.
 * @return The value on success.  On failure returns NULL and sets errno.
 */
__attribute__((visibility("default")))
char *qubesd_call(const char *dest, char *method, char *arg, size_t *len);
__attribute__((visibility("default")))
char *qubesd_call2(const char *dest, char *method, char *arg, const char *payload, size_t len, size_t *out_len);

/**
 * Read all data from the file descriptor until EOF, then close it.
 * The returned buffer must be released by the caller using free().
 *
 * @param fd The file descriptor to read from.
 * @param initial_buffer_size The size of the buffer to use initially.
 *        Must be at least 1.
 * @param max_bytes Maximum number of bytes to read.  The function will fail
 *        if more than this number of bytes are read.
 * @param[out] len The number of bytes read.
 * @return A buffer to the number of bytes read.  On failure returns NULL and sets errno.
 */
__attribute__((visibility("default")))
void *qubes_read_all_to_malloc(int fd, size_t initial_buffer_size, size_t max_bytes, size_t *len);

/**
 * Send all data in the given msghdr.  Short writes are retried as necessary.
 *
 * Returns true on success.  Otherwise returns false setting errno.
 */
__attribute__((visibility("default")))
bool qubes_sendmsg_all(struct msghdr *msg, int sock);

/**
 * Wait for a vchan connection with a timeout.
 *
 * @param conn the vchan
 * @param wait_fd The FD set by libvchan_client_init_async() for clients,
 *                or the FD returned by libvchan_fd_for_select() for servers.
 * @param is_server Is this a server or a client vchan?
 * @param timeout The timeout to use.
 */
__attribute__((visibility("default")))
int qubes_wait_for_vchan_connection_with_timeout(
        libvchan_t *conn, int wait_fd, bool is_server, time_t timeout);

/**
 * Determine if the fork server should be used, even though the fork server
 * does not load service configuration.
 *
 * \param cmd The command to check.
 * \return true if the command should be executed using the fork server,
 *         false otherwise.
 */
__attribute__((visibility("default")))
bool qrexec_cmd_use_fork_server(const struct qrexec_parsed_command *cmd);
#endif /* LIBQREXEC_UTILS_H */
