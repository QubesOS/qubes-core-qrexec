/** Directory containing the qrexec sockets */
extern const char *socket_dir;

/**
 * Connect to the listening socket for a Xen VM.
 *
 * \param domid The Xen domain ID of the VM.
 * \return The file descriptor for the socket.
 */
__attribute__((warn_unused_result))
int connect_unix_socket_by_id(unsigned int domid);
/**
 * Connect to the listening socket for a Xen VM.
 *
 * \param domname The name of the VM.
 * \return The file descriptor of the connection.
 */
__attribute__((warn_unused_result))
int connect_unix_socket(const char *domname);
/**
 * Handshake with the qrexec daemon connected on this FD.
 *
 * @param fd The file descriptor of the connection.
 * @return 0 on success or -1 on failure.
 */
__attribute__((warn_unused_result))
int handle_daemon_handshake(int fd);
/**
 * Send a message of type TYPE to the qrexec daemon connected on FD s.
 *
 * @param s The file descriptor for the connection.
 * @param other_domid The domain ID of the peer.
 * @param type The type of the message.
 * @param cmdline_param The parameter passed after the data.
 * @param cmdline_size The size of the cmdline_param passed.
 * @param[out] data_domain The domain ID to use for the data connection.
 * @param[out] data_port The port to use for the data connection.
 * @return true on success, false on failure.
 */
__attribute__((warn_unused_result))
bool negotiate_connection_params(int s, int other_domid, unsigned type,
        const void *cmdline_param, int cmdline_size,
        int *data_domain, int *data_port);

/**
 * Send a MSG_SERVICE_CONNECT to the daemon connected via file descriptor s.
 *
 * @param s The file descriptor for the connection.
 * @param connect_domain The domain ID of the calling domain.
 * @param connect_port The port to use for the data connection.
 * @return true on success, false on failure.
 */
__attribute__((warn_unused_result))
bool send_service_connect(int s, const char *conn_ident,
        int connect_domain, int connect_port);

/**
 * Run a qrexec command in dom0.
 *
 * @param svc_params The parameters of the service.
 * @param src_domain_id The source domain ID.
 * @param src_domain_name The source domain name.
 * @param cmd The command to execute.
 * @param connection_timeout The connection timeout in seconds.
 * @param exit_with_code \true if the return value should be the exit
 * code of the qrexec command, \false if the return value should be 0
 * unless the command could not be executed for some reason.
 */
__attribute__((warn_unused_result))
int run_qrexec_to_dom0(const struct service_params *svc_params,
                       int src_domain_id,
                       const char *src_domain_name,
                       char *remote_cmdline,
                       int connection_timeout,
                       bool exit_with_code);
/** Parameters for handshake_and_go(), organized as a struct
 * for convenience. */
struct handshake_params {
    /// Data vchan.
    libvchan_t *data_vchan;
    /// Buffer with data to be prepended to stdin.
    struct buffer *stdin_buffer;
    union {
        /// Return value of the preparation code: nonzero if there was already a problem.
        /// If this is nonzero the handshake is not run.
        int prepare_ret;
        /// Data protocol version from the handshake.
        int data_protocol_version;
    };
    /// Whether this is a call to dom0 (true) or a call from dom0 (false).
    /// The name comes from the source of the call always sending the first
    /// handshake message.
    bool remote_send_first;
    /// Whether to return with status 0 or the return value of the call.
    bool exit_with_code;
    /// Whether to replace problematic bytes with _ before writing to stdout.
    bool replace_chars_stdout;
    /// Whether to replace problematic bytes with _ before writing to stderr.
    bool replace_chars_stderr;
};
/**
 * Process IO call with the parameters specified by the parameters.
 * The vchan will be closed afterwards and set to NULL.
 *
 * \param params The parameters to use.
 * \param cmd The parsed command.
 */
__attribute__((warn_unused_result))
int handshake_and_go(struct handshake_params *params,
                     const struct qrexec_parsed_command *cmd);
/**
 * Handshake with the remote qrexec-agent.
 *
 * \param vchan The vchan to use.
 * \param remote_send_first \true if the remote should send the first message,
 *        otherwise \false.
 * \return The protocol version.  Guaranteed to be either -1 (failure) or
 *         between `QREXEC_PROTOCOL_V2` and `QREXEC_PROTOCOL_V3` inclusive.
 */
__attribute__((warn_unused_result))
int handle_agent_handshake(libvchan_t *vchan, bool remote_send_first);
/**
 * Execute the given qrexec command in dom0.  If it requires data to be prepended
 * to its stdin, add that to the buffer.
 */
__attribute__((warn_unused_result))
int prepare_local_fds(struct qrexec_parsed_command *command, struct buffer *stdin_buffer);

/**
 * Execute the given command (of length service_length) in VM target.
 *
 * \param target The target VM name.
 * \param autostart \true to start the VM if it is not already started, otherwise \false.
 * \param remote_domain_id Xen domain ID of the remote domain.
 * \param cmd The command.
 * \param service_length The length of the command.
 * \param request_id The request ID used.
 * \param just_exec True for `MSG_JUST_EXEC`, false for `MSG_EXEC_CMDLINE`.
 * \param wait_connection_end \true to wait until the connection has finishe, else \false.
 * \return \true on success and \false on failure.
 */
__attribute__((warn_unused_result))
bool qrexec_execute_vm(const char *target, bool autostart, int remote_domain_id,
                       const char *cmd, size_t service_length, const char *request_id,
                       bool just_exec, bool wait_connection_end, bool use_uuid);
/** FD for stdout of remote process */
extern int local_stdin_fd;
__attribute__((warn_unused_result))
bool target_refers_to_dom0(const char *target);
