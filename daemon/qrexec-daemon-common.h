extern const char *socket_dir;
__attribute__((warn_unused_result))
int connect_unix_socket_by_id(unsigned int domid);
__attribute__((warn_unused_result))
int connect_unix_socket(const char *domname);
__attribute__((warn_unused_result))
int handle_daemon_handshake(int fd);
__attribute__((warn_unused_result))
bool negotiate_connection_params(int s, int other_domid, unsigned type,
        const void *cmdline_param, int cmdline_size,
        int *data_domain, int *data_port);
__attribute__((warn_unused_result))
bool send_service_connect(int s, const char *conn_ident,
        int connect_domain, int connect_port);
__attribute__((warn_unused_result))
int run_qrexec_to_dom0(const struct service_params *svc_params,
                       int src_domain_id,
                       const char *src_domain_name,
                       char *remote_cmdline,
                       int connection_timeout,
                       bool exit_with_code);
struct handshake_params {
    libvchan_t *data_vchan;
    struct buffer *stdin_buffer;
    union {
        int prepare_ret;
        int data_protocol_version;
    };
    bool remote_send_first;
    bool exit_with_code;
    // whether qrexec-client should replace problematic bytes with _ before printing the output
    bool replace_chars_stdout;
    bool replace_chars_stderr;
};
__attribute__((warn_unused_result))
int handshake_and_go(struct handshake_params *params);
__attribute__((warn_unused_result))
int handle_agent_handshake(libvchan_t *vchan, bool remote_send_first);
__attribute__((warn_unused_result))
int prepare_local_fds(struct qrexec_parsed_command *command, struct buffer *stdin_buffer);
