extern const char *socket_dir;
int connect_unix_socket_by_id(unsigned int domid);
int connect_unix_socket(const char *domname);
int handle_daemon_handshake(int fd);
void negotiate_connection_params(int s, int other_domid, unsigned type,
        const void *cmdline_param, int cmdline_size,
        int *data_domain, int *data_port);
void send_service_connect(int s, const char *conn_ident,
        int connect_domain, int connect_port);
void run_qrexec_to_dom0(const struct service_params *svc_params,
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
_Noreturn void handshake_and_go(struct handshake_params *params);
int handle_agent_handshake(libvchan_t *vchan, bool remote_send_first);
int prepare_local_fds(const char *cmdline, struct buffer *stdin_buffer);
