extern const char *socket_dir;
__attribute__((warn_unused_result))
int connect_unix_socket_by_id(unsigned int domid);
__attribute__((warn_unused_result))
int connect_unix_socket(const char *domname);
__attribute__((warn_unused_result))
int handle_daemon_handshake(int fd);
__attribute__((warn_unused_result))
bool negotiate_connection_params(int s, int other_domid, unsigned type,
        void *cmdline_param, int cmdline_size,
        int *data_domain, int *data_port);
__attribute__((warn_unused_result))
bool send_service_connect(int s, const char *conn_ident,
        int connect_domain, int connect_port);
