extern const char *socket_dir;
int connect_unix_socket_by_id(unsigned int domid);
int connect_unix_socket(const char *domname);
int handle_daemon_handshake(int fd);
void negotiate_connection_params(int s, int other_domid, unsigned type,
        void *cmdline_param, int cmdline_size,
        int *data_domain, int *data_port);
void send_service_connect(int s, const char *conn_ident,
        int connect_domain, int connect_port);
