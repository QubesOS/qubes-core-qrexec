#pragma once
#include <stdbool.h>
int qubes_toml_config_parse(const char *config_full_path, bool *wait_for_session,
                            char **user,
                            bool *send_service_descriptor,
                            bool *exit_on_stdout_eof,
                            bool *exit_on_stdin_eof);
