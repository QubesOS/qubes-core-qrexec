#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <libqrexec-utils.h>

int open_logger(struct qrexec_parsed_command *command, int *pid)
{
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC)) {
        LOG(ERROR, "Cannot create status pipe");
        return -1;
    }
    char *buf[] = {
        "logger",
        "-t",
        NULL,
        NULL,
    };
    if (asprintf(buf + 2, "%.*s-%s", (int)command->service_descriptor_len,
                command->service_descriptor, command->source_domain) < 0) {
        LOG(ERROR, "asprintf() failed");
        return -1;
    }
    switch ((*pid = fork())) {
    case -1:
        LOG(ERROR, "Cannot fork logger process");
        return -1;
    case 0:
        fix_fds(pipes[0], 1, 2);
        execvp("logger", buf);
        _exit(126);
    default:
        free(buf[2]);
        close(pipes[0]);
        return pipes[1];
    }
}
