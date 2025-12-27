#include "sshm.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *name = (argc >= 2) ? argv[1] : "demo_plain";

    if (sshm_init() != 0) {
        fprintf(stderr, "sshm_init failed: %s\n", sshm_last_error());
        return 1;
    }

    if (sshm_create(name, 4096, 0, SSHM_MODE_APPEND) != 0) {
        fprintf(stderr, "sshm_create failed: %s\n", sshm_last_error());
        return 1;
    }

    for (int i = 1; i <= 5; i++) {
        char msg[128];
        snprintf(msg, sizeof msg, "message %d from writer\n", i);
        if (sshm_write(name, msg, strlen(msg), 0) < 0) {
            fprintf(stderr, "sshm_write failed: %s\n", sshm_last_error());
            return 1;
        }
        fprintf(stdout, "wrote: %s", msg);
        usleep(200 * 1000);
    }

    sshm_shutdown();
    return 0;
}
