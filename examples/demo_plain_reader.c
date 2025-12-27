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

    char buf[4096];

    for (int i = 0; i < 10; i++) {
        memset(buf, 0, sizeof buf);
        ssize_t n = sshm_read(name, buf, sizeof buf - 1, 0);
        if (n < 0) {
            fprintf(stderr, "sshm_read failed: %s\n", sshm_last_error());
            return 1;
        }

        fprintf(stdout, "--- read (%zd bytes) ---\n%.*s\n", n, (int)n, buf);
        usleep(300 * 1000);
    }

    sshm_shutdown();
    return 0;
}
