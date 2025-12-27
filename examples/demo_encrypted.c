#include "sshm.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *name = (argc >= 2) ? argv[1] : "demo_secret";

    if (sshm_init() != 0) {
        fprintf(stderr, "sshm_init failed: %s\n", sshm_last_error());
        return 1;
    }

    /* Encrypted segments require sshmd running and SSHM_SOCKET_PATH configured. */
    if (sshm_create(name, 4096, 1, SSHM_MODE_APPEND) != 0) {
        fprintf(stderr, "sshm_create(encrypted) failed: %s\n", sshm_last_error());
        return 1;
    }

    const char *msg = "top-secret\n";
    if (sshm_write(name, msg, strlen(msg), 1) < 0) {
        fprintf(stderr, "sshm_write(encrypted) failed: %s\n", sshm_last_error());
        return 1;
    }

    char out[4096];
    ssize_t n = sshm_read(name, out, sizeof out - 1, 1);
    if (n < 0) {
        fprintf(stderr, "sshm_read(decrypt) failed: %s\n", sshm_last_error());
        return 1;
    }
    out[n] = '\0';

    printf("decrypted read (%zd bytes): %s", n, out);

    (void)sshm_destroy(name);
    sshm_shutdown();
    return 0;
}
