#include "sshm.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    if (sshm_init() != 0) {
        fprintf(stderr, "sshm_init failed: %s\n", sshm_last_error());
        return 1;
    }

    const char *name = "demo";
    if (sshm_create(name, 4096, 0, SSHM_MODE_OVERWRITE) != 0) {
        fprintf(stderr, "sshm_create failed: %s\n", sshm_last_error());
        return 1;
    }

    const char *msg = "hello from demo_create\n";
    if (sshm_write(name, msg, strlen(msg), 0) < 0) {
        fprintf(stderr, "sshm_write failed: %s\n", sshm_last_error());
        return 1;
    }

    char buf[4096];
    ssize_t n = sshm_read(name, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
        fprintf(stderr, "sshm_read failed: %s\n", sshm_last_error());
        return 1;
    }
    buf[n] = '\0';
    fputs(buf, stdout);

    (void)sshm_destroy(name);
    return 0;
}
