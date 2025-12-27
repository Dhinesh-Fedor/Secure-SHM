/*
 * auth_client.c
 * Tries to access the segment created by auth_owner.
 * This process is "unauthorized" by default.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "sshm.h"

static const char* SEG_NAME = "hw_test";

int main(void) {
    pid_t my_pid = getpid();

    /* Make stdout unbuffered so printf appears immediately */
    setbuf(stdout, NULL);

    printf("[Client] My PID is: %d\n", (int)my_pid);
    fprintf(stderr, "[Client] uid=%d euid=%d SSHM_DEBUG='%s'\n",
            (int)getuid(), (int)geteuid(), getenv("SSHM_DEBUG"));

    printf("[Client] Initializing SSHM library...\n");

    if (sshm_init() != 0) {
        fprintf(stderr, "[Client] Failed to initialize SSHM: %s\n", sshm_last_error());
        return 1;
    }

    /* Instruct and wait so the PID stays the same while you authorize it */
    printf("[Client] Please authorize my PID: %d\n", (int)my_pid);
    printf("Run in another terminal:\n");
    printf("    ./sshmctl authorize %s %d\n", SEG_NAME, (int)my_pid);
    printf("After authorizing, press Enter here to continue...\n");
    fflush(stdout);
    (void)getchar();

    printf("[Client] Attempting a single read from segment '%s'...\n", SEG_NAME);

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    /* Single attempt: read and decrypt (last flag = 1) */
    ssize_t bytes_read = sshm_read(SEG_NAME, buffer, sizeof(buffer) - 1, 1);

    if (bytes_read > 0) {
        printf("\n\n[Client] SUCCESS!\n");
        printf("[Client] Read %zd bytes: '%s'\n", bytes_read, buffer);
        return 0;
    }

    /* On 0 or negative return treat as access denied / failure and instruct auth */
    fprintf(stderr, "[Client] Read failed (bytes=%zd). Error: %s\n", bytes_read, sshm_last_error());
    printf("[Client] Access denied or no data.\n");
    printf("[Client] Please authorize my PID: %d\n", (int)my_pid);
    printf("Run in another terminal:\n");
    printf("    ./sshmctl authorize %s %d\n", SEG_NAME, (int)my_pid);

    return 1;
}
