#define _GNU_SOURCE
#include "sshm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/types.h>

/*
 * Public API test: uses sshm.h only.
 * Spawns multiple readers/writers interacting by segment name.
 */

static void child_reader(int id, const char *seg_name, unsigned int delay_us) {
    usleep(delay_us);
    char buf[8192];
    ssize_t n = sshm_read(seg_name, buf, sizeof(buf) - 1, 1);
    if (n < 0)
        fprintf(stderr, "[reader %d pid=%d] read error: %s\n", id, getpid(), sshm_last_error());
    else {
        buf[n] = '\0';
        printf("[reader %d pid=%d] read %zd bytes:\n%s", id, getpid(), n, buf);
    }
    fflush(stdout);
    _exit(0);
}

static void child_writer(int id, const char *seg_name, const char *msg, unsigned int delay_us) {
    usleep(delay_us);
    ssize_t w = sshm_write(seg_name, msg, strlen(msg), 1);
    if (w < 0)
        fprintf(stderr, "[writer %d pid=%d] write error: %s\n", id, getpid(), sshm_last_error());
    else
        printf("[writer %d pid=%d] wrote %zd bytes: %s", id, getpid(), w, msg);
    fflush(stdout);
    _exit(0);
}

int main(void) {
    if (sshm_init() != 0) {
        fprintf(stderr, "sshm_init failed: %s\n", sshm_last_error());
        return 1;
    }

    const char *seg_name = "hw_test";
    printf("[parent pid=%d] Creating encrypted segment '%s'\n", getpid(), seg_name);
    
    /* --- FIX: Use new API with SSHM_MODE_OVERWRITE --- */
    if (sshm_create(seg_name, 4096, 1, SSHM_MODE_APPEND) != 0) {
        fprintf(stderr, "create failed: %s\n", sshm_last_error());
        return 1;
    }

    printf("[parent pid=%d] Segment created successfully\n", getpid());
    const char *init = "INITIAL\n";
    if (sshm_write(seg_name, init, strlen(init), 1) < 0) {
        fprintf(stderr, "initial write failed: %s\n", sshm_last_error());
        return 1;
    }

    pid_t pids[4];
    if ((pids[0] = fork()) == 0) child_reader(1, seg_name, 100000);
    if ((pids[1] = fork()) == 0) child_writer(1, seg_name, "Hello from writer 1\n", 250000);
    if ((pids[2] = fork()) == 0) child_writer(2, seg_name, "Hello from writer 2\n", 350000);
    if ((pids[3] = fork()) == 0) child_reader(2, seg_name, 500000);

    for (int i = 0; i < 4; ++i) waitpid(pids[i], NULL, 0);

    char buf[8192];
    ssize_t r = sshm_read(seg_name, buf, sizeof(buf) - 1, 1);
    if (r >= 0) {
        buf[r] = '\0';
        printf("[final reader parent pid=%d] read %zd bytes:\n%s", getpid(), r, buf);
    } else {
        fprintf(stderr, "[final reader parent pid=%d] read failed: %s\n", getpid(), sshm_last_error());
    }

    // Uncomment for full cleanup:
    // sshm_destroy(seg_name);
    // sshm_shutdown();
    return 0;
}
