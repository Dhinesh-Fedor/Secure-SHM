#pragma once
#include <sys/types.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSHM_SOCKET_PATH "/run/sshm/sshm_daemon.sock"
#define SSHM_NAME_MAX 256 
#define SSHM_MAX_AUTH_PIDS 64
#define SSHM_KEY_BYTES 32

#ifndef SSHM_KEYBYTES
#define SSHM_KEYBYTES SSHM_KEY_BYTES
#endif

typedef struct {
    char  name[SSHM_NAME_MAX];
    uint8_t key[SSHM_KEYBYTES];
    pid_t owner_pid;
    uid_t owner_uid;
    pid_t authorized_pids[SSHM_MAX_AUTH_PIDS];
    uid_t authorized_uids[SSHM_MAX_AUTH_PIDS];
    int   authorized_count;
    time_t created_at;
} sshm_key_entry_t;

/* Main entry point for the daemon */
int sshm_daemon_run(void);

#ifdef __cplusplus
}
#endif