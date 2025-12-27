#include "sshm_sync.h"
#include "sshm_core_internal.h"
#include "sshm_utils.h"
#include <semaphore.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>

// Basic exclusive lock
int sshm_lock(sshm_segment_t *seg) {
    if (!seg || !seg->sem) return -1;
    while (sem_wait(seg->sem) != 0) {
        if (errno == EINTR) continue;  // Retry on signal
        return -1;
    }
    return 0;
}

int sshm_unlock(sshm_segment_t *seg) {
    if (!seg || !seg->sem) return -1;
    if (sem_post(seg->sem) != 0) return -1;
    return 0;
}

// Reader lock/unlock
int sshm_rlock(sshm_segment_t *seg) {
    /* Readers do not take the semaphore.
     * Safety is provided by version fencing in _sshm_read_internal().
     * This avoids deadlocks if a reader process crashes mid-read.
     */
    (void)seg;
    return 0;
}

int sshm_runlock(sshm_segment_t *seg) {
    (void)seg;
    return 0;
}

// Writer lock/unlock
int sshm_wlock(sshm_segment_t *seg) {
    /* Writers use the semaphore as a cross-process mutex.
     * Readers do not block writers; readers retry via version fencing.
     */
    return sshm_lock(seg);
}

int sshm_wunlock(sshm_segment_t *seg) {
    return sshm_unlock(seg);
}

