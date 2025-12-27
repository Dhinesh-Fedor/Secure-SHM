#pragma once
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize / shutdown library */
int sshm_init(void);
void sshm_shutdown(void);

/* Define the write modes for segment creation */
#define SSHM_MODE_OVERWRITE 0
#define SSHM_MODE_APPEND    1

/**
 * Create or open a shared memory segment.
 * If encrypted!=0, a key will be REGISTERed with the daemon.
 * @param name Segment name
 * @param size Segment size in bytes
 * @param encrypted 1 for encrypted, 0 for plain
 * @param mode Write mode: SSHM_MODE_OVERWRITE or SSHM_MODE_APPEND
 */
int sshm_create(const char *name, size_t size, int encrypted, int mode);

int sshm_open(const char *name, int encrypted);
// ... (rest of the file is unchanged) ...
/* Write buffer to a segment. If encrypt!=0, encrypt before writing. */
ssize_t sshm_write(const char *name, const void *buf, size_t len, int encrypt);
/* Read data from a segment. If decrypt!=0, decrypt before returning. */
ssize_t sshm_read(const char *name, void *buf, size_t buflen, int decrypt);
/* Close/detach or destroy a segment */
int sshm_close(const char *name);
int sshm_destroy(const char *name);
/* Retrieve last error string for diagnostic purposes */
const char *sshm_last_error(void);
void set_err(const char *fmt, ...);

#ifdef __cplusplus
}
#endif