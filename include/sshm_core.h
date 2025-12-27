#pragma once
/**
 * sshm_core.h
 * Internal interface for Secure Shared Memory Toolkit (SSHM) v1.0
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSHM_MAX_NAME 256
#define SSHM_KEYBYTES 32

/* Opaque pointer for internal use */
typedef struct sshm_segment sshm_segment_t;

/* Library lifecycle */
int sshm_init(void);
void sshm_shutdown(void);

/* Segment operations (Internal)
 * These no longer accept a key. The key is *always* fetched from the daemon.
 */
sshm_segment_t *_sshm_create_internal(const char *name, size_t size, uint32_t flags,
                            mode_t mode);
sshm_segment_t *_sshm_open_internal(const char *name, uint32_t flags);
int _sshm_close_internal(sshm_segment_t *seg);
int _sshm_destroy_internal(sshm_segment_t *seg);

/* Read/write segment contents */
ssize_t _sshm_write_internal(sshm_segment_t *seg, const void *data, size_t len, int do_encrypt);
ssize_t _sshm_read_internal(sshm_segment_t *seg, void *buffer, size_t buf_len, int do_decrypt);

/* Retrieve last error string (thread-local) */
const char *sshm_last_error(void);
void set_err(const char *fmt, ...);
size_t sshm_get_size(sshm_segment_t *seg);
uint32_t sshm_get_flags(sshm_segment_t *seg);

/* Segment flags */
#define SSHM_FLAG_NONE      0
#define SSHM_FLAG_ENCRYPTED (1u << 0)
#define SSHM_FLAG_PERSIST   (1u << 1)
#define SSHM_FLAG_APPEND_ONLY (1u << 2)

/* Helper: human readable flags string (returns pointer to static buffer) */
const char *sshm_flags_to_string(uint32_t flags);

#ifdef __cplusplus
}
#endif