/**
 * sshm_core.c
 * Core logic: create/open/destroy/read/write secure shared memory (SSHM)
 *
 * Frame format: [type:1][len_be:4][payload]
 * type=0 -> plaintext payload
 * type=1 -> ciphertext payload = nonce||ciphertext (as produced by sshm_encrypt)
 *
 * Version fencing:
 * writer: version += 1 (odd, in-progress) ... write ... version += 1 (even, stable)
 * reader: only reads when version is even and unchanged across a pass
 */

#include "sshm_core.h"
#include "sshm_core_internal.h"
#include "sshm_sync.h"
#include "sshm_utils.h"
#include "sshm_daemon.h"
#include "sshm_crypto.h"
#include "sshm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h> 
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <arpa/inet.h>
#include <sodium.h> 

// Helpers

static ssize_t cli_write_exact(int fd, const void *buf, size_t n) {
    size_t total = 0;
    const char *p = (const char*)buf;
    while (total < n) {
        ssize_t w = write(fd, p + total, n - total);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        total += (size_t)w;
    }
    return (ssize_t)total;
}

static ssize_t cli_read_some(int fd, char *buf, size_t n) {
    return read(fd, buf, n);
}

// Daemon protocol helpers (REGISTER/FETCH/REMOVE)

static int connect_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        sshm_debug("[core]", "socket() failed: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sshm_get_socket_path(), sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        sshm_debug("[core]", "connect() to %s failed: %s", sshm_get_socket_path(), strerror(errno));
        close(fd);
        return -1;
    }
    sshm_debug("[core]", "connected to daemon socket");
    return fd;
}

// Expect line: "OK <64hex>\n"
static int parse_ok_hex_key_line(const char *line, uint8_t out[SSHM_KEYBYTES]) {
    while (*line==' '||*line=='\t') line++;
    if (strncmp(line,"OK",2)!=0) return -1;
    line += 2;
    while (*line==' '||*line=='\t') line++;
    char hex[SSHM_KEYBYTES * 2 + 1] = {0};
    size_t i = 0;
    while (line[i] && line[i] != '\n' && i < (SSHM_KEYBYTES * 2)){ hex[i] = line[i]; i++; }
    if (i != (SSHM_KEYBYTES * 2)) return -1;
    for (size_t j=0;j<SSHM_KEYBYTES;j++){
        unsigned int v=0;
        if (sscanf(&hex[2*j], "%2x", &v) != 1) return -1;
        out[j] = (uint8_t)v;
    }
    return 0;
}

static int register_key_with_daemon(const char *name) {
    sshm_debug("[core]", "→ REGISTER request for '%s'", name);
    int fd = connect_daemon();
    if (fd < 0) {
        set_err("Failed to connect to SSHM daemon (is sshmd running?)");
        // Daemon will audit the failed connection attempt if it's running.
        return -1;
    }
    char line[512];
    int n = snprintf(line, sizeof line, "REGISTER %s\n", name);
    if (n <= 0 || (size_t)n >= sizeof(line)) { close(fd); return -1; }
    if (cli_write_exact(fd, line, (size_t)n) < 0) { close(fd); return -1; }

    char resp[256];
    ssize_t r = cli_read_some(fd, resp, sizeof(resp)-1);
    close(fd);
    if (r <= 0) { set_err("Daemon replied: <no data>"); sshm_debug("[core]", "← Daemon replied: <no data>"); return -1; }
    resp[r] = '\0';
    {
        const char *status = "UNKNOWN";
        if (strncmp(resp, "OK", 2) == 0) status = "OK";
        else if (strncmp(resp, "ERR", 3) == 0) status = "ERR";
        sshm_debug("[core]", "← Daemon replied: %s (redacted)", status);
    }

    if (strncmp(resp, "OK", 2) != 0) {
        set_err("Daemon denied REGISTER: %s", resp);
        return -1;
    }
    return 0;
}

static int request_key_from_daemon(const char *name, uint8_t out[SSHM_KEYBYTES]) {
    sshm_debug("[core]", "→ FETCH key for '%s'", name);
    int fd = connect_daemon();
    if (fd < 0) {
        set_err("Failed to connect to SSHM daemon");
        return -1;
    }

    char line[512];
    int n = snprintf(line, sizeof line, "FETCH %s\n", name);
    if (n <= 0 || (size_t)n >= sizeof(line)) { close(fd); return -1; }
    if (cli_write_exact(fd, line, (size_t)n) < 0) { close(fd); return -1; }

    char resp[256];
    ssize_t r = cli_read_some(fd, resp, sizeof(resp)-1);
    close(fd);
    if (r <= 0) { set_err("Daemon replied: <no data>"); sshm_debug("[core]", "← Daemon replied: <no data>"); return -1; }
    resp[r] = '\0';
    {
        const char *status = "UNKNOWN";
        if (strncmp(resp, "OK", 2) == 0) status = "OK";
        else if (strncmp(resp, "ERR", 3) == 0) status = "ERR";
        sshm_debug("[core]", "← Daemon replied: %s (redacted)", status);
    }

    if (parse_ok_hex_key_line(resp, out) != 0) {
        set_err("Daemon denied FETCH");
        return -1;
    }
    return 0;
}

// Optional: ask daemon to remove a key.
static int remove_key_from_daemon(const char *name) {
    sshm_debug("[core]", "→ REMOVE '%s'", name);
    if (!name) return -1;
    int fd = connect_daemon();
    if (fd < 0) return -1;
    char line[256];
    int n = snprintf(line, sizeof line, "REMOVE %s\n", name);
    if (cli_write_exact(fd, line, (size_t)n) < 0) { close(fd); return -1; }
    char resp[128]; ssize_t r = cli_read_some(fd, resp, sizeof(resp)-1);
    close(fd);
    if (r <= 0) return -1;
    resp[r] = '\0';
    return (strncmp(resp, "OK", 2) == 0) ? 0 : -1;
}

// Best-effort notify stub (kept for future).
static void sshm_notify_daemon(const char *op, const char *seg) {
    (void)op; (void)seg;
}

// Error buffer
static __thread char tls_err[256];
const char *sshm_last_error(void) { return tls_err[0] ? tls_err : "no error"; }
void set_err(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(tls_err, sizeof tls_err, fmt, ap);
    va_end(ap);
    sshm_warn("[core]", "set_err: %s", tls_err);
}

// Misc helpers

const char *sshm_flags_to_string(uint32_t flags) {
    static __thread char buf[64]; // Thread-local, safe across threads.
    buf[0] = '\0';
    size_t off = 0;
    if (flags == SSHM_FLAG_NONE) return "None";
    if (flags & SSHM_FLAG_ENCRYPTED) {
        off += (size_t)snprintf(buf + off, sizeof buf - off, "%sEncrypted", off ? "|" : "");
    }
    if (flags & SSHM_FLAG_PERSIST) {
        off += (size_t)snprintf(buf + off, sizeof buf - off, "%sPersist", off ? "|" : "");
    }
    if (flags & SSHM_FLAG_APPEND_ONLY) {
        off += (size_t)snprintf(buf + off, sizeof buf - off, "%sAppendOnly", off ? "|" : "");
    }
    return buf;
}

static uint32_t simple_crc32(const void *data, size_t n) {
    const uint8_t *p = (const uint8_t*)data;
    uint32_t crc = 0;
    for (size_t i = 0; i < n; i++) crc = crc * 101u + p[i];
    return crc;
}

static int validate_segment_name(const char *name) {
    if (!name || !name[0]) return 0;
    size_t n = strlen(name);
    if (n > SSHM_MAX_NAME) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c <= 32 || c == '/' || c == '\\') return 0;
    }
    return 1;
}

// Build a semaphore name.
static void semname_for(const char *name, char out[128]) {
    // If too long, use a hash-based name to avoid truncation.
    if (strlen(name) > 100) {
        uint32_t h = simple_crc32(name, strlen(name));
        snprintf(out, 128, "/sshm_%08x_lock", h);
    } else {
        snprintf(out, 128, "/sshm_%s_lock", name);
    }
}

static int seg_has_key(const sshm_segment_t *seg) {
    if (!seg) return 0;
    for (size_t i=0;i<SSHM_KEYBYTES;i++) if (seg->key[i]) return 1;
    return 0;
}

// Active segment tracking
#define MAX_ACTIVE_SEGMENTS 128
static sshm_segment_t *active_segments[MAX_ACTIVE_SEGMENTS];
static int active_segment_count = 0;
static pthread_mutex_t active_lock = PTHREAD_MUTEX_INITIALIZER;

// Init / shutdown

/**
 * Initialize the SSHM library.
 * In the systemd model, this just checks for daemon connectivity.
 */
int sshm_init(void) {
    sshm_debug("[core]", "Checking daemon presence...");

    if (!sshm_check_daemon_alive()) {
        sshm_error("[core]", "Background daemon service is NOT running.");
        sshm_error("[core]", "Please run 'sshmctl start-daemon' or 'systemctl start sshmd.service'.");
        set_err("Daemon is not running or not responsive.");
        return -1;
    }

    sshm_debug("[core]", "Daemon running and reachable. Proceeding with initialization...");
    // Client-side init doesn't need a persistent audit log; daemon handles events.
    return 0;
}

void sshm_shutdown(void) {
    sshm_debug("[core]", "Shutting down SSHM client library");
    pthread_mutex_lock(&active_lock);
    for (int i=0;i<active_segment_count;i++){
        if (active_segments[i]) _sshm_destroy_internal(active_segments[i]);
    }
    active_segment_count = 0;
    pthread_mutex_unlock(&active_lock);
}

// Size / flags accessors

size_t sshm_get_size(sshm_segment_t *seg) {
    if (!seg) return 0;
    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    return (size_t)hdr->payload_size;
}

uint32_t sshm_get_flags(sshm_segment_t *seg) {
    if (!seg) return SSHM_FLAG_NONE;
    return seg->flags;
}

// Create

sshm_segment_t* _sshm_create_internal(const char *name, size_t size, uint32_t flags,
                                      mode_t mode) {
    if (!validate_segment_name(name)) { set_err("invalid name"); return NULL; }
    sshm_debug("[core]", "Creating segment '%s' (size=%zu, flags=%s)", name, size, sshm_flags_to_string(flags));

    size_t map_size = sizeof(struct segment_header) + size;
    char shmname[SSHM_MAX_NAME + 16];
    snprintf(shmname, sizeof shmname, "/sshm_%s", name);

    int fd = shm_open(shmname, O_CREAT | O_EXCL | O_RDWR, mode ? mode : 0660);
    if (fd < 0) { set_err("shm_open: %s", strerror(errno)); return NULL; }
    if (ftruncate(fd, (off_t)map_size) != 0) {
        set_err("ftruncate: %s", strerror(errno)); close(fd); shm_unlink(shmname); return NULL;
    }

    void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { set_err("mmap: %s", strerror(errno)); close(fd); shm_unlink(shmname); return NULL; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(base, 0);
    hdr->flags = flags;
    hdr->version = 0;           // Even means stable.
    hdr->payload_size = (uint64_t)size;
    hdr->data_len = 0;
    hdr->readers_count = 0;
    hdr->crc32 = 0;

    char semname[128]; semname_for(name, semname);
    sem_unlink(semname); // Clean up stale semaphore.
    sem_t *sem = sem_open(semname, O_CREAT | O_EXCL, 0600, 1);
    if (sem == SEM_FAILED) { sem_unlink(semname); sem = sem_open(semname, O_CREAT, 0600, 1); }
    if (sem == SEM_FAILED) { set_err("sem_open failed"); munmap(base, map_size); close(fd); shm_unlink(shmname); return NULL; }

    sshm_segment_t *seg = (sshm_segment_t*)calloc(1, sizeof(*seg));
    if (!seg) { set_err("calloc"); sem_close(sem); sem_unlink(semname); munmap(base, map_size); close(fd); shm_unlink(shmname); return NULL; }

    strncpy(seg->name, name, sizeof(seg->name)-1);
    seg->shm_fd = fd;
    seg->map_size = map_size;
    seg->map_base_offset = (uintptr_t)base;
    seg->header_offset = 0;
    seg->sem = sem;
    seg->flags = flags;

    if (flags & SSHM_FLAG_ENCRYPTED) {
        if (register_key_with_daemon(name) != 0) {
            sshm_debug("[core]", "REGISTER failed for %s", name);
            // Fatal during creation.
            set_err("Failed to register key with daemon");
            _sshm_close_internal(seg); // Frees seg, munmap, closes fd.
            shm_unlink(shmname); // Clean up shm.
            sem_unlink(semname); // Clean up sem.
            return NULL;
        }
        uint8_t fetched[SSHM_KEYBYTES] = {0};
        if (request_key_from_daemon(name, fetched) == 0){
            memcpy(seg->key, fetched, SSHM_KEYBYTES);
        } else {
            sshm_warn("[core]", "Failed to fetch key for newly registered segment '%s'", name);
            set_err("Failed to fetch key after register");
            _sshm_close_internal(seg);
            shm_unlink(shmname);
            sem_unlink(semname);
            return NULL;
        }
        secure_zero(fetched, sizeof fetched);
    }

    pthread_mutex_lock(&active_lock);
    if (active_segment_count < MAX_ACTIVE_SEGMENTS) active_segments[active_segment_count++] = seg;
    pthread_mutex_unlock(&active_lock);

    sshm_debug("[core]", "Created segment '%s'", name);
    return seg;
}

// Open

sshm_segment_t* _sshm_open_internal(const char *name, uint32_t flags) {
    (void)flags;
    if (!validate_segment_name(name)) { set_err("invalid name"); return NULL; }
    sshm_debug("[core]", "Opening segment '%s'", name);

    char shmname[SSHM_MAX_NAME + 16];
    snprintf(shmname, sizeof shmname, "/sshm_%s", name);

    int fd = shm_open(shmname, O_RDWR, 0);
    if (fd < 0) { set_err("shm_open: %s", strerror(errno)); return NULL; }

    struct stat st;
    if (fstat(fd, &st) != 0) { set_err("fstat: %s", strerror(errno)); close(fd); return NULL; }
    size_t map_size = (size_t)st.st_size;

    void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { set_err("mmap: %s", strerror(errno)); close(fd); return NULL; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(base, 0);

    sshm_segment_t *seg = (sshm_segment_t*)calloc(1, sizeof(*seg));
    if (!seg) { set_err("calloc"); munmap(base, map_size); close(fd); return NULL; }

    strncpy(seg->name, name, sizeof(seg->name)-1);
    seg->shm_fd = fd;
    seg->map_size = map_size;
    seg->map_base_offset = (uintptr_t)base;
    seg->header_offset = 0;
    seg->flags = hdr->flags;

    if (seg->flags & SSHM_FLAG_ENCRYPTED) {
        sshm_debug("[core]", "Encrypted segment, fetching key from daemon for '%s'", name);
        uint8_t tmp[SSHM_KEYBYTES] = {0};
        if (request_key_from_daemon(name, tmp) == 0) {
            memcpy(seg->key, tmp, SSHM_KEYBYTES);
        } else {
            sshm_warn("[core]", "Failed to fetch key for '%s'. Decrypt will fail.", name);
            set_err("Failed to fetch key for segment");
             // Do not fail open; decrypt will fail later.
        }
        secure_zero(tmp, sizeof tmp);
    }

    char semname[128]; semname_for(name, semname);
    seg->sem = sem_open(semname, 0);
    if (seg->sem == SEM_FAILED) {
        sshm_warn("[core]", "sem_open failed for '%s': %s", semname, strerror(errno));
        set_err("Failed to open semaphore for segment");
        munmap(base, map_size);
        close(fd);
        free(seg);
        return NULL;
    }

    pthread_mutex_lock(&active_lock);
    if (active_segment_count < MAX_ACTIVE_SEGMENTS) active_segments[active_segment_count++] = seg;
    pthread_mutex_unlock(&active_lock);

    sshm_debug("[core]", "Opened segment '%s'", name);
    return seg;
}

// Close / destroy

int _sshm_close_internal(sshm_segment_t *seg) {
    if (!seg) return -1;
    sshm_debug("[core]", "Closing segment '%s'", seg->name);

    if (seg->sem) { sem_close(seg->sem); seg->sem = NULL; }
    if (seg->map_base_offset && seg->map_size) munmap((void*)seg->map_base_offset, seg->map_size);
    if (seg->shm_fd >= 0) { close(seg->shm_fd); seg->shm_fd = -1; }

    pthread_mutex_lock(&active_lock);
    for (int i=0;i<active_segment_count;i++){
        if (active_segments[i] == seg) {
            active_segments[i] = active_segments[active_segment_count-1];
            active_segments[active_segment_count-1] = NULL;
            active_segment_count--;
            break;
        }
    }
    pthread_mutex_unlock(&active_lock);

    secure_zero(seg->key, sizeof seg->key);
    free(seg);
    return 0;
}

int _sshm_destroy_internal(sshm_segment_t *seg) {
    if (!seg) return -1;
    char name_copy[SSHM_MAX_NAME+1]; // Avoid use-after-free in debug.
    strncpy(name_copy, seg->name, sizeof name_copy - 1); name_copy[sizeof name_copy - 1] = '\0';

    sshm_debug("[core]", "Destroying segment '%s'", name_copy);

    char shmname[SSHM_MAX_NAME + 16]; snprintf(shmname, sizeof shmname, "/sshm_%s", name_copy);
    char semname[128]; semname_for(name_copy, semname);

    if (seg->sem) { sem_close(seg->sem); sem_unlink(semname); seg->sem = NULL; }
    if (seg->map_base_offset && seg->map_size) munmap((void*)seg->map_base_offset, seg->map_size);
    if (seg->shm_fd >= 0) { close(seg->shm_fd); shm_unlink(shmname); seg->shm_fd = -1; }

    (void)remove_key_from_daemon(name_copy); // Ask daemon to remove key.

    pthread_mutex_lock(&active_lock);
    for (int i=0;i<active_segment_count;i++){
        if (active_segments[i] == seg) {
            active_segments[i] = active_segments[active_segment_count-1];
            active_segments[active_segment_count-1] = NULL;
            active_segment_count--;
            break;
        }
    }
    pthread_mutex_unlock(&active_lock);

    secure_zero(seg->key, sizeof seg->key);
    free(seg);
    sshm_debug("[core]", "Destroyed segment '%s'", name_copy);
    return 0;
}

// Write (framed: [type][len_be][payload])
/* type: 0 = plaintext, 1 = encrypted; len_be = big-endian length of payload */
ssize_t _sshm_write_internal(sshm_segment_t *seg, const void *data, size_t len, int do_encrypt) {
    if (!seg || !data) return -1;
    sshm_debug("[core]", "Writing to '%s' (len=%zu, encrypt=%d)", seg->name, len, do_encrypt);

    /* Enforce encryption semantics at the segment boundary.
     * - Encrypted segment: must write encrypted frames (no accidental plaintext).
     * - Plain segment: must not request encryption (no key available).
     */
    if ((seg->flags & SSHM_FLAG_ENCRYPTED) && !do_encrypt) {
        set_err("write rejected: segment requires encryption");
        return -1;
    }
    if (!(seg->flags & SSHM_FLAG_ENCRYPTED) && do_encrypt) {
        set_err("write rejected: segment is not encrypted");
        return -1;
    }

    if (sshm_wlock(seg) != 0) { set_err("wlock failed"); return -1; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    uint8_t *payload = (uint8_t *)SSHM_PTR(seg->map_base_offset, sizeof(struct segment_header));

    // Begin write (odd = in-progress).
    hdr->version += 1;
    msync(hdr, sizeof *hdr, MS_SYNC);

    // Choose write mode based on flags.
    uint8_t *dst;
    if (hdr->flags & SSHM_FLAG_APPEND_ONLY) {
        dst = payload + hdr->data_len; // Append
    } else {
        dst = payload; // Overwrite
        hdr->data_len = 0; // Reset length
    }
    size_t frame_len = 0;

    if ((seg->flags & SSHM_FLAG_ENCRYPTED) && do_encrypt) {
        if (!seg_has_key(seg)) {
            set_err("encrypt failed: segment has no key");
            hdr->version += 1; // Revert to even.
            msync(hdr, sizeof *hdr, MS_SYNC);
            sshm_wunlock(seg);
            return -1;
        }

        size_t out_len = 0;
        // Calculate *potential* frame length for check
        size_t frame_len_guess = 5 + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        
        // Guard against buffer overflow.
        if (hdr->data_len + frame_len_guess > hdr->payload_size) { // Use data_len (for append) or 0 (for overwrite)
            set_err("write failed: segment is full");
            hdr->version += 1; // Revert to even.
            msync(hdr, sizeof *hdr, MS_SYNC);
            sshm_wunlock(seg);
            return -1;
        }

        // Reserve: type + len + ciphertext (nonce + tag + data).
        dst[0] = 1;
        // Encrypt into dst+5; sshm_encrypt writes [nonce|ct+tag] and returns total size.
        if (sshm_encrypt(seg->key, data, len, dst + 5, &out_len) != 0) {
            set_err("encrypt failed");
            // Revert to even to avoid locking readers.
            hdr->version += 1;
            msync(hdr, sizeof *hdr, MS_SYNC);
            sshm_wunlock(seg);
            return -1;
        }
        uint32_t net_len = htonl((uint32_t)out_len);
        memcpy(dst + 1, &net_len, 4);
        frame_len = 5 + out_len; // Get exact frame length
    } else {
        // Plaintext write.
        frame_len = 5 + len;

        if (hdr->data_len + frame_len > hdr->payload_size) {
            set_err("write failed: segment is full");
            hdr->version += 1; // Revert to even.
            msync(hdr, sizeof *hdr, MS_SYNC);
            sshm_wunlock(seg);
            return -1;
        }

        dst[0] = 0;
        uint32_t net_len = htonl((uint32_t)len);
        memcpy(dst + 1, &net_len, 4);
        memcpy(dst + 5, data, len);
    }

    if (hdr->flags & SSHM_FLAG_APPEND_ONLY) {
        hdr->data_len += frame_len;
    } else {
        hdr->data_len = frame_len;
    }
    hdr->crc32 = simple_crc32(payload, hdr->data_len);

    // End write (even = stable).
    hdr->version += 1;

    msync(hdr, sizeof *hdr, MS_SYNC);
    msync(payload, hdr->data_len, MS_SYNC);

    sshm_wunlock(seg);
    sshm_notify_daemon("write", seg->name);

    sshm_debug("[core]", "Write complete (%zu bytes written) to '%s'", len, seg->name);
    return (ssize_t)len;
}

// Read

ssize_t _sshm_read_internal(sshm_segment_t *seg, void *buffer, size_t buf_len, int do_decrypt) {
    if (!seg || !buffer) return -1;
    sshm_debug("[core]", "Reading from '%s' (decrypt=%d)", seg->name, do_decrypt);
    if (sshm_rlock(seg) != 0) { set_err("rlock failed"); return -1; }

    struct segment_header *hdr = (struct segment_header *)SSHM_PTR(seg->map_base_offset, seg->header_offset);
    uint8_t *payload = (uint8_t *)SSHM_PTR(seg->map_base_offset, sizeof(struct segment_header));

    ssize_t out_total = 0;
    int retries = 16;

    while (retries-- > 0) {
        uint32_t v1 = hdr->version;
        if (v1 & 1) { usleep(1000); continue; } // Writer in progress.

        size_t offset = 0, out_off = 0, data_len = (size_t)hdr->data_len;
        
        // Choose read mode based on flags.
        int loop_frames = (hdr->flags & SSHM_FLAG_APPEND_ONLY);

        while (offset + 5 <= data_len && out_off < buf_len) {
            uint8_t type = payload[offset++];
            uint32_t be_len = 0;
            memcpy(&be_len, payload + offset, 4);
            offset += 4;
            uint32_t clen = ntohl(be_len);
            if (offset + clen > data_len) break; // Incomplete frame.

            if (type == 1) {
                // Encrypted blob = [nonce | ciphertext+tag].
                if (do_decrypt) {
                    if (!seg_has_key(seg)) {
                        set_err("decrypt failed: segment has no key");
                        out_total = -1; // Mark as error.
                        break; // No point retrying if key is missing.
                    }
                    size_t pt_len = buf_len - out_off;
                    if (sshm_decrypt(seg->key, payload + offset, clen,
                                     (uint8_t*)buffer + out_off, &pt_len) == 0) {
                        out_off += pt_len;
                    } else {
                        set_err("decrypt failed: invalid key or corrupt data");
                        out_total = -1; // Mark as error.
                        break; // Data is corrupt; do not retry.
                    }
                } else {
                    // Caller wants ciphertext.
                    size_t tocopy = clen; if (tocopy > buf_len - out_off) tocopy = buf_len - out_off;
                    memcpy((uint8_t*)buffer + out_off, payload + offset, tocopy);
                    out_off += tocopy;
                }
            } else {
                // Plaintext frame.
                size_t tocopy = clen; if (tocopy > buf_len - out_off) tocopy = buf_len - out_off;
                memcpy((uint8_t*)buffer + out_off, payload + offset, tocopy);
                out_off += tocopy;
            }
            offset += clen;

            // If not in append mode, only read one frame.
            if (!loop_frames) {
                break;
            }
        }



        uint32_t v2 = hdr->version;
        if (v1 == v2 && !(v2 & 1)) {
            // Integrity check on the stable snapshot.
            uint32_t expect = hdr->crc32;
            uint32_t actual = simple_crc32(payload, data_len);
            if (expect != 0 && expect != actual) {
                set_err("integrity check failed: checksum mismatch");
                out_total = -1;
                break;
            }
            out_total = (ssize_t)out_off;
            break; // Stable read successful.
        }
        usleep(1000);
    }

    if (retries <= 0 && out_total == 0) {
        set_err("no stable data to read");
        out_total = -1;
    }

    sshm_runlock(seg);
    sshm_notify_daemon("read", seg->name);
    sshm_debug("[core]", "Read %zd bytes from '%s'%s", out_total, seg->name, do_decrypt ? " (dec)" : "");
    return out_total;
}

// Simple name-based wrappers

int sshm_create(const char *name, size_t size, int encrypted, int mode) {
    sshm_debug("[api]", "sshm_create(name=%s, size=%zu, enc=%d, mode=%d)", name, size, encrypted, mode);
    
    uint32_t flags = encrypted ? SSHM_FLAG_ENCRYPTED : SSHM_FLAG_NONE;
    if (mode == SSHM_MODE_APPEND) {
        flags |= SSHM_FLAG_APPEND_ONLY;
    }

    // Try to create the segment.
    sshm_segment_t *seg = _sshm_create_internal(name, size, flags, 0660);

    if (!seg) {
        // If it already exists, validate it matches the requested settings.
        if (errno == EEXIST) {
            sshm_warn("[api]", "sshm_create: Segment '%s' already exists. Opening instead.", name);
            seg = _sshm_open_internal(name, 0);
            if (!seg) {
                set_err("Segment exists, but failed to open: %s", sshm_last_error());
                return -1;
            }

            // Validate encryption expectation against existing segment flags.
            int seg_is_encrypted = (seg->flags & SSHM_FLAG_ENCRYPTED) != 0;
            int want_encrypted = (encrypted != 0);
            if (seg_is_encrypted != want_encrypted) {
                set_err("Segment encryption mismatch");
                _sshm_close_internal(seg);
                return -1;
            }
            
            // Check if existing segment's mode matches the requested mode.
            int seg_is_append = (seg->flags & SSHM_FLAG_APPEND_ONLY);
            int mode_is_append = (mode == SSHM_MODE_APPEND);

            if (seg_is_append != mode_is_append) {
                sshm_error("[api]", "Segment '%s' exists but mode does not match.", name);
                set_err("Segment mode mismatch");
                _sshm_close_internal(seg);
                return -1;
            }
            
            _sshm_close_internal(seg);
            return 0;
        }
        // It failed for some other reason.
        return -1;
    }

    // Create was successful. Close the handle.
    _sshm_close_internal(seg);
    return 0;
}


int sshm_open(const char *name, int encrypted) {
    // No-op: segments are opened/closed per operation.
    sshm_debug("[api]", "sshm_open(name=%s, enc=%d) - no-op", name, encrypted);
    return 0;
}

ssize_t sshm_write(const char *name, const void *buf, size_t len, int encrypt) {
    sshm_debug("[api]", "sshm_write(name=%s, len=%zu, enc=%d)", name, len, encrypt);
    sshm_segment_t *seg = _sshm_open_internal(name, 0);
    if (!seg) return -1;
    ssize_t rc = _sshm_write_internal(seg, buf, len, encrypt);
    _sshm_close_internal(seg);
    return rc;
}

ssize_t sshm_read(const char *name, void *buf, size_t buflen, int decrypt) {
    sshm_debug("[api]", "sshm_read(name=%s, dec=%d)", name, decrypt);
    sshm_segment_t *seg = _sshm_open_internal(name, 0);
    if (!seg) return -1;
    ssize_t n = _sshm_read_internal(seg, buf, buflen, decrypt);
    _sshm_close_internal(seg);
    return n;
}

int sshm_close(const char *name) {
    // No-op: segments are opened/closed per operation.
    sshm_debug("[api]", "sshm_close(name=%s) - no-op", name);
    return 0;
}

int sshm_destroy(const char *name) {
    sshm_debug("[api]", "sshm_destroy(name=%s)", name);
    sshm_segment_t *seg = _sshm_open_internal(name, 0);
    if (!seg) {
        /*
         * If open failed, segment might not exist.
         * We can still try to request daemon removal.
         */
        sshm_warn("[api]", "Segment '%s' not found, attempting key removal anyway.", name);
        remove_key_from_daemon(name);
        return -1;
    }
    return _sshm_destroy_internal(seg);
}