/*
 * sshm_utils.c
 * Central logging, audit, and small runtime helpers.
 */

#include "sshm_utils.h"
#include "sshm_daemon.h" /* For SSHM_SOCKET_PATH */
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>

/* Defaults (can be overridden by env vars via getters below) */
#define SSHM_DEFAULT_AUDIT_DIR   "/var/log/sshm"
#define SSHM_DEFAULT_AUDIT_FILE  "/var/log/sshm/audit.log"
#define SSHM_DEFAULT_RUNTIME_LOG "/var/log/sshm/sshm.log"

static const char *env_or_default(const char *env_name, const char *def) {
    const char *v = getenv(env_name);
    return (v && v[0]) ? v : def;
}

static int file_exists(const char *path) {
    struct stat st;
    return (path && stat(path, &st) == 0);
}

const char *sshm_get_socket_path(void) {
    /* Default comes from daemon header macro for backward compatibility. */
    return env_or_default("SSHM_SOCKET_PATH", SSHM_SOCKET_PATH);
}

const char *sshm_get_audit_dir(void) {
    return env_or_default("SSHM_AUDIT_DIR", SSHM_DEFAULT_AUDIT_DIR);
}

const char *sshm_get_audit_file(void) {
    return env_or_default("SSHM_AUDIT_FILE", SSHM_DEFAULT_AUDIT_FILE);
}

const char *sshm_get_runtime_log(void) {
    return env_or_default("SSHM_RUNTIME_LOG", SSHM_DEFAULT_RUNTIME_LOG);
}

const char *sshm_get_state_dir(void) {
    const char *v = getenv("SSHM_STATE_DIR");
    if (v && v[0]) return v;

    /* By default, keep state next to the socket path when possible (test-friendly). */
    const char *sock = getenv("SSHM_SOCKET_PATH");
    if (!sock || !sock[0]) return "/tmp";

    static char dir[256];
    const char *slash = strrchr(sock, '/');
    if (!slash || slash == sock) return "/tmp";
    size_t n = (size_t)(slash - sock);
    if (n >= sizeof(dir)) return "/tmp";
    memcpy(dir, sock, n);
    dir[n] = '\0';
    return dir;
}

const char *sshm_get_debug_flag_file(void) {
    static char path[512];
    const char *dir = sshm_get_state_dir();
    if (!dir || !dir[0]) dir = "/tmp";
    snprintf(path, sizeof path, "%s/%s", dir, "sshm.debug");
    return path;
}

static int env_debug_enabled(void) {
    const char *v = getenv("SSHM_DEBUG");
    if (!v || !v[0]) return 0;
    return (strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcmp(v, "yes") == 0);
}

int sshm_is_debug_enabled(void) {
    if (env_debug_enabled()) return 1;
    return file_exists(sshm_get_debug_flag_file());
}

int sshm_set_debug_enabled(int enabled) {
    const char *flag = sshm_get_debug_flag_file();
    if (!flag) return -1;

    const char *dir = sshm_get_state_dir();
    if (dir && dir[0]) {
        (void)mkdir(dir, 0755);
    }

    if (enabled) {
        int fd = open(flag, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return -1;
        (void)write(fd, "1\n", 2);
        close(fd);
        return 0;
    }

    if (unlink(flag) != 0 && errno != ENOENT) return -1;
    return 0;
}

static const size_t AUDIT_ROTATE_BYTES = 1024*1024; /* 1MB */

static void json_write_escaped(int fd, const char *s) {
    if (!s) s = "";
    for (const unsigned char *p = (const unsigned char*)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '\\': (void)write(fd, "\\\\", 2); break;
            case '"':  (void)write(fd, "\\\"", 2); break;
            case '\b': (void)write(fd, "\\b", 2); break;
            case '\f': (void)write(fd, "\\f", 2); break;
            case '\n': (void)write(fd, "\\n", 2); break;
            case '\r': (void)write(fd, "\\r", 2); break;
            case '\t': (void)write(fd, "\\t", 2); break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    snprintf(buf, sizeof buf, "\\u%04x", (unsigned int)c);
                    (void)write(fd, buf, strlen(buf));
                } else {
                    (void)write(fd, (const char*)&c, 1);
                }
        }
    }
}

/* timestamp local [HH:MM:SS] */
char *sshm_timestamp(char *buf, size_t n) {
    if (!buf || n==0) return NULL;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, n, "%H:%M:%S", &tm);
    return buf;
}

static int level_to_num(const char *level) {
    if (!level) return 2;
    if (strcmp(level, "ERROR") == 0) return 0;
    if (strcmp(level, "WARN") == 0) return 1;
    if (strcmp(level, "INFO") == 0) return 2;
    if (strcmp(level, "DEBUG") == 0) return 3;
    return 2;
}

/*
 * internal log writer
 * - runtime log: INFO/WARN/ERROR by default, DEBUG only when enabled
 * - stderr: WARN/ERROR by default, INFO/DEBUG only when enabled
 */
void _sshm_log(const char *level, const char *context, const char *fmt, ...) {
    if (!level) level = "INFO";
    const int msg_level = level_to_num(level);
    const int debug_on = sshm_is_debug_enabled();
    const int file_level = debug_on ? 3 : 2;
    const int stderr_level = debug_on ? 3 : 1;

    if (msg_level > file_level && msg_level > stderr_level) return;

    char ts[16]; sshm_timestamp(ts, sizeof ts);
    va_list ap;
    va_start(ap, fmt);
    char msg[1024];
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    char line[1400];
    snprintf(line, sizeof line, "[%s] [%s] %s %s\n", ts, level, context ? context : "", msg);

    if (msg_level <= stderr_level) {
        fputs(line, stderr);
    }

    if (msg_level <= file_level) {
        const char *runtime_log = sshm_get_runtime_log();
        int fd = open(runtime_log, O_WRONLY|O_CREAT|O_APPEND, 0640);
        if (fd >= 0) {
            (void)flock(fd, LOCK_EX);
            (void)write(fd, line, strlen(line));
            (void)flock(fd, LOCK_UN);
            close(fd);
        }
    }
}

/*
 * Ensures audit directory exists and rotates log file if needed.
 * Returns 0 on success, -1 on failure.
 */
static int ensure_audit_ready(void) {
    const char *audit_dir = sshm_get_audit_dir();
    struct stat st;
    if (stat(audit_dir, &st) != 0) {
        if (errno == ENOENT) {
            if (mkdir(audit_dir, 0750) != 0 && errno != EEXIST) {
                sshm_error("[util]", "Failed to create audit dir %s: %s", audit_dir, strerror(errno));
                return -1;
            }
            sshm_info("[util]", "Created audit directory: %s", audit_dir);
        } else {
            sshm_error("[util]", "Failed to stat audit dir %s: %s", audit_dir, strerror(errno));
            return -1;
        }
    }
    return 0;
}


/*
 * structured log_event -> runtime and audit JSON
 * This is the primary function for logging auditable events.
 */
int sshm_log_event(const char *level, const char *context, pid_t pid, uid_t uid,
                   const char *action, const char *name,
                   const char *result, const char *reason, const char *key_hex) {
    (void)key_hex; /* Never log key material (even if provided by callers). */
    char ctx[512];
    /* Build human-readable context for runtime log */
    snprintf(ctx, sizeof ctx, "Client(pid=%d,uid=%d)", (int)pid, (int)uid);

    char msg[1024];
    snprintf(msg, sizeof msg, "%s %s name=\"%s\" result=%s%s%s",
             context ? context : "",
             action, name ? name : "-",
             result ? result : "-",
             (reason && reason[0]) ? " reason=" : "", (reason && reason[0]) ? reason : "");

    /* Log to runtime log (human-readable) */
    if (strcmp(level, "INFO") == 0) {
        sshm_info(ctx, "%s", msg);
    } else if (strcmp(level, "WARN") == 0) {
        sshm_warn(ctx, "%s", msg);
    } else if (strcmp(level, "DEBUG") == 0) {
        sshm_debug(ctx, "%s", msg);
    } else {
        _sshm_log(level, ctx, "%s", msg);
    }

    /* Log to audit log (JSON) - keys are never written */
    log_json_event(pid, uid, action, name ? name : "-", result ? result : "-", reason ? reason : "", NULL);
    return 0;
}

/*
 * audit JSON (UTC timestamp)
 * Logs *only* to the JSON audit file.
 */
int log_json_event(pid_t pid, uid_t uid, const char *action,
                   const char *name, const char *result, const char *reason, const char *key_hex) {
    (void)key_hex; /* Never write key material to audit logs. */

    if (ensure_audit_ready() != 0) return -1;

    /* UTC timestamp */
    char ts[64];
    time_t t = time(NULL); struct tm g; gmtime_r(&t, &g);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &g);

    const char *audit_file = sshm_get_audit_file();
    int fd = open(audit_file, O_WRONLY|O_CREAT|O_APPEND, 0640);
    if (fd < 0) {
        sshm_error("[util]", "Failed to open audit file %s: %s", audit_file, strerror(errno));
        return -1;
    }

    (void)flock(fd, LOCK_EX);

    /* Rotate under lock. */
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > (off_t)AUDIT_ROTATE_BYTES) {
        char bak[256], ts_utc[32];
        time_t t2 = time(NULL); struct tm g2; gmtime_r(&t2, &g2);
        strftime(ts_utc, sizeof ts_utc, "%Y%m%dT%H%M%SZ", &g2);
        snprintf(bak, sizeof bak, "%s/audit-%s.log", sshm_get_audit_dir(), ts_utc);
        (void)rename(audit_file, bak);

        (void)flock(fd, LOCK_UN);
        close(fd);
        fd = open(audit_file, O_WRONLY|O_CREAT|O_APPEND, 0640);
        if (fd < 0) return -1;
        (void)flock(fd, LOCK_EX);
    }

    (void)write(fd, "{\"ts\":\"", 7);
    json_write_escaped(fd, ts);
    dprintf(fd, "\",\"pid\":%d,\"uid\":%d,\"action\":\"", (int)pid, (int)uid);
    json_write_escaped(fd, action);
    (void)write(fd, "\",\"name\":\"", sizeof("\",\"name\":\"") - 1);
    json_write_escaped(fd, name);
    (void)write(fd, "\",\"result\":\"", sizeof("\",\"result\":\"") - 1);
    json_write_escaped(fd, result);
    (void)write(fd, "\"", 1);
    if (reason && reason[0]) {
        (void)write(fd, ",\"reason\":\"", 11);
        json_write_escaped(fd, reason);
        (void)write(fd, "\"", 1);
    }
    (void)write(fd, "}\n", 2);

    (void)flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

/* DEPRECATED - Use log_json_event */
void write_audit_log(const char *fmt, ...) {
    if (ensure_audit_ready() != 0) {
        va_list ap; va_start(ap, fmt);
        sshm_warn("[util-compat]", "Failed to write to audit log. Fallback to stderr:");
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
        return;
    }
    const char *audit_file = sshm_get_audit_file();
    int fd = open(audit_file, O_WRONLY|O_CREAT|O_APPEND, 0640);
    if (fd < 0) return;
    char ts[64];
    time_t t = time(NULL); struct tm g; gmtime_r(&t, &g);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &g);
    dprintf(fd, "{\"ts\":\"%s\",\"legacy_msg\":\"", ts);
    va_list ap; va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
    dprintf(fd, "\"}\n");
    close(fd);
}


/* Securely zero memory */
void secure_zero(void *p, size_t n) {
    if (!p || n == 0) return;
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile unsigned char *v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
#endif
}

// Simple JSON helpers (audit viewer)

/**
 * @brief Basic JSON string value extractor.
 * Finds a key like "action":"value" and copies "value" into out.
 * @return 1 on success, 0 on failure.
 */
static int json_get_string(const char *json_line, const char *key, char *out, size_t out_n) {
    char key_str[128];
    snprintf(key_str, sizeof(key_str), "\"%s\":\"", key); // e.g., "action":"
    
    const char *start = strstr(json_line, key_str);
    if (!start) return 0; // Key not found
    
    start += strlen(key_str); // Move pointer to start of value
    const char *end = strchr(start, '"');
    if (!end) return 0; // Closing quote not found
    
    size_t len = (size_t)(end - start);
    if (len >= out_n) len = out_n - 1; // Truncate
    
    memcpy(out, start, len);
    out[len] = '\0';
    return 1;
}

/**
 * @brief Basic JSON integer value extractor.
 * Finds a key like "pid":123 and parses 123.
 * @return 1 on success, 0 on failure.
 */
static int json_get_int(const char *json_line, const char *key, int *out) {
    char key_str[128];
    snprintf(key_str, sizeof(key_str), "\"%s\":", key); // e.g., "pid":
    
    const char *start = strstr(json_line, key_str);
    if (!start) return 0;
    
    start += strlen(key_str);
    // Skip whitespace
    while (*start == ' ' || *start == '\t') start++;
    
    *out = atoi(start); // Simple, assumes number is next
    return 1;
}


int show_audit_log(int count, int json_output) {
    if (ensure_audit_ready() != 0) {
        sshm_error("[cli]", "No audit log found or audit directory inaccessible.");
        return -1;
    }
    const char *audit_file = sshm_get_audit_file();
    FILE *f = fopen(audit_file, "r");
    if (!f) {
        sshm_error("[cli]", "Failed to open audit file %s: %s", audit_file, strerror(errno));
        return -1;
    }
    char **lines = NULL; size_t nlines = 0;
    char *ln = NULL; size_t cap = 0; ssize_t sz;
    while ((sz = getline(&ln, &cap, f)) > 0) {
        if (sz>0 && ln[sz-1]=='\n') ln[sz-1]=0;
        char *c = strdup(ln);
        if (!c) continue;
        char **tmp = realloc(lines, (nlines+1)*sizeof(char*));
        if (!tmp) { free(c); break; }
        lines = tmp; lines[nlines++] = c;
    }
    free(ln); fclose(f);
    size_t start = 0;
    if (count>0 && (size_t)count < nlines) start = nlines - (size_t)count;
    
    for (size_t i = start; i < nlines; ++i) {
        if (json_output) {
            printf("%s\n", lines[i]);
        } else {
            if (lines[i][0] != '{') {
                continue;
            }
            
            char ts[64] = {0}, action[64] = {0}, name[256] = {0};
            char result[64] = {0}, reason[64] = {0};
            int pid = 0, uid = 0;

            json_get_string(lines[i], "ts", ts, sizeof(ts));
            json_get_string(lines[i], "action", action, sizeof(action));
            json_get_string(lines[i], "name", name, sizeof(name));
            json_get_string(lines[i], "result", result, sizeof(result));
            json_get_string(lines[i], "reason", reason, sizeof(reason));
            json_get_int(lines[i], "pid", &pid);
            json_get_int(lines[i], "uid", &uid);

                 printf("[%s] %-8s (pid:%-6d uid:%-5d) name=%-20s result=%-4s%s%s\n",
                   ts, action, pid, uid, name, result,
                     reason[0] ? " reason=" : "", reason);
        }
        free(lines[i]);
    }
    free(lines);
    return 0;
}

/* Return 1 if the daemon socket is responsive, else 0 */
int sshm_check_daemon_alive(void) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sshm_get_socket_path(), sizeof(addr.sun_path) - 1);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; /* 500ms timeout */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    int ok = (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    close(fd);
    return ok;
}
