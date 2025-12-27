/*
 * sshm_daemon.c
 * Single-process, multi-threaded client handler daemon.
 * Designed to be run by a service manager like systemd.
 * Runs in the foreground and does NOT manage its own PID/lock file.
 */

#define _GNU_SOURCE
#include "sshm_daemon.h"
#include "sshm_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdatomic.h>

#define SSHM_MAX_LINE 512

/* peer credential type */
typedef struct {
    pid_t pid;
    uid_t uid;
    gid_t gid;
} peercred_t;

/* globals and keystore */
#define MAX_KEYS 256
static sshm_key_entry_t g_keys[MAX_KEYS];
static int g_key_count = 0;
static pthread_mutex_t g_keys_lock = PTHREAD_MUTEX_INITIALIZER;

static volatile sig_atomic_t g_stop = 0;
static int srv_fd = -1; /* Server socket */

/* Basic local DoS guard: cap concurrent client handlers */
#define SSHM_MAX_CONCURRENT_CLIENTS 128
static atomic_int g_active_clients = 0;

// Internal helpers

/*
 * Release lockfile, zero keys, close socket, unlink files.
 * This is the one-stop cleanup function.
 */
static void daemon_cleanup(void) {
    sshm_debug("[daemon]", "Immediate shutdown — socket cleared.");

    if (srv_fd >= 0) {
        close(srv_fd);
        srv_fd = -1;
    }
    unlink(sshm_get_socket_path());

    /* zeroize keys */
    pthread_mutex_lock(&g_keys_lock);
    secure_zero(g_keys, sizeof(g_keys));
    g_key_count = 0;
    pthread_mutex_unlock(&g_keys_lock);

    /* No lock file to clean up */
}

/* small secure random filler */
static int fill_random(uint8_t *b, size_t n) {
    if (!b || n == 0) return -1;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        sshm_error("[daemon]", "Failed to open /dev/urandom: %s", strerror(errno));
        return -1;
    }
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, b + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            sshm_error("[daemon]", "Failed to read %zu bytes from /dev/urandom: %s", n, strerror(errno));
            return -1;
        }
        if (r == 0) {
            close(fd);
            sshm_error("[daemon]", "Short read from /dev/urandom (%zu/%zu)", off, n);
            return -1;
        }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}

/* check ancestry by walking /proc ppid chain */
static int is_descendant(pid_t child, pid_t ancestor) {
    if (child == ancestor) return 1;
    char path[64];
    pid_t cur = child;
    for (int depth = 0; depth < 128; ++depth) {
        if (cur <= 1) return 0;
        snprintf(path, sizeof path, "/proc/%d/stat", (int)cur);
        FILE *f = fopen(path, "r");
        if (!f) return 0;
        int pid=0, ppid=0; char comm[256], state;
        if (fscanf(f, "%d %255s %c %d", &pid, comm, &state, &ppid) != 4) { fclose(f); return 0; }
        fclose(f);
        if ((pid_t)ppid == ancestor) return 1;
        cur = (pid_t)ppid;
    }
    return 0;
}

static int validate_segment_name(const char *name) {
    if (!name || !name[0]) return 0;
    size_t n = strlen(name);
    if (n >= SSHM_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c <= 32 || c == '/' || c == '\\') return 0;
    }
    return 1;
}

static int read_pid_uid(pid_t pid, uid_t *out_uid) {
    if (!out_uid || pid <= 0) return -1;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            unsigned int ruid = 0;
            if (sscanf(line, "Uid:\t%u", &ruid) == 1) {
                fclose(f);
                *out_uid = (uid_t)ruid;
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

/* assumes g_keys_lock held */
static sshm_key_entry_t *find_key_locked(const char *name) {
    for (int i=0;i<g_key_count;i++) {
        if (strncmp(g_keys[i].name, name, SSHM_NAME_MAX)==0) return &g_keys[i];
    }
    return NULL;
}

/* assumes g_keys_lock held */
static int authorize_pid_locked(sshm_key_entry_t *e, pid_t pid, uid_t uid) {
    if (!e) return -1;
    for (int i = 0; i < e->authorized_count; i++) {
        if (e->authorized_pids[i] == pid) {
            /* Update uid in-place (handles re-authorize safely). */
            e->authorized_uids[i] = uid;
            return 0;
        }
    }
    if (e->authorized_count >= SSHM_MAX_AUTH_PIDS) return -1;
    e->authorized_pids[e->authorized_count] = pid;
    e->authorized_uids[e->authorized_count] = uid;
    e->authorized_count++;
    return 0;
}

/* assumes g_keys_lock held */
static int revoke_pid_locked(sshm_key_entry_t *e, pid_t pid) {
    if (!e) return -1;
    for (int i=0;i<e->authorized_count;i++) {
        if (e->authorized_pids[i]==pid) {
            e->authorized_pids[i] = e->authorized_pids[e->authorized_count-1];
            e->authorized_uids[i] = e->authorized_uids[e->authorized_count-1];
            e->authorized_count--;
            return 0;
        }
    }
    return -1;
}

/* Get peer credentials from socket */
static int get_peercred(int fd, peercred_t *out) {
    struct ucred cred; socklen_t len = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
        sshm_warn("[daemon]", "getsockopt(SO_PEERCRED) failed: %s", strerror(errno));
        return -1;
    }
    out->pid = cred.pid; out->uid = cred.uid; out->gid = cred.gid;
    return 0;
}

/* signal handler */
static void on_sig(int s) {
    (void)s;
    g_stop = 1;
    /*
     * Force shutdown of the accept() loop.
     * This is safe because daemon_cleanup() will only run once
     * after the loop exits.
     */
    if (srv_fd >= 0) {
        close(srv_fd);
        srv_fd = -1; /* prevent double-close */
    }
}

static void key_to_hex(const uint8_t *key, char hex[SSHM_KEYBYTES*2+1]) {
    static const char *lut = "0123456789abcdef";
    for (int i = 0; i < SSHM_KEYBYTES; i++) {
        const uint8_t b = key[i];
        hex[i * 2] = lut[(b >> 4) & 0x0F];
        hex[i * 2 + 1] = lut[b & 0x0F];
    }
    hex[SSHM_KEYBYTES * 2] = '\0';
}

/*
 * process a single client inline (synchronous)
 * This function is called by client_thread.
 */
static void handle_client(int cfd) {
    {
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    peercred_t pc;
    if (get_peercred(cfd, &pc) != 0) {
        sshm_warn("[daemon]", "Client(fd=%d) unable to get peercred, closing", cfd);
        close(cfd); return;
    }

    /* Client context for logging */
    char cli_ctx[128];
    snprintf(cli_ctx, sizeof cli_ctx, "Client(pid=%d,uid=%d)", (int)pc.pid, (int)pc.uid);
    sshm_info(cli_ctx, "connected");

    FILE *in = fdopen(dup(cfd), "r");
    if (!in) {
        dprintf(cfd, "ERR fdopen\n");
        close(cfd);
        sshm_warn(cli_ctx, "fdopen failed: %s", strerror(errno));
        return;
    }

    char line[SSHM_MAX_LINE];
    while (fgets(line, sizeof line, in)) {
        if (!strchr(line, '\n') && !feof(in)) {
            int ch;
            while ((ch = fgetc(in)) != '\n' && ch != EOF) { /* drain */ }
            dprintf(cfd, "ERR toolong\n");
            continue;
        }
        size_t L = strlen(line); while (L && (line[L-1]=='\n' || line[L-1]=='\r')) line[--L]='\0';
        char cmd[64]={0}, a1[SSHM_NAME_MAX]={0}, a2[128]={0};
        int tok = sscanf(line, "%63s %255s %127s", cmd, a1, a2);
        if (tok < 1) { dprintf(cfd, "ERR parse\n"); continue; }

        if (tok >= 2 && !validate_segment_name(a1)) {
            dprintf(cfd, "ERR name\n");
            sshm_log_event("WARN", NULL, pc.pid, pc.uid, cmd, "-", "DENY", "badname", NULL);
            continue;
        }

        if (strcmp(cmd, "REGISTER")==0) {
            if (tok < 2) { dprintf(cfd, "ERR args\n"); continue; }
            char key_hex[SSHM_KEYBYTES*2+1] = {0};
            pthread_mutex_lock(&g_keys_lock);
            sshm_key_entry_t *existing = find_key_locked(a1);
            if (existing) {
                pthread_mutex_unlock(&g_keys_lock);
                dprintf(cfd, "ERR exists\n");
                sshm_log_event("WARN", NULL, pc.pid, pc.uid, "REGISTER", a1, "DENY", "exists", NULL);
                continue;
            }
            if (g_key_count >= MAX_KEYS) {
                pthread_mutex_unlock(&g_keys_lock);
                dprintf(cfd, "ERR full\n");
                sshm_log_event("WARN", NULL, pc.pid, pc.uid, "REGISTER", a1, "DENY", "full", NULL);
                continue;
            }
            sshm_key_entry_t *e = &g_keys[g_key_count];
            memset(e, 0, sizeof *e);
            snprintf(e->name, sizeof e->name, "%s", a1);
            e->owner_uid = pc.uid; e->owner_pid = pc.pid; e->created_at = time(NULL);
            if (fill_random(e->key, SSHM_KEYBYTES) != 0) {
                /* g_key_count not incremented, just return */
                pthread_mutex_unlock(&g_keys_lock);
                dprintf(cfd, "ERR rand\n");
                sshm_log_event("WARN", NULL, pc.pid, pc.uid, "REGISTER", a1, "DENY", "randfail", NULL);
                continue;
            }
            g_key_count++; /* Commit new key */
            key_to_hex(e->key, key_hex);
            pthread_mutex_unlock(&g_keys_lock);
            dprintf(cfd, "OK\n");
            /* Never log key material (key_hex) to audit/runtime logs */
            sshm_log_event("INFO", NULL, pc.pid, pc.uid, "REGISTER", a1, "OK", NULL, NULL);
            continue;
        }

        /* FETCH */
        if (strcmp(cmd, "FETCH") == 0) {
            if (tok < 2) { dprintf(cfd, "ERR args\n"); continue; }
            sshm_key_entry_t *e = NULL;
            const char *auth_reason = "unauthorized";
            int authorized = 0;
            char key_hex[SSHM_KEYBYTES*2+1] = {0};

            sshm_debug("[auth]", "verifying key authorisation for pid=%d name=%s", (int)pc.pid, a1);

            pthread_mutex_lock(&g_keys_lock);
            e = find_key_locked(a1);
            if (!e) {
                auth_reason = "notfound";
            } else {
                /* authorization check */
                if (pc.uid == e->owner_uid) {
                    authorized = 1;
                    auth_reason = is_descendant(pc.pid, e->owner_pid) ? "descendant" : "same-uid";
                }
                else {
                    for (int j = 0; j < e->authorized_count; j++) {
                        if (e->authorized_pids[j] == pc.pid && e->authorized_uids[j] == pc.uid) {
                            authorized = 1; auth_reason = "authorized"; break;
                        }
                    }
                }
            }
            if (authorized) {
                key_to_hex(e->key, key_hex);
            }
            pthread_mutex_unlock(&g_keys_lock);

            if (!authorized) {
                sshm_warn("[auth]", "authorisation=denied reason=%s", auth_reason);
                sshm_log_event("WARN", "[auth]", pc.pid, pc.uid, "FETCH", a1, "DENY", auth_reason, NULL);
                dprintf(cfd, "ERR deny\n");
                continue;
            }

            /* authorized -> return key hex */
            sshm_info("[auth]", "authorisation=granted reason=%s", auth_reason);
            /* Never log key material (key_hex) to audit/runtime logs */
            sshm_log_event("INFO", "[auth]", pc.pid, pc.uid, "FETCH", a1, "OK", auth_reason, NULL);
            dprintf(cfd, "OK %s\n", key_hex);
            continue;
        }

        if (strcmp(cmd, "AUTHORIZE")==0) {
            if (tok < 3) { dprintf(cfd,"ERR args\n"); continue; }
            pid_t tgt = (pid_t)strtol(a2,NULL,10);
            int rc = -1;
            const char *reason = NULL;
            pthread_mutex_lock(&g_keys_lock);
            sshm_key_entry_t *e = find_key_locked(a1);
            if (!e) { reason = "notfound"; }
            else if (pc.uid != e->owner_uid) { reason = "notowner"; }
            else {
                uid_t tgt_uid = (uid_t)-1;
                if (read_pid_uid(tgt, &tgt_uid) != 0) {
                    reason = "noproc";
                } else if (tgt_uid != e->owner_uid) {
                    reason = "uidmismatch";
                } else {
                    rc = authorize_pid_locked(e, tgt, tgt_uid);
                    reason = (rc == 0) ? NULL : "full";
                }
            }
            pthread_mutex_unlock(&g_keys_lock);

            dprintf(cfd, rc==0 ? "OK\n" : "ERR perm\n");
            sshm_log_event("INFO", NULL, pc.pid, pc.uid, "AUTHORIZE", a1,
                           rc==0 ? "OK" : "DENY", reason, NULL);
            continue;
        }

        if (strcmp(cmd, "REVOKE")==0) {
            if (tok < 3) { dprintf(cfd,"ERR args\n"); continue; }
            pid_t tgt = (pid_t)strtol(a2,NULL,10);
            int rc = -1;
            const char *reason = NULL;
            pthread_mutex_lock(&g_keys_lock);
            sshm_key_entry_t *e = find_key_locked(a1);
            if (!e) { reason = "notfound"; }
            else if (pc.uid != e->owner_uid) { reason = "notowner"; }
            else {
                rc = revoke_pid_locked(e, tgt);
                reason = (rc == 0) ? NULL : "notfound";
            }
            pthread_mutex_unlock(&g_keys_lock);
            dprintf(cfd, rc==0 ? "OK\n" : "ERR perm\n");
            sshm_log_event("INFO", NULL, pc.pid, pc.uid, "REVOKE", a1,
                           rc==0 ? "OK" : "DENY", reason, NULL);
            continue;
        }

        if (strcmp(cmd, "REMOVE")==0) {
            if (tok < 2) { dprintf(cfd,"ERR args\n"); continue; }
            int rc = -1;
            const char *reason = NULL;
            pthread_mutex_lock(&g_keys_lock);
            int idx = -1;
            for (int i=0;i<g_key_count;i++) if (strcmp(g_keys[i].name,a1)==0) { idx=i; break; }

            if (idx < 0) { reason = "notfound"; }
            else {
                sshm_key_entry_t *e = &g_keys[idx];
                if (!(pc.uid == 0 || pc.uid == e->owner_uid)) {
                    reason = "perm";
                } else {
                    /* Found and authorized, perform remove */
                    secure_zero(e->key, SSHM_KEYBYTES);
                    /* Compact the array */
                    for (int j=idx;j<g_key_count-1;j++) g_keys[j]=g_keys[j+1];
                    memset(&g_keys[g_key_count-1], 0, sizeof(g_keys[0]));
                    g_key_count--;
                    rc = 0;
                }
            }
            pthread_mutex_unlock(&g_keys_lock);

            dprintf(cfd, rc==0 ? "OK\n" : "ERR perm\n");
            sshm_log_event("INFO", NULL, pc.pid, pc.uid, "REMOVE", a1,
                           rc==0 ? "OK" : "DENY", reason, NULL);
            continue;
        }

        if (strcmp(cmd, "PING")==0) { dprintf(cfd,"OK PONG\n"); continue; }

        if (strcmp(cmd, "SHUTDOWN")==0) {
            sshm_log_event("INFO", NULL, pc.pid, pc.uid, "SHUTDOWN", "-", "OK", NULL, NULL);
            dprintf(cfd,"OK Shutting down\n");
            fclose(in); close(cfd);
            g_stop = 1;
            /*
             * Force the accept() loop to break.
             * This is safe because daemon_cleanup() only runs after the loop exits.
             */
            if (srv_fd >= 0) {
                close(srv_fd);
                srv_fd = -1;
            }
            return;
        }

        dprintf(cfd,"ERR cmd\n");
    }

    fclose(in);
    close(cfd);
    sshm_info(cli_ctx, "disconnected");
}

/*
 * Thread wrapper for handle_client
 */
static void* client_thread(void *arg) {
    int cfd = (int)(intptr_t)arg;
    handle_client(cfd);
    atomic_fetch_sub(&g_active_clients, 1);
    return NULL;
}


// Main loop and guards

int sshm_daemon_run(void) {
    /* ensure log dir exists (configurable for CI/tests) */
    mkdir(sshm_get_audit_dir(), 0750);
    sshm_debug("[daemon]", "Daemon starting...");

    /*
     * 2. Check for stale/active socket
     * systemd handles this, but unlinking at start is good for cleanup.
     */
    unlink(sshm_get_socket_path()); /* Clean up stale socket just in case */


    /* 3. Create and bind server socket */
    srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        sshm_error("[daemon]", "socket() failed: %s", strerror(errno));
        daemon_cleanup(); return 1;
    }

    struct sockaddr_un addr; memset(&addr,0,sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sshm_get_socket_path(), sizeof addr.sun_path - 1);
    umask(0177); /* Set umask to 0177 so 0600 perms are effective */
    if (bind(srv_fd, (struct sockaddr*)&addr, sizeof addr) < 0) {
        sshm_error("[daemon]", "bind() failed for %s: %s", sshm_get_socket_path(), strerror(errno));
        daemon_cleanup(); return 1;
    }
    /* Socket permissions are configurable so non-root users/CI can work safely.
     * Default remains 0600.
     */
    mode_t sock_mode = 0600;
    const char *sock_mode_s = getenv("SSHM_SOCKET_MODE");
    if (sock_mode_s && sock_mode_s[0]) {
        char *end = NULL;
        long v = strtol(sock_mode_s, &end, 8);
        if (end && end != sock_mode_s && v >= 0 && v <= 0777) {
            sock_mode = (mode_t)v;
        }
    }
    chmod(sshm_get_socket_path(), sock_mode);

    if (listen(srv_fd, 128) < 0) {
        sshm_error("[daemon]", "listen() failed: %s", strerror(errno));
        daemon_cleanup(); return 1;
    }

    /* 4. Setup signal handlers */
    struct sigaction sa; memset(&sa,0,sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* Ignore SIGPIPE so write errors are handled inline */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    sshm_info("[daemon]", "Daemon listening at %s (pid=%d)", sshm_get_socket_path(), (int)getpid());
    log_json_event(getpid(), getuid(), "start", sshm_get_socket_path(), "OK", NULL, NULL);

    while (!g_stop) {
        int cfd = accept(srv_fd, NULL, NULL);
        if (cfd < 0) {
            if (g_stop) break; /* Normal shutdown */
            if (errno == EINTR) continue;
            sshm_warn("[daemon]", "accept() failed: %s", strerror(errno));
            continue;
        }

        int active = atomic_fetch_add(&g_active_clients, 1) + 1;
        if (active > SSHM_MAX_CONCURRENT_CLIENTS) {
            atomic_fetch_sub(&g_active_clients, 1);
            dprintf(cfd, "ERR busy\n");
            close(cfd);
            continue;
        }
        /* Spawn thread to handle client */
        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, (void*)(intptr_t)cfd) != 0) {
            sshm_warn("[daemon]", "Failed to create client thread: %s", strerror(errno));
            atomic_fetch_sub(&g_active_clients, 1);
            close(cfd);
        }
        pthread_detach(th);
    }

    /* 5. Cleanup */
    sshm_info("[daemon]", "Shutdown signal received, cleaning up...");
    log_json_event(getpid(), getuid(), "stop", sshm_get_socket_path(), "OK", NULL, NULL);
    daemon_cleanup();

    sshm_info("[daemon]", "Daemon stopped.");
    return 0;
}