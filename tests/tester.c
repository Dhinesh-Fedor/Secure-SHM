#define _GNU_SOURCE
#include "sshm.h"


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

/* ---------- ANSI (only for UX; not required) ---------- */
#define C_RESET  "\033[0m"
#define C_GRN    "\033[1;32m"
#define C_RED    "\033[1;31m"
#define C_YLW    "\033[1;33m"
#define C_CYN    "\033[1;36m"
#define C_BLU    "\033[1;34m"

/* ---------- Config ---------- */
typedef struct {
    const char *seg;
    size_t size;
    int encrypted;
    int decrypt_reads;
    int writers;
    int readers;
    int loops;
    unsigned delay_ms;
    const char *msg;
    int mode;             /* <-- FIX: ADDED */
    int debug;            /* sets SSHM_DEBUG=1 in environment */
} cfg_t;

static void print_help(const char *prog) {
    printf(C_CYN "SSHM concurrency test\n" C_RESET);
    printf("Usage:\n");
    printf("  %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --seg <name>         Segment name (default: hw_test)\n");
    printf("  --size <bytes>       Segment size (default: 4096)\n");
    printf("  --encrypted|--plain  Create encrypted/plain segment (default: encrypted)\n");
    printf("  --append             Create segment in append-only mode (default: overwrite)\n"); /* <-- FIX: ADDED */
    printf("  --writers N          Number of writer children (default: 2)\n");
    printf("  --readers N          Number of reader children (default: 2)\n");
    printf("  --loops N            Each writer writes N times (default: 1)\n");
    printf("  --msg \"text\"         Writer base message (default: \"Hello from writer\")\n");
    printf("  --delay-ms N         Base delay between child starts (default: 150)\n");
    printf("  --dec                Decrypt on reads (default: on when encrypted)\n");
    printf("  --debug              Set SSHM_DEBUG=1 (library debug)\n");
    printf("  --help               Show this help\n");
}

static unsigned ms_to_us(unsigned ms) { return ms * 1000U; }

static void child_reader(int id, const char *seg_name, unsigned int delay_us, int do_dec) {
    usleep(delay_us);
    char buf[1<<16];
    ssize_t n = sshm_read(seg_name, buf, sizeof(buf) - 1, do_dec);
    if (n < 0) {
        fprintf(stderr, C_RED "[reader %d pid=%d] read error: %s\n" C_RESET,
                id, getpid(), sshm_last_error());
        _exit(2);
    }
    buf[n] = '\0';
    printf(C_BLU "[reader %d pid=%d] read %zd bytes%s\n" C_RESET,
           id, getpid(), n, do_dec ? " (dec)" : "");
    /* Print at most first 256 bytes to avoid flooding */
    size_t shown = (size_t)n < 256 ? (size_t)n : 256;
    fwrite(buf, 1, shown, stdout);
    if (shown && buf[shown-1] != '\n') fputc('\n', stdout);
    fflush(stdout);
    _exit(0);
}

static void child_writer(int id, const char *seg_name, const char *msg, int loops,
                         unsigned int delay_us) {
    usleep(delay_us);
    size_t base_len = strlen(msg);
    char line[1024];
    for (int k = 0; k < loops; ++k) {
        int n = snprintf(line, sizeof line, "%s [writer=%d loop=%d]\n", msg, id, k+1);
        if (n < 0) { _exit(3); }
        ssize_t w = sshm_write(seg_name, line, (size_t)n, 1 /* encrypt if seg encrypted */);
        if (w < 0) {
            fprintf(stderr, C_RED "[writer %d pid=%d] write error: %s\n" C_RESET,
                    id, getpid(), sshm_last_error());
            _exit(3);
        }
        printf(C_GRN "[writer %d pid=%d] wrote %zd bytes: \"%.*s\"\n" C_RESET,
               id, getpid(), w, (int)(base_len > 40 ? 40 : base_len), msg);
        fflush(stdout);
        /* small intra-loop delay to mix with readers */
        usleep(30000);
    }
    _exit(0);
}

static int parse_int(const char *s, int *out) {
    char *end = NULL; long v = strtol(s, &end, 10);
    if (!s || *s == '\0' || !end || *end != '\0') return -1;
    *out = (int)v; return 0;
}

static int parse_size_t(const char *s, size_t *out) {
    char *end = NULL; unsigned long long v = strtoull(s, &end, 10);
    if (!s || *s == '\0' || !end || *end != '\0') return -1;
    *out = (size_t)v; return 0;
}

int main(int argc, char **argv) {
    cfg_t cfg = {
        .seg = "hw_test",
        .size = 4096,
        .encrypted = 1,
        .decrypt_reads = -1, /* auto: same as encrypted */
        .writers = 2,
        .readers = 2,
        .loops = 1,
        .delay_ms = 150,
        .msg = "Hello from writer",
        .mode = SSHM_MODE_OVERWRITE, /* <-- FIX: ADDED */
        .debug = 0
    };

    /* Parse args */
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            print_help(argv[0]); return 0;
        } else if (!strcmp(argv[i], "--seg") && i+1 < argc) {
            cfg.seg = argv[++i];
        } else if (!strcmp(argv[i], "--size") && i+1 < argc) {
            if (parse_size_t(argv[++i], &cfg.size) != 0) { fprintf(stderr, "bad --size\n"); return 1; }
        } else if (!strcmp(argv[i], "--encrypted")) {
            cfg.encrypted = 1;
        } else if (!strcmp(argv[i], "--plain")) {
            cfg.encrypted = 0;
        } else if (!strcmp(argv[i], "--append")) { /* <-- FIX: ADDED */
            cfg.mode = SSHM_MODE_APPEND;
        } else if (!strcmp(argv[i], "--writers") && i+1 < argc) {
            if (parse_int(argv[++i], &cfg.writers) != 0) { fprintf(stderr, "bad --writers\n"); return 1; }
        } else if (!strcmp(argv[i], "--readers") && i+1 < argc) {
            if (parse_int(argv[++i], &cfg.readers) != 0) { fprintf(stderr, "bad --readers\n"); return 1; }
        } else if (!strcmp(argv[i], "--loops") && i+1 < argc) {
            if (parse_int(argv[++i], &cfg.loops) != 0) { fprintf(stderr, "bad --loops\n"); return 1; }
        } else if (!strcmp(argv[i], "--msg") && i+1 < argc) {
            cfg.msg = argv[++i];
        } else if (!strcmp(argv[i], "--delay-ms") && i+1 < argc) {
            int v=0; if (parse_int(argv[++i], &v) != 0 || v < 0) { fprintf(stderr, "bad --delay-ms\n"); return 1; }
            cfg.delay_ms = (unsigned)v;
        } else if (!strcmp(argv[i], "--dec")) {
            cfg.decrypt_reads = 1;
        } else if (!strcmp(argv[i], "--debug")) {
            cfg.debug = 1;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    if (cfg.decrypt_reads == -1) cfg.decrypt_reads = cfg.encrypted ? 1 : 0;

    if (cfg.debug) setenv("SSHM_DEBUG", "1", 1);

    if (sshm_init() != 0) {
        fprintf(stderr, C_RED "sshm_init failed: %s\n" C_RESET, sshm_last_error());
        return 1;
    }

    /* --- FIX: Updated printf to show mode --- */
    printf(C_CYN "[parent pid=%d] Creating %s segment '%s' (size=%zu, mode=%s)\n" C_RESET,
           getpid(), cfg.encrypted ? "encrypted" : "plain", cfg.seg, cfg.size,
           cfg.mode == SSHM_MODE_APPEND ? "append" : "overwrite");

    /* --- FIX: Use new API with mode --- */
    if (sshm_create(cfg.seg, cfg.size, cfg.encrypted, cfg.mode) != 0) {
        fprintf(stderr, C_YLW "create may exist / failed: %s (continuing with open)\n" C_RESET, sshm_last_error());
        /* Try opening so downstream ops can proceed if already present */
        if (sshm_open(cfg.seg, cfg.encrypted) != 0) {
            fprintf(stderr, C_RED "open failed too: %s\n" C_RESET, sshm_last_error());
            return 1;
        }
    }

    /* Seed initial frame */
    const char *init = "INITIAL\n";
    if (sshm_write(cfg.seg, init, strlen(init), cfg.encrypted) < 0) {
        fprintf(stderr, C_RED "initial write failed: %s\n" C_RESET, sshm_last_error());
        return 1;
    }

    int total_children = cfg.writers + cfg.readers;
    pid_t *pids = (pid_t*)calloc((size_t)total_children, sizeof(pid_t));
    int idx = 0;

    /* Readers */
    for (int i = 0; i < cfg.readers; ++i) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) {
            child_reader(i+1, cfg.seg, ms_to_us(cfg.delay_ms * (unsigned)(i+1)), cfg.decrypt_reads);
        }
        pids[idx++] = pid;
        printf(C_BLU "[parent] spawned reader %d pid=%d\n" C_RESET, i+1, pid);
    }

    /* Writers */
    for (int i = 0; i < cfg.writers; ++i) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) {
            child_writer(i+1, cfg.seg, cfg.msg, cfg.loops, ms_to_us(cfg.delay_ms * (unsigned)(i+1 + cfg.readers)));
        }
        pids[idx++] = pid;
        printf(C_GRN "[parent] spawned writer %d pid=%d\n" C_RESET, i+1, pid);
    }

    /* Wait all */
    int exit_status = 0;
    for (int i = 0; i < total_children; ++i) {
        int st=0; pid_t w = waitpid(pids[i], &st, 0);
        if (w <= 0) { perror("waitpid"); exit_status = 1; continue; }
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            fprintf(stderr, C_RED "[parent] child pid=%d exited abnormally (st=0x%x)\n" C_RESET, w, st);
            exit_status = 1;
        }
    }
    free(pids);

    /* Final read */
    {
        char buf[1<<20];
        ssize_t r = sshm_read(cfg.seg, buf, sizeof(buf) - 1, cfg.decrypt_reads);
        if (r >= 0) {
            buf[r] = '\0';
            printf(C_CYN "[final parent pid=%d] read %zd bytes%s\n" C_RESET,
                   getpid(), r, cfg.decrypt_reads ? " (dec)" : "");
            /* show last ~512 bytes to keep output manageable */
            size_t show = (size_t)r;
            const size_t lim = 512;
            const char *p = buf;
            if (show > lim) { p = buf + (show - lim); show = lim; printf("(…tail)\n"); }
            fwrite(p, 1, show, stdout);
            if (show && p[show-1] != '\n') fputc('\n', stdout);
        } else {
            fprintf(stderr, C_RED "[final parent] read failed: %s\n" C_RESET, sshm_last_error());
            exit_status = 1;
        }
    }

 

    /* Optional cleanup (keep commented if you want to inspect segment content externally) */
    // sshm_destroy(cfg.seg);
    // sshm_shutdown();

    return exit_status;
}