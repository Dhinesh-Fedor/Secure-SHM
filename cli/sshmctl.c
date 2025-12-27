/*
 * sshmctl.c
 * CLI for managing the sshmd service via systemd.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include <sys/wait.h>

#include "sshm.h"
#include "sshm_core.h"
#include "sshm_daemon.h"
#include "sshm_utils.h"
#include "sshm_core_internal.h"

/* colors */
#define C_RESET   "\033[0m"
#define C_GREEN   "\033[1;32m"
#define C_RED     "\033[1;31m"
#define C_YELLOW  "\033[1;33m"
#define C_CYAN    "\033[1;36m"
#define C_BLUE    "\033[1;34m"

// Global debug toggle
static int DEBUG_MODE = 0;
static int JSON_OUTPUT = 0;
#define DPRINT(fmt, ...) \
    do { if (DEBUG_MODE) fprintf(stderr, C_BLUE "[DEBUG] " C_RESET fmt "\n", ##__VA_ARGS__); } while(0)

// Socket connection (for socket-protocol commands)
static int sock_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        sshm_error("[cli]", "socket() failed: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr; memset(&addr,0,sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sshm_get_socket_path(), sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) {
        sshm_error("[cli]", "connect() to daemon failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    sshm_debug("[cli]", "Connected to daemon socket: %s", sshm_get_socket_path());
    return fd;
}

// Command sender (socket-protocol commands)
static int send_line_cmd(const char *line) {
    int fd = sock_connect();
    if (fd < 0) return 1;
    sshm_debug("[cli]", "Sending command: '%s'", line);
    dprintf(fd, "%s\n", line);
    char buf[4096]; ssize_t n = read(fd, buf, sizeof buf - 1);
    int rc = 1;
    if (n > 0) {
        buf[n] = 0;
        printf("%s", buf);
        /* Treat any non-OK response as failure for scripting/tests. */
        rc = (strncmp(buf, "OK", 2) == 0) ? 0 : 1;
    } else {
        sshm_error("[cli]", "No response from daemon.");
        fprintf(stderr, C_RED "[ERR] No response from daemon.\n" C_RESET);
        rc = 1;
    }
    close(fd);
    return rc;
}

static int file_exists(const char *p){
    struct stat st; return (stat(p,&st)==0 && S_ISREG(st.st_mode));
}

static int cmd_ping(void) {
    return send_line_cmd("PING");
}

static int cmd_shutdown_socket(void) {
    return send_line_cmd("SHUTDOWN");
}

static int cmd_info(const char *name) {
    if (!name || !name[0]) return 1;

    char shm_name[512];
    snprintf(shm_name, sizeof shm_name, "/sshm_%s", name);

    int fd = shm_open(shm_name, O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, C_RED "[DENY]" C_RESET " Segment '%s' not found (%s)\n", name, strerror(errno));
        return 1;
    }

    struct segment_header hdr;
    ssize_t r = read(fd, &hdr, sizeof hdr);
    close(fd);
    if (r != (ssize_t)sizeof hdr) {
        fprintf(stderr, C_RED "[DENY]" C_RESET " Failed to read segment header for '%s'\n", name);
        return 1;
    }

    printf("name=%s\n", name);
    printf("flags=%s (0x%08x)\n", sshm_flags_to_string(hdr.flags), hdr.flags);
    printf("payload_size=%llu\n", (unsigned long long)hdr.payload_size);
    printf("data_len=%llu\n", (unsigned long long)hdr.data_len);
    printf("version=%llu\n", (unsigned long long)hdr.version);
    printf("crc32=0x%08x\n", hdr.crc32);
    return 0;
}

// Help
static void print_help(const char *prog) {
    printf(C_CYAN "Secure Shared Memory Toolkit CLI (sshmctl)\n" C_RESET);
    printf("Usage:\n");
    printf("  %s " C_YELLOW "start-daemon" C_RESET "              - Start sshm daemon (via systemd)\n", prog);
    printf("  %s " C_YELLOW "shutdown-daemon" C_RESET "           - Stop the daemon (via systemd)\n", prog);
    printf("  %s " C_YELLOW "restart-daemon" C_RESET "            - Restart the daemon (via systemd)\n", prog);
    printf("  %s " C_YELLOW "status-daemon" C_RESET "             - Check daemon status (via systemd)\n", prog);
    printf("\n");
    printf("  %s " C_YELLOW "create <name> <size> [--enc] [--append]" C_RESET " - Create a new segment\n", prog);
    printf("  %s " C_YELLOW "write <segment> <message|file> [--enc]" C_RESET "  - Write to segment\n", prog);
    printf("  %s " C_YELLOW "read <segment> [outfile] [--dec]" C_RESET "     - Read data\n", prog);
    printf("  %s " C_YELLOW "destroy <segment>" C_RESET "                   - Destroy a segment\n", prog);
    printf("\n");
    printf("  %s " C_YELLOW "authorize <segment> <pid>" C_RESET "           - Grant PID access\n", prog);
    printf("  %s " C_YELLOW "unauthorize <segment> <pid>" C_RESET "         - Revoke PID access\n", prog);
    printf("  %s " C_YELLOW "ping" C_RESET "                            - Check daemon socket responsiveness\n", prog);
    printf("  %s " C_YELLOW "shutdown" C_RESET "                        - Ask daemon to exit (socket protocol)\n", prog);
    printf("  %s " C_YELLOW "info <segment>" C_RESET "                   - Print segment header information\n", prog);
    printf("  %s " C_YELLOW "audit [count]" C_RESET "                      - View audit log\n", prog);
    printf("  %s " C_YELLOW "debug <on|off|status>" C_RESET "              - Toggle global debug logging\n", prog);
    printf("\nOptions:\n");
    printf("  " C_YELLOW "--debug" C_RESET "      Enable verbose logging\n");
    printf("  " C_YELLOW "--json" C_RESET "       Output audit log in raw JSON (for 'audit' cmd)\n");
    printf("  " C_YELLOW "--help" C_RESET "       Show this help text\n\n");
}

static int cmd_debug_toggle(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, C_RED "[ERROR]" C_RESET " debug requires: on|off|status\n");
        return 1;
    }

    const char *arg = argv[2];
    if (!strcmp(arg, "status")) {
        printf("debug=%s (flag=%s)\n", sshm_is_debug_enabled() ? "on" : "off", sshm_get_debug_flag_file());
        return 0;
    }
    if (!strcmp(arg, "on")) {
        if (sshm_set_debug_enabled(1) != 0) {
            sshm_error("[cli]", "Failed to enable debug flag at %s: %s", sshm_get_debug_flag_file(), strerror(errno));
            fprintf(stderr, C_RED "[ERROR]" C_RESET " Failed to enable debug.\n");
            return 1;
        }
        printf(C_GREEN "[OK]" C_RESET " Debug enabled (global).\n");
        return 0;
    }
    if (!strcmp(arg, "off")) {
        if (sshm_set_debug_enabled(0) != 0) {
            sshm_error("[cli]", "Failed to disable debug flag at %s: %s", sshm_get_debug_flag_file(), strerror(errno));
            fprintf(stderr, C_RED "[ERROR]" C_RESET " Failed to disable debug.\n");
            return 1;
        }
        printf(C_GREEN "[OK]" C_RESET " Debug disabled (global).\n");
        return 0;
    }

    fprintf(stderr, C_RED "[ERROR]" C_RESET " Unknown debug option: %s\n", arg);
    return 1;
}

// Daemon commands (systemd wrappers)

static int run_cmd(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        sshm_error("[cli]", "fork failed: %s", strerror(errno));
        return 1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        fprintf(stderr, C_RED "[ERROR]" C_RESET " execvp(%s) failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno == EINTR) continue;
        sshm_error("[cli]", "waitpid failed: %s", strerror(errno));
        return 1;
    }

    if (WIFEXITED(st)) return (WEXITSTATUS(st) == 0) ? 0 : 1;
    return 1;
}

static int run_systemctl(const char *verb, int use_sudo) {
    if (!verb || !verb[0]) return 1;
    char *argv_sudo[] = { (char*)"sudo", (char*)"systemctl", (char*)verb, (char*)"sshmd.service", NULL };
    char *argv_plain[] = { (char*)"systemctl", (char*)verb, (char*)"sshmd.service", NULL };
    return run_cmd(use_sudo ? argv_sudo : argv_plain);
}

static int cmd_start_daemon(void){
    sshm_debug("[cli]", "start-daemon requested");
    sshm_info("[cli]", "Attempting to start daemon via systemd...");
    int ret = run_systemctl("start", (geteuid() != 0));
    if (ret == 0) {
        printf(C_GREEN "[OK]" C_RESET " Daemon start request sent.\n");
    } else {
        sshm_error("[cli]", "systemctl start failed");
        fprintf(stderr, C_RED "[ERROR]" C_RESET " Failed to start daemon.\n");
    }
    return ret;
}

static int cmd_shutdown_daemon(void){
    sshm_debug("[cli]", "shutdown-daemon requested");
    sshm_info("[cli]", "Attempting to stop daemon via systemd...");
    int ret = run_systemctl("stop", (geteuid() != 0));
    if (ret == 0) {
        printf(C_GREEN "[OK]" C_RESET " Daemon stop request sent.\n");
    } else {
        sshm_error("[cli]", "systemctl stop failed");
        fprintf(stderr, C_RED "[ERROR]" C_RESET " Failed to stop daemon.\n");
    }
    return ret;
}

static int cmd_restart_daemon(void) {
    sshm_debug("[cli]", "restart-daemon requested");
    sshm_info("[cli]", "Attempting to restart daemon via systemd...");
    int ret = run_systemctl("restart", (geteuid() != 0));
    if (ret == 0) {
        printf(C_GREEN "[OK]" C_RESET " Daemon restart request sent.\n");
    } else {
        sshm_error("[cli]", "systemctl restart failed");
        fprintf(stderr, C_RED "[ERROR]" C_RESET " Failed to restart daemon.\n");
    }
    return ret;
}

static int cmd_status_daemon(void) {
    sshm_debug("[cli]", "status-daemon requested");
    return run_systemctl("status", 0);
}


// Main
int main(int argc, char **argv){
    if (argc < 2){ print_help(argv[0]); return 1; }

    /* parse global flags first */
    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i],"--debug")) {
            DEBUG_MODE = 1;
            setenv("SSHM_DEBUG", "1", 1);
        }
        if (!strcmp(argv[i],"--json")) JSON_OUTPUT = 1;
        if (!strcmp(argv[i],"--help")) { print_help(argv[0]); return 0; }
    }

    const char *sub = argv[1];
    sshm_debug("[cli]", "Command = %s", sub);

    // Daemon commands (no sshm_init needed).
    if (!strcmp(sub,"start-daemon")){
        return cmd_start_daemon();
    } else if (!strcmp(sub,"shutdown-daemon")){
        return cmd_shutdown_daemon();
    } else if (!strcmp(sub,"restart-daemon")){
        return cmd_restart_daemon();
    } else if (!strcmp(sub,"status-daemon")){
        return cmd_status_daemon();
    } else if (!strcmp(sub,"audit")){
        int count = (argc >= 3) ? atoi(argv[2]) : 0;
        sshm_info("[cli]", "Command=audit count=%d json=%d", count, JSON_OUTPUT);
        return show_audit_log(count, JSON_OUTPUT);
    } else if (!strcmp(sub, "debug")) {
        return cmd_debug_toggle(argc, argv);
    }

    if (!strcmp(sub, "ping")) {
        return cmd_ping();
    } else if (!strcmp(sub, "shutdown")) {
        return cmd_shutdown_socket();
    } else if (!strcmp(sub, "info")) {
        if (argc < 3) { print_help(argv[0]); return 1; }
        return cmd_info(argv[2]);
    }

    // All other commands (require running daemon).
    if (sshm_init() != 0) {
        sshm_error("[cli]", "Failed to initialize SSHM library: %s", sshm_last_error());
        fprintf(stderr, C_RED "[FATAL]" C_RESET " SSHM initialization failed. Is the daemon running?\n");
        fprintf(stderr, " -> Try running: " C_YELLOW "sudo ./sshmctl start-daemon\n" C_RESET);
        return 1;
    }

    if (!strcmp(sub,"create")){
        if (argc < 4){ print_help(argv[0]); return 1; }
        const char *name = argv[2];
        size_t size = (size_t)strtoull(argv[3], NULL, 10);
        
        /* Parse flags. */
        int enc = 0;
        int mode = SSHM_MODE_OVERWRITE; // Default
        for (int i = 4; i < argc; i++) {
            if (!strcmp(argv[i], "--enc")) enc = 1;
            if (!strcmp(argv[i], "--append")) mode = SSHM_MODE_APPEND;
        }
        
        sshm_debug("[cli]", "Creating segment '%s' (size=%zu, encrypted=%d, mode=%d)", name, size, enc, mode);
        
        if (sshm_create(name, size, enc, mode)==0){
            sshm_info("[cli]", "Command=create name=\"%s\" result=OK", name);
            printf(C_GREEN "[OK]" C_RESET " Created segment '%s' (%s, %s)\n", 
                   name, 
                   enc ? "encrypted" : "plain", 
                   mode == SSHM_MODE_APPEND ? "append" : "overwrite");
            return 0;
        } else {
            sshm_error("[cli]", "Command=create name=\"%s\" result=ERR", name);
            fprintf(stderr, C_RED "[DENY]" C_RESET " Failed to create segment '%s': %s\n", name, sshm_last_error());
            return 1;
        }

    } else if (!strcmp(sub,"write")){
        if (argc < 4){ print_help(argv[0]); return 1; }
        const char *seg = argv[2], *src = argv[3];
        int enc = 0;
        if (argc >= 5 && !strcmp(argv[4],"--enc")) enc = 1;

        sshm_debug("[cli]", "Writing to segment '%s' (enc=%d)", seg, enc);
        char *data=NULL; size_t len=0;
        int isfile = file_exists(src);
        if (isfile){
            FILE *f=fopen(src,"rb"); if(!f){ perror("fopen"); return 1; }
            fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
            if (sz < 0) { perror("ftell"); fclose(f); return 1; }
            data = (char*)malloc((size_t)sz); if(!data){ fclose(f); return 1; }
            if (fread(data,1,(size_t)sz,f) != (size_t)sz) {
                sshm_error("[cli]", "Failed to read full file %s", src);
                fclose(f); free(data); return 1;
            }
            fclose(f); len=(size_t)sz;
        } else {
            data = (char*)src; len = strlen(src);
        }
        
        ssize_t w = sshm_write(seg, data, len, enc);
        if (isfile) free(data);
        
        if (w >= 0) {
            sshm_info("[cli]", "Command=write name=\"%s\" result=OK", seg);
            printf(C_GREEN "[OK]" C_RESET " Wrote %zd bytes%s\n", w, enc?" (encrypted)":"");
        } else {
            sshm_error("[cli]", "Command=write name=\"%s\" result=ERR", seg);
            fprintf(stderr, C_RED "[DENY]" C_RESET " Write failed on '%s': %s\n", seg, sshm_last_error());
        }
        return (w>=0)?0:1;

    } else if (!strcmp(sub,"read")){
        if (argc < 3){ print_help(argv[0]); return 1; }
        const char *seg = argv[2];
        const char *outfile = (argc>=4 && strcmp(argv[3],"--dec")!=0) ? argv[3] : NULL;
        int dec = ((argc>=4 && !strcmp(argv[3],"--dec")) || (argc>=5 && !strcmp(argv[4],"--dec")));
        
        sshm_debug("[cli]", "Reading segment '%s' (decrypt=%d)", seg, dec);
        size_t buflen = 1<<20; /* 1MB buffer */
        void *buf = malloc(buflen); if(!buf) return 1;
        
        ssize_t r = sshm_read(seg, buf, buflen, dec);
        
        if (r < 0){
            sshm_error("[cli]", "Command=read name=\"%s\" result=ERR", seg);
            free(buf);
            fprintf(stderr, C_RED "[DENY]" C_RESET " Read failed on '%s': %s\n", seg, sshm_last_error());
            return 1;
        }
        
        if (outfile){
            FILE *f=fopen(outfile,"wb"); if(!f){ perror("fopen"); free(buf); return 1; }
            fwrite(buf,1,(size_t)r,f); fclose(f);
            sshm_info("[cli]", "Command=read name=\"%s\" result=OK", seg);
            printf(C_GREEN "[OK]" C_RESET " Read %zd bytes -> %s%s\n", r, outfile, dec?" (decrypted)":"");
        } else {
            sshm_info("[cli]", "Command=read name=\"%s\" result=OK", seg);
            fwrite(buf,1,(size_t)r, stdout);
            if (r>0 && ((char*)buf)[r-1] != '\n') fputc('\n', stdout);
        }
        free(buf);
        return 0;

    } else if (!strcmp(sub, "destroy")) {
        if (argc < 3) { print_help(argv[0]); return 1; }
        const char *name = argv[2];
        sshm_debug("[cli]", "Destroying segment '%s'", name);
        if (sshm_destroy(name) == 0) {
            sshm_info("[cli]", "Command=destroy name=\"%s\" result=OK", name);
            printf(C_GREEN "[OK]" C_RESET " Segment '%s' destroyed.\n", name);
        } else {
            sshm_error("[cli]", "Command=destroy name=\"%s\" result=ERR", name);
            fprintf(stderr, C_RED "[DENY]" C_RESET " Failed to destroy segment '%s': %s\n", name, sshm_last_error());
        }
        return 0;

    } else if (!strcmp(sub,"authorize")){
        if (argc < 4){ print_help(argv[0]); return 1; }
        char line[256]; snprintf(line, sizeof line, "AUTHORIZE %s %s", argv[2], argv[3]);
        return send_line_cmd(line);

    } else if (!strcmp(sub,"unauthorize")){
        if (argc < 4){ print_help(argv[0]); return 1; }
        char line[256]; snprintf(line, sizeof line, "REVOKE %s %s", argv[2], argv[3]);
        return send_line_cmd(line);
    }

    sshm_error("[cli]", "Unknown command: %s", sub);
    print_help(argv[0]);
    return 1;
}