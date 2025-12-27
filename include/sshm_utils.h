#pragma once
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h> /* pid_t, uid_t */
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SSHM_KEYBYTES
#define SSHM_KEYBYTES 32
#endif

/* timestamp helpers */
char *sshm_timestamp(char *buf, size_t n); /* returns local [HH:MM:SS] */

/*
 * Runtime-configurable paths.
 * Defaults are suitable for production, but can be overridden for tests/CI.
 *
 * Env vars:
 * - SSHM_SOCKET_PATH
 * - SSHM_AUDIT_DIR
 * - SSHM_AUDIT_FILE
 * - SSHM_RUNTIME_LOG
 * - SSHM_STATE_DIR (optional; used for global debug flag)
 * - SSHM_DEBUG (optional; per-process override)
 */
const char *sshm_get_socket_path(void);
const char *sshm_get_audit_dir(void);
const char *sshm_get_audit_file(void);
const char *sshm_get_runtime_log(void);

/* runtime state files (used for global toggles like debug) */
const char *sshm_get_state_dir(void);
const char *sshm_get_debug_flag_file(void);

/* logging controls */
int sshm_is_debug_enabled(void);
int sshm_set_debug_enabled(int enabled);

/* low-level log (used by macros) */
void _sshm_log(const char *level, const char *context, const char *fmt, ...);

/*
 * Unified logging macros.
 * Use context for subsystems, e.g., "[auth]", "[core]", "[cli]", "[daemon]"
 */
#define sshm_debug(ctx, fmt, ...) _sshm_log("DEBUG", ctx, fmt, ##__VA_ARGS__)
#define sshm_info(ctx, fmt, ...)  _sshm_log("INFO",  ctx, fmt, ##__VA_ARGS__)
#define sshm_warn(ctx, fmt, ...)  _sshm_log("WARN",  ctx, fmt, ##__VA_ARGS__)
#define sshm_error(ctx, fmt, ...) _sshm_log("ERROR", ctx, fmt, ##__VA_ARGS__)

/* structured event helpers */
/* Logs human-readable to runtime log AND JSON to audit log.
 * Note: key material is never written to logs. The key_hex parameter is
 * accepted for backward compatibility and is ignored.
 */
int sshm_log_event(const char *level, const char *context, pid_t pid, uid_t uid,
                   const char *action, const char *name,
                   const char *result, const char *reason, const char *key_hex);

/* Logs only a JSON event to the audit file.
 * Note: key material is never written to logs. The key_hex parameter is
 * accepted for backward compatibility and is ignored.
 */
int log_json_event(pid_t pid, uid_t uid, const char *action,
                   const char *name, const char *result, const char *reason, const char *key_hex);

/* daemon/cli utility helpers */
/* Return 1 if the daemon socket is responsive, else 0 */
int sshm_check_daemon_alive(void);
/*
int sshm_check_multiple_daemons(void);
int sshm_kill_all_daemons(int verbose);
int sshm_cleanup_stale_socket(int verbose);
int sshm_prompt_yes_no(const char *question);
*/

/* audit helpers */
void write_audit_log(const char *fmt, ...); /* DEPRECATED: Use log_json_event */
int show_audit_log(int count, int json_output);

/* secure */
void secure_zero(void *p, size_t n);

#ifdef __cplusplus
}
#endif