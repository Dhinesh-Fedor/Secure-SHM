#!/usr/bin/env bash
set -euo pipefail
LOG_DIR=${SSHM_AUDIT_DIR:-/var/log/sshm}
LOG=${SSHM_AUDIT_FILE:-$LOG_DIR/audit.log}
[ -f "$LOG" ] || { echo "No audit log at $LOG"; exit 0; }
TS=$(date +"%Y-%m-%dT%H:%M:%S")
mv "$LOG" "$LOG_DIR/audit-$TS.log"
touch "$LOG"
echo "Rotated audit log."
