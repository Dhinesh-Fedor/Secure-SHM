#!/usr/bin/env bash
set -euo pipefail
SSHM_DEBUG=${SSHM_DEBUG:-0}
echo "Starting sshmd (SSHM_DEBUG=$SSHM_DEBUG) ..."
./build/bin/sshmd &
echo $! > ./build/bin/sshmd.pid
echo "Daemon PID $(cat ./build/bin/sshmd.pid)"
