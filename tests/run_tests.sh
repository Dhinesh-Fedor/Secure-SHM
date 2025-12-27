#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Ensure binaries can find libsshm.so without install
export LD_LIBRARY_PATH="$ROOT_DIR/build/lib:${LD_LIBRARY_PATH:-}"

_tmp="$(mktemp -d)"
cleanup() {
  set +e
  if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$_tmp"
}
trap cleanup EXIT

export SSHM_SOCKET_PATH="$_tmp/sshm.sock"
export SSHM_AUDIT_DIR="$_tmp/log"
export SSHM_AUDIT_FILE="$_tmp/log/audit.log"
export SSHM_RUNTIME_LOG="$_tmp/log/sshm.log"

mkdir -p "$_tmp/log"

# Start daemon
"$ROOT_DIR/build/bin/sshmd" &
DAEMON_PID=$!

# Wait for socket
for _ in {1..100}; do
  [[ -S "$SSHM_SOCKET_PATH" ]] && break
  sleep 0.05
done
if [[ ! -S "$SSHM_SOCKET_PATH" ]]; then
  echo "[FAIL] daemon socket not created: $SSHM_SOCKET_PATH" >&2
  exit 1
fi

pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

# Segment names map to /dev/shm objects. If a previous run crashed mid-test,
# the name may still exist. Use per-run unique names to keep tests reliable.
RUN_ID="${$}_${RANDOM}"

# --- Sanity: daemon socket responds ---
ping_out="$($ROOT_DIR/build/bin/sshmctl ping 2>/dev/null || true)"
[[ "$ping_out" == *"OK"* ]] || fail "ping failed (got: $ping_out)"
pass "daemon ping"

# --- Sanity: daemon protocol edge cases ---
gcc -Wall -Wextra -O2 -g -Iinclude -L"$ROOT_DIR/build/lib" -Wl,-rpath,"$ROOT_DIR/build/lib" \
  -o "$_tmp/test_daemon_protocol_edges" "$ROOT_DIR/tests/test_daemon_protocol_edges.c" -lsshm -lsodium -lpthread \
  >/dev/null 2>&1 || fail "build daemon protocol edges test"

"$_tmp/test_daemon_protocol_edges" >/dev/null 2>&1 || fail "run daemon protocol edges test"
pass "daemon protocol edges"

# --- Test 1: plaintext segment read/write ---
seg_plain="plain_seg_${RUN_ID}"
"$ROOT_DIR/build/bin/sshmctl" create "$seg_plain" 4096 >/dev/null || fail "create plaintext"
"$ROOT_DIR/build/bin/sshmctl" write "$seg_plain" "hello" >/dev/null || fail "write plaintext"
out="$($ROOT_DIR/build/bin/sshmctl read "$seg_plain" 2>/dev/null || true)"
[[ "$out" == *"hello"* ]] || fail "read plaintext (got: $out)"
"$ROOT_DIR/build/bin/sshmctl" destroy "$seg_plain" >/dev/null || fail "destroy plaintext"
pass "plaintext create/write/read/destroy"

# --- Test 2: encrypted segment requires encryption on write ---
seg_enc="enc_seg_${RUN_ID}"
"$ROOT_DIR/build/bin/sshmctl" create "$seg_enc" 4096 --enc --append >/dev/null || fail "create encrypted"

# This must fail now (plaintext write into encrypted segment)
if "$ROOT_DIR/build/bin/sshmctl" write "$seg_enc" "oops" >/dev/null 2>&1; then
  fail "unencrypted write to encrypted segment should fail"
fi

"$ROOT_DIR/build/bin/sshmctl" write "$seg_enc" "secret" --enc >/dev/null || fail "encrypted write"
out2="$($ROOT_DIR/build/bin/sshmctl read "$seg_enc" --dec 2>/dev/null || true)"
[[ "$out2" == *"secret"* ]] || fail "decrypt read (got: $out2)"
"$ROOT_DIR/build/bin/sshmctl" destroy "$seg_enc" >/dev/null || fail "destroy encrypted"
pass "encrypted enforcement + decrypt read"

# --- Test 3: audit log should never contain key material ---
if [[ -f "$SSHM_AUDIT_FILE" ]] && grep -q '"key"\s*:' "$SSHM_AUDIT_FILE"; then
  fail "audit log contains key material"
fi
pass "audit log does not store keys"

# --- Test 3b: AUTHORIZE should reject non-existent PID ---
seg_auth="auth_seg_${RUN_ID}"
"$ROOT_DIR/build/bin/sshmctl" create "$seg_auth" 4096 >/dev/null || fail "create auth seg"

bogus_pid=999999
while kill -0 "$bogus_pid" 2>/dev/null; do bogus_pid=$((bogus_pid+1)); done
if "$ROOT_DIR/build/bin/sshmctl" authorize "$seg_auth" "$bogus_pid" >/dev/null 2>&1; then
  fail "authorize should fail for non-existent pid ($bogus_pid)"
fi

"$ROOT_DIR/build/bin/sshmctl" destroy "$seg_auth" >/dev/null || true
pass "authorize rejects non-existent pid"

# --- Test 3c: audit JSON escaping ---
gcc -Wall -Wextra -O2 -g -Iinclude -L"$ROOT_DIR/build/lib" -Wl,-rpath,"$ROOT_DIR/build/lib" \
  -o "$_tmp/audit_escape_test" "$ROOT_DIR/tests/audit_escape_test.c" -lsshm -lsodium -lpthread \
  >/dev/null 2>&1 || fail "build audit escape test"

"$_tmp/audit_escape_test" >/dev/null 2>&1 || fail "run audit escape test"

# Ensure the reason value was escaped (no raw quotes/newlines/tabs inside the JSON string).
# We expect JSON escapes: \" for quotes, \n for newline, \t for tab.
grep -Fq 'bad\"reason\nline\tend' "$SSHM_AUDIT_FILE" || fail "audit JSON escaping missing"
pass "audit JSON escaping"

# --- Test 4: checksum/integrity detection ---
seg_int="int_seg_${RUN_ID}"
"$ROOT_DIR/build/bin/sshmctl" create "$seg_int" 4096 >/dev/null || fail "create integrity"
"$ROOT_DIR/build/bin/sshmctl" write "$seg_int" "integrity" >/dev/null || fail "write integrity"

shm_path="/dev/shm/sshm_${seg_int}"
if [[ ! -e "$shm_path" ]]; then
  # Some systems mount shm differently; fail explicitly so we notice.
  fail "expected shm backing file not found at $shm_path"
fi

# Corrupt one byte within the active frame so checksum verification triggers.
# Layout (Linux): /dev/shm/sshm_<name> is the shm object backing file.
# Header is a packed struct (~36 bytes); payload starts right after. Our frame is small,
# so corrupt near the beginning of the payload.
printf '\xFF' | dd of="$shm_path" bs=1 seek=42 conv=notrunc status=none || fail "corrupt shm"

if "$ROOT_DIR/build/bin/sshmctl" read "$seg_int" >/dev/null 2>&1; then
  fail "read should fail after corruption"
fi

"$ROOT_DIR/build/bin/sshmctl" destroy "$seg_int" >/dev/null || true
pass "integrity check triggers on corruption"

echo "All tests passed."
