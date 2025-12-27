# SSHM — Full User Guide

This guide documents **everything currently implemented** in this repository:

- `libsshm` (C library)
- `sshmd` (local daemon)
- `sshmctl` (CLI)
- daemon socket protocol
- configuration (env vars), logging, audit, and troubleshooting

If you are new, read this in order:

1. **Install / build**
2. **Run the daemon** (dev mode or systemd)
3. **Use `sshmctl`** (plaintext first, then encryption)
4. **Embed `libsshm` in your C program**

---

## 1) What is SSHM?

SSHM is a small toolkit for local (same-host) IPC using POSIX shared memory.

### Components

- **`libsshm`**: creates/uses POSIX shared memory segments and reads/writes frames.
- **`sshmd`**: stores per-segment encryption keys and enforces authorization for key retrieval.
- **`sshmctl`**: convenience CLI for segment operations and daemon control.

### When do you need the daemon?

- **Plaintext segments**: work without the daemon.
- **Encrypted segments**: require the daemon to:
  - `REGISTER` a per-segment key (when creating the segment)
  - `FETCH` the key (when encrypting/decrypting)

---

## 2) Concepts and data model

### Segment names

A segment name like `demo` maps to a POSIX shm object (typically) under `/dev/shm` as something like:

- `/dev/shm/sshm_demo`

If you reuse a name and a previous run left it behind, you may see `exists` errors; destroy it or choose a new name.

### Frames (payload format)

The payload uses a simple frame format (see `docs/DESIGN.md` for details):

- `[type:1][len_be:4][payload...]`
- `type=0`: plaintext
- `type=1`: encrypted payload (nonce + ciphertext+tag)

### Write modes

- **overwrite**: replaces the segment content.
- **append**: appends frames to the segment.

In the CLI:

- overwrite is default
- append is enabled with `--append`

### Encryption model (libsodium)

- Uses AEAD: **XChaCha20-Poly1305**
- Each write uses a fresh nonce
- Reads verify the authentication tag before decrypting

Important:

- The daemon must not log key material.
- Audit logs record actions/outcomes, not secrets.

---

## 2.5) Real-life example (end-to-end)

Here’s a realistic same-host IPC pattern you can build with SSHM:

- A long-running **producer** process (C program) publishes status/telemetry into a shared-memory segment.
- One or more **consumers** (another C program, or `sshmctl`) read the latest stable value with low latency.

### Example: “system agent” publishes status

1) Producer writes updates (plaintext) into a segment `agent_status`.
2) Consumer reads it in a loop and prints it.
3) If you need multi-user privacy, switch to encryption (`--enc` / encrypt=1), and run `sshmd`.

You can run this today using the included examples:

- Plaintext writer: `examples/demo_plain_writer.c`
- Plaintext reader: `examples/demo_plain_reader.c`
- Encrypted demo: `examples/demo_encrypted.c`

Build/run steps are in `examples/README.md`.

---

## 3) Install and build

### Prerequisites

You need:

- `gcc`, `make`
- libsodium development headers:
  - Debian/Ubuntu: `libsodium-dev`
  - Fedora: `libsodium-devel`

Optional but recommended:

- `pkg-config`
- `systemd` (if you want the daemon as a service)

### Build from source

```bash
make
```

### Run tests

```bash
make test
```

### Install system-wide

```bash
sudo make install
sudo ldconfig
```

Verify from `pkg-config`:

```bash
pkg-config --cflags --libs sshm
```

### Convenience scripts

Systemd install (recommended for “real” use):

```bash
bash scripts/install.sh --systemd
sshmctl ping
```

Uninstall:

```bash
bash scripts/uninstall.sh
```

---

## 4) Running the daemon

You have two good modes.

### Mode A: Development (no sudo)

Use user-writable locations for socket and logs:

```bash
export SSHM_SOCKET_PATH="/tmp/sshm.sock"
export SSHM_AUDIT_DIR="/tmp/sshm-log"
export SSHM_AUDIT_FILE="/tmp/sshm-log/audit.log"
export SSHM_RUNTIME_LOG="/tmp/sshm-log/sshm.log"
mkdir -p "$SSHM_AUDIT_DIR"

./build/bin/sshmd &
./build/bin/sshmctl ping
```

### Mode B: System install (systemd)

If installed via the systemd scripts, the defaults are:

- socket: `/run/sshm/sshm_daemon.sock`
- logs: `/var/log/sshm/sshm.log`
- audit: `/var/log/sshm/audit.log`

The systemd unit also sets `SSHM_SOCKET_MODE` so non-root users can connect.

---

## 5) Using the CLI (`sshmctl`)

Tip: if you built locally, use `./build/bin/sshmctl`. If you installed, use `sshmctl`.

### Global flags

- `--debug` enables extra CLI debug output
- `--json` makes `audit` print raw JSON-lines
- `--help` prints usage

### Segment operations

Create:

```bash
sshmctl create <name> <size> [--enc] [--append]
```

Write (string or file path):

```bash
sshmctl write <name> <message|file> [--enc]
```

Read:

```bash
sshmctl read <name> [outfile] [--dec]
```

Destroy:

```bash
sshmctl destroy <name>
```

Inspect header:

```bash
sshmctl info <name>
```

### Daemon socket operations

Health check:

```bash
sshmctl ping
```

Ask daemon to exit (socket protocol):

```bash
sshmctl shutdown
```

### Access control (for encrypted segments)

Grant a PID access:

```bash
sshmctl authorize <segment> <pid>
```

Revoke a PID:

```bash
sshmctl unauthorize <segment> <pid>
```

Notes:

- The daemon uses `SO_PEERCRED` to identify the caller.
- `authorize` enforces that the target PID exists and belongs to the same UID as the segment owner.

### Audit and debug

Audit (last N entries):

```bash
sshmctl audit 10
```

Raw JSON:

```bash
sshmctl audit 10 --json
```

Debug toggle (global):

```bash
sshmctl debug on
sshmctl debug status
sshmctl debug off
```

---

## 6) End-to-end examples

### Plaintext example

```bash
sshmctl create demo 4096
sshmctl write demo "hello"
sshmctl read demo
sshmctl destroy demo
```

### Encrypted example

```bash
sshmctl create secret 4096 --enc --append

# Must use --enc for encrypted segments
sshmctl write secret "top-secret" --enc

# Must use --dec to decrypt reads
sshmctl read secret --dec

sshmctl destroy secret
```

---

## 7) Using the C library (`libsshm`) in your program

Yes — you can include and link this as a normal C library.

### Public header

Use:

- `#include "sshm.h"`

### Build/link (installed)

```bash
gcc -o myapp myapp.c $(pkg-config --cflags --libs sshm)
```

### Build/link (from the repo, without install)

```bash
make
export LD_LIBRARY_PATH="$PWD/build/lib:${LD_LIBRARY_PATH:-}"

gcc -Iinclude -Lbuild/lib -Wl,-rpath,"$PWD/build/lib" \
  -o myapp myapp.c -lsshm -lsodium -lpthread
```

### Minimal example

See `examples/demo_create.c` and `examples/README.md`.

The public API (from `include/sshm.h`) is:

- `sshm_init()`, `sshm_shutdown()`
- `sshm_create(name, size, encrypted, mode)`
- `sshm_write(name, buf, len, encrypt)`
- `sshm_read(name, buf, buflen, decrypt)`
- `sshm_destroy(name)`
- `sshm_last_error()`

### What each API does (practical reference)

- `sshm_init()`
  - Must be called once per process before using other APIs.
  - Returns `0` on success, `-1` on failure.

- `sshm_create(name, size, encrypted, mode)`
  - Creates a new segment.
  - If the segment already exists, it opens it and validates:
    - encryption flag matches
    - append vs overwrite mode matches
  - `encrypted=1` requires `sshmd` running (the library will talk to the daemon).
  - `mode`:
    - `SSHM_MODE_OVERWRITE`
    - `SSHM_MODE_APPEND`

- `sshm_write(name, buf, len, encrypt)`
  - Writes bytes into the segment.
  - `encrypt=1` encrypts the payload first (requires `sshmd` for key fetch).
  - Returns bytes written, or `-1` on error.

- `sshm_read(name, buf, buflen, decrypt)`
  - Reads the latest stable bytes from the segment.
  - `decrypt=1` verifies+decrypts (requires `sshmd` for key fetch).
  - Returns bytes read, or `-1` on error.
  - Tip: allocate `buflen` large enough for your expected payload(s), especially in append mode.

- `sshm_destroy(name)`
  - Removes the segment and asks the daemon to forget the key.
  - Returns `0` on success, `-1` on failure.

- `sshm_shutdown()`
  - Cleans up process-local library state.

### Minimal multi-process pattern

- One process:
  - `sshm_create(..., SSHM_MODE_APPEND)`
  - `sshm_write()` periodically

- Another process:
  - `sshm_read()` periodically

See the runnable programs in `examples/`:

- `examples/demo_plain_writer.c`
- `examples/demo_plain_reader.c`

Notes:

- `sshm_open()` / `sshm_close()` are currently no-ops (the library opens/closes per operation).
- For encrypted operations, ensure `sshmd` is running and `SSHM_SOCKET_PATH` matches.

### Error handling

Most APIs return `-1` on error. Get a readable message with:

- `sshm_last_error()`

---

## 8) Daemon protocol (wire format)

The daemon speaks a simple line protocol over a UNIX domain socket.

- Each request is a single line terminated by `\n`.
- The daemon replies with `OK ...` or `ERR ...`.

Commands:

- `PING` → `OK PONG`
- `REGISTER <name>` → `OK` or `ERR <reason>`
- `FETCH <name>` → `OK <hexkey>` or `ERR <reason>`
- `AUTHORIZE <name> <pid>` → `OK` or `ERR <reason>`
- `REVOKE <name> <pid>` → `OK` or `ERR <reason>`
- `REMOVE <name>` → `OK` or `ERR <reason>`
- `SHUTDOWN` → `OK` or `ERR <reason>`

Full details: see `docs/PROTOCOL.md`.

---

## 9) Configuration (environment variables)

All important runtime paths can be overridden with env vars (useful for dev and CI):

- `SSHM_SOCKET_PATH`
  - daemon socket path
- `SSHM_SOCKET_MODE`
  - octal mode like `0666` (used by the daemon after `bind()`)
- `SSHM_AUDIT_DIR`
  - directory containing audit logs
- `SSHM_AUDIT_FILE`
  - JSON-lines audit log file
- `SSHM_RUNTIME_LOG`
  - human-readable runtime log
- `SSHM_STATE_DIR`
  - directory for global toggles (e.g., debug flag file)
- `SSHM_DEBUG=1`
  - per-process debug enable

---

## 10) Troubleshooting

### `sshmctl ping` fails

- Make sure `sshmd` is running.
- Ensure `SSHM_SOCKET_PATH` matches between daemon and client.

### `sshmctl audit` fails

- Systemd installs write to `/var/log/sshm/audit.log`.
- Dev installs should set `SSHM_AUDIT_FILE` to a user-writable file.

### Encrypted reads/writes fail

- Create the segment with `--enc`.
- Write with `--enc`.
- Read with `--dec`.
- Ensure the daemon authorizes your process to fetch the key.

### “exists” errors

A previous run may have left `/dev/shm/sshm_<name>` behind.

- Use `sshmctl destroy <name>`
- Or choose a new name.

---

## 11) References

- Usage summary: `docs/USAGE.md`
- Protocol: `docs/PROTOCOL.md`
- Design: `docs/DESIGN.md`
- Security model: `docs/SECURITY.md`
- Examples: `examples/README.md`
