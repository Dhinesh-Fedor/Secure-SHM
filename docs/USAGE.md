# SSHM Usage

For a complete end-to-end guide (installation, systemd vs dev mode, CLI reference, C integration, protocol, env vars, troubleshooting), see `docs/GUIDE.md`.

This project provides:

- `sshmd`: a local daemon that manages per-segment encryption keys and access checks.
- `libsshm`: a C library for creating and using shared memory segments.
- `sshmctl`: a CLI wrapper for common operations.

Security model and threat model notes are in docs/SECURITY.md.

## What `sshmctl` can do

Segment operations:

- `sshmctl create <name> <size> [--enc] [--append]`
- `sshmctl write <segment> <message|file> [--enc]`
- `sshmctl read <segment> [outfile] [--dec]`
- `sshmctl destroy <segment>`
- `sshmctl info <segment>`

Daemon socket operations:

- `sshmctl ping`
- `sshmctl shutdown`

Access control operations:

- `sshmctl authorize <segment> <pid>`
- `sshmctl unauthorize <segment> <pid>`

Logs and debugging:

- `sshmctl audit [count]` (add `--json` for raw JSON output)
- `sshmctl debug <on|off|status>`

systemd wrappers (optional):

- `sshmctl start-daemon`
- `sshmctl shutdown-daemon`
- `sshmctl restart-daemon`
- `sshmctl status-daemon`

## Quick start

Build:

```bash
make
```

Start the daemon (dev/test):

```bash
./build/bin/sshmd
```

Create and use a segment:

```bash
./build/bin/sshmctl create demo 4096
./build/bin/sshmctl write demo "hello"
./build/bin/sshmctl read demo
./build/bin/sshmctl destroy demo
```

Encrypted segment:

```bash
./build/bin/sshmctl create secret 4096 --enc --append
./build/bin/sshmctl write secret "top-secret" --enc
./build/bin/sshmctl read secret --dec
```

## Paths and environment variables

All runtime paths are configurable (useful for CI and non-root runs):

- `SSHM_SOCKET_PATH` (default comes from the build-time daemon setting)
- `SSHM_AUDIT_DIR` (default: `/var/log/sshm`)
- `SSHM_AUDIT_FILE` (default: `/var/log/sshm/audit.log`)
- `SSHM_RUNTIME_LOG` (default: `/var/log/sshm/sshm.log`)
- `SSHM_STATE_DIR` (optional; directory used for global runtime toggles such as debug)

Logging control:

- `SSHM_DEBUG=1` enables debug logs for the current process.

## Logging and debug

By default, the library/daemon only prints warnings and errors to stderr. Informational logs go to the runtime log file. Debug logs are disabled.

Enable debug globally using `sshmctl`:

```bash
./build/bin/sshmctl debug on
./build/bin/sshmctl debug status
./build/bin/sshmctl debug off
```

Daemon health check:

```bash
./build/bin/sshmctl ping
```

Ask the daemon to exit (socket protocol):

```bash
./build/bin/sshmctl shutdown
```

Inspect a segment header:

```bash
./build/bin/sshmctl info demo
```

Notes:

- Debug is also available per-process via `SSHM_DEBUG=1`.
- The global debug flag is a small file: `$(SSHM_STATE_DIR)/sshm.debug` (or a default derived from `SSHM_SOCKET_PATH`).

## Troubleshooting

- `sshmctl ping` fails: make sure `sshmd` is running and `SSHM_SOCKET_PATH` points to the same socket the daemon uses.
- `create` fails with `exists`: a shared memory object already exists at `/dev/shm/sshm_<name>`. Use a different name or `destroy` it.
- Encrypted reads fail: ensure the segment was created with `--enc` and the daemon authorizes your process to fetch the key.

## systemd

If installed with the provided service file, you can run:

```bash
sudo systemctl start sshmd.service
sudo systemctl status sshmd.service
```
