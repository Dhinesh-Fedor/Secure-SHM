# Daemon Protocol (sshmd)

The daemon listens on a UNIX domain socket (`SSHM_SOCKET_PATH`) and speaks a simple line-based protocol.

Each request is a single line terminated by `\n`.

The daemon applies per-connection timeouts and rejects overly long request lines.

## Commands

- `PING` → `OK PONG`
- `REGISTER <name>` → `OK` or `ERR <reason>`
- `FETCH <name>` → `OK <hexkey>` or `ERR <reason>`
- `AUTHORIZE <name> <pid>` → `OK` or `ERR <reason>`
- `REVOKE <name> <pid>` → `OK` or `ERR <reason>`
- `REMOVE <name>` → `OK` or `ERR <reason>`
- `SHUTDOWN` → `OK` or `ERR <reason>`

### Error responses

The daemon returns `ERR <token>` where `<token>` is a short reason. Common ones:

- `ERR args` (missing arguments)
- `ERR name` (invalid segment name)
- `ERR toolong` (request line too long)
- `ERR deny` / `ERR perm` (authorization failure)
- `ERR exists` (already registered)
- `ERR full` (daemon keystore full)

`sshmctl` provides convenience commands for these socket-level operations:

- `sshmctl ping`
- `sshmctl shutdown`

## Notes

- Caller identity is not taken from the request line. The daemon uses kernel-attested peer credentials (`SO_PEERCRED`) from the UNIX socket to get the caller PID/UID/GID.
- `AUTHORIZE`/`REVOKE` take a target PID. The daemon enforces that the target PID exists and belongs to the same UID as the segment owner.
- `FETCH` returns key material. It must never be logged.
- Authorization decisions are enforced by the daemon; clients still need OS-level isolation (UIDs/permissions) to be safe.
