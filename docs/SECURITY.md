# Security Model

This project is designed for local, same-host IPC. It assumes the kernel and the host OS are trusted.

## Threat model (in-scope)

- Prevent accidental disclosure of shared-memory payloads to other local users.
- Detect tampering/corruption of payloads (and reject reads if integrity checks fail).
- Prevent simple authorization bypasses (e.g., PID reuse, spoofed PID/UID in client requests).

## Threat model (out-of-scope)

- If an authorized process is compromised, its memory (including decrypted data and keys) can be stolen.
- Side channels such as timing/access-pattern leakage are not mitigated.
- A malicious root user can always read/write process memory and shared memory.

## Encryption model

- Encrypted segments use libsodium AEAD (XChaCha20-Poly1305).
- Each write uses a fresh nonce and produces ciphertext + authentication tag.
- Reads verify the tag before decrypting. Tampering causes read/decrypt failure.

Notes:

- Encryption protects the payload content. Segment metadata (name/size/access pattern) may still leak information.
- Keys are per-segment and should be treated as secrets.

## Integrity model

- Each segment has a header with a version counter and CRC.
- Writers update the payload and header; readers use version fencing and checksum verification to detect torn writes/corruption.

## Daemon model (sshmd)

- The daemon stores per-segment keys and enforces authorization.
- Client identity is kernel-attested via `SO_PEERCRED` on the UNIX domain socket.
- The daemon must not log key material. Audit logs record actions and outcomes, not secrets.

## CLI model (sshmctl)

- `sshmctl` is a convenience client for daemon operations and common segment workflows.
- Default output is user-friendly status/errors. Debug output is gated behind explicit enablement.

## Operational recommendations

- Restrict daemon socket permissions so only intended users/groups can connect.
- Run the daemon as a dedicated user/group when possible.
- Keep debug disabled in production.
