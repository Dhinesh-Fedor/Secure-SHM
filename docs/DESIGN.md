# DESIGN — SSHM Toolkit (v1.0)

See top-level README. Key points:

- POSIX shm + mmap
- Named semaphores for synchronization
- Version fencing to avoid torn reads from writers
- Optional AEAD encryption with libsodium (XChaCha20-Poly1305)
- Per-segment header stores flags, version, payload_size, crc32

## High-level architecture

SSHM is split into three parts:

- `libsshm`: creates/opens shared memory segments and reads/writes data.
- `sshmd`: manages per-segment keys and enforces authorization for key retrieval.
- `sshmctl`: a convenience CLI that speaks the daemon protocol and calls `libsshm` APIs.

## Shared memory layout

Each segment is a POSIX shared memory object (typically backed by `/dev/shm`) with:

- A fixed header (flags, version, sizes, checksum)
- A payload area

The payload stores a simple frame format:

- `[type:1][len_be:4][payload...]`
- `type=0` means plaintext
- `type=1` means encrypted payload (nonce + ciphertext+tag)

If the segment is created with append mode, multiple frames can be appended.

## Synchronization

- A named POSIX semaphore provides exclusive writer mutual exclusion.
- Readers use version fencing: writers flip the header version odd/even around writes.
- Readers retry if they observe an in-progress write or a changing version.

Security:

- `sshmd` manages per-segment keys and enforces access control for key retrieval.
- Encrypted segments use AEAD: reads verify authenticity before decrypting.
- The library/daemon avoid writing key material to logs.

Fault tolerance:

- Writers update a version counter around payload writes; readers retry if they observe an in-progress write.
- Header versioning and CRC detect corruption
- WAL & advanced recovery omitted in this minimal implementation; recommended to add on top

## Logging and audit

- Runtime log is human-readable.
- Audit log is JSON-lines. String fields are JSON-escaped and writes are locked to avoid interleaving.
