# SSHM Toolkit

SSHM is a small C toolkit for working with POSIX shared memory segments. It
ships with a daemon + CLI, optional libsodium encryption, and stable reads using
a version-fencing scheme. Each segment also uses a named semaphore for
write-side mutual exclusion.

Version: 1.0.0

## Overview

- Create/open/destroy shared memory segments.
- Write/read payloads (including append-style writes).
- Optional encryption/decryption via libsodium.
- Daemon to register segments and manage access.
- `sshmctl` for basic operations and daemon control.

## Quick start

### Option A: local development (no sudo)

Build:

```bash
make
```

Run the daemon using user-writable paths:

```bash
export SSHM_SOCKET_PATH="/tmp/sshm.sock"
export SSHM_AUDIT_DIR="/tmp/sshm-log"
export SSHM_AUDIT_FILE="/tmp/sshm-log/audit.log"
export SSHM_RUNTIME_LOG="/tmp/sshm-log/sshm.log"
mkdir -p "$SSHM_AUDIT_DIR"

./build/bin/sshmd &
```

Ping the daemon:

```bash
./build/bin/sshmctl ping
```

Create + write + read:

```bash
./build/bin/sshmctl create myseg 4096
./build/bin/sshmctl write myseg "hello"
./build/bin/sshmctl read myseg
./build/bin/sshmctl destroy myseg
```

### Option B: system install (systemd)

```bash
bash scripts/install.sh --systemd
sshmctl ping
```

## Logging

By default, SSHM stays quiet on stderr (warnings/errors only). Operational logs
go to `SSHM_RUNTIME_LOG`. Debug logs are off unless you explicitly enable them.

Enable debug globally:

```bash
./build/bin/sshmctl debug on
./build/bin/sshmctl debug status
./build/bin/sshmctl debug off
```

Per-process override (developer use):

```bash
SSHM_DEBUG=1 ./build/bin/sshmctl read demo
```

More detail (protocol, security model, etc.) is in the [docs](docs) directory.

## Docs

- Usage: docs/USAGE.md
- Full user guide: docs/GUIDE.md
- Protocol: docs/PROTOCOL.md
- Design notes: docs/DESIGN.md
- Security model: docs/SECURITY.md

## Encryption (optional)

If you create a segment with encryption enabled, write with `--enc` and read
with `--dec` (see [docs](docs) for full CLI usage and examples).

## Audit, logs, and paths

By default, the daemon writes logs under `/var/log/sshm` and listens on
`/run/sshm/sshm_daemon.sock`.

For local development and CI (no sudo), override paths:

```bash
export SSHM_SOCKET_PATH="/tmp/sshm.sock"
export SSHM_AUDIT_DIR="/tmp/sshm-log"
export SSHM_AUDIT_FILE="/tmp/sshm-log/audit.log"
export SSHM_RUNTIME_LOG="/tmp/sshm-log/sshm.log"
mkdir -p "$SSHM_AUDIT_DIR"
```

## Tests

```bash
make test
```

## Installation

### Clone

```bash
git clone https://github.com/Dhinesh-Fedor/Secure-SHM.git
cd Secure-SHM
```

### Install script (convenience)

This wraps the documented steps below (build + install + `ldconfig`). It does **not** install dependencies.

Make the helper scripts executable:

```bash
chmod +x scripts/install.sh scripts/uninstall.sh scripts/install-systemd.sh
```

```bash
bash scripts/install.sh
```

To install and set up the systemd service (creates `sshm` user, log dir, installs unit):

```bash
bash scripts/install.sh --systemd
sshmctl ping
```

Uninstall:

```bash
bash scripts/uninstall.sh
```

Uninstall systemd service too:

```bash
bash scripts/uninstall.sh --systemd
```

### Prerequisites

You need a C toolchain and libsodium.

- Build tools: `gcc`, `make`
- Crypto dependency: libsodium (runtime + development headers)
- Optional: `pkg-config` (for downstream builds), `systemd` (to run the daemon as a service)

Common distro installs:

- Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libsodium-dev pkg-config
```

- Fedora:

```bash
sudo dnf install -y gcc make libsodium-devel pkgconf-pkg-config
```

### Build from source

```bash
make
```

### Install to your system

Installs the library, headers, daemon, and CLI under `/usr/local` by default.

```bash
sudo make install
sudo ldconfig
```

Verify the library is discoverable:

```bash
pkg-config --cflags --libs sshm
```

### Run the daemon

#### Option A: systemd service (recommended)

This repo includes a helper script that:

- runs `make install` + `ldconfig`
- creates a dedicated `sshm` system user
- creates `/var/log/sshm` with safe permissions
- installs the systemd unit

```bash
sudo bash scripts/install-systemd.sh
sshmctl ping
```

#### Option B: run manually (development)

```bash
export SSHM_SOCKET_PATH="/tmp/sshm.sock"
export SSHM_AUDIT_DIR="/tmp/sshm-log"
export SSHM_AUDIT_FILE="/tmp/sshm-log/audit.log"
export SSHM_RUNTIME_LOG="/tmp/sshm-log/sshm.log"
mkdir -p "$SSHM_AUDIT_DIR"

sshmd &
sshmctl ping
```

### Quick sanity check after install

```bash
sshmctl create myseg 4096
sshmctl write myseg "hello"
sshmctl read myseg
sshmctl destroy myseg
```

## Troubleshooting

- `sshmctl ping` fails: ensure the daemon is running and the client and daemon agree on `SSHM_SOCKET_PATH`.
- `sshmctl audit` fails: on systemd installs the audit log is `/var/log/sshm/audit.log`. For dev runs, set `SSHM_AUDIT_FILE` to a user-writable path.
- `sshmctl` can’t load `libsshm.so`: after `make install`, run `sudo ldconfig` (the install scripts do this for you).

### Uninstall

```bash
sudo make uninstall
sudo ldconfig
```

If you installed the systemd unit, also remove it:

```bash
sudo systemctl disable --now sshmd || true
sudo rm -f /etc/systemd/system/sshmd.service
sudo systemctl daemon-reload
```
