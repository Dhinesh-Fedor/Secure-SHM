#!/usr/bin/env bash
set -euo pipefail

is_root() {
  [[ "$(id -u)" -eq 0 ]]
}

ensure_sudo() {
  local why="$1"
  if is_root; then
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "error: this step requires root but sudo is not available: $why" >&2
    exit 1
  fi
  sudo -v
}

SUDO=()
if ! is_root; then
  SUDO=(sudo)
fi

run_ldconfig() {
  if command -v ldconfig >/dev/null 2>&1; then
    "${SUDO[@]}" ldconfig
    return 0
  fi
  if [[ -x /sbin/ldconfig ]]; then
    "${SUDO[@]}" /sbin/ldconfig
    return 0
  fi
  if [[ -x /usr/sbin/ldconfig ]]; then
    "${SUDO[@]}" /usr/sbin/ldconfig
    return 0
  fi
  return 1
}

ensure_linux_dynamic_linker_path() {
  local libdir="$1"
  if [[ "$(uname -s)" != "Linux" ]]; then
    return 0
  fi

  if compgen -G "/lib/ld-musl-*.so.1" >/dev/null; then
    local musl_path_file
    musl_path_file="$(ls -1 /etc/ld-musl-*.path 2>/dev/null | head -n 1 || true)"
    if [[ -n "$musl_path_file" ]]; then
      if ! grep -Fxq -- "$libdir" "$musl_path_file" 2>/dev/null; then
        echo "$libdir" | sudo tee -a "$musl_path_file" >/dev/null
      fi
      return 0
    fi
    echo "warning: musl detected but no /etc/ld-musl-*.path found; you may need to add $libdir to the musl loader path manually" >&2
    return 0
  fi

  local drop_in="/etc/ld.so.conf.d/sshm.conf"
  local marker="# sshm (Secure-SHM) dynamic linker path"
  if [[ -d /etc/ld.so.conf.d ]]; then
    if ! grep -R --fixed-strings --quiet -- "$libdir" /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null; then
      {
        echo "$marker"
        echo "$libdir"
      } | "${SUDO[@]}" tee "$drop_in" >/dev/null
    fi
  else
    echo "warning: /etc/ld.so.conf.d not found; you may need to add $libdir to your dynamic linker config manually" >&2
  fi
}

# Install library + binaries (handles SONAME + symlinks)
ensure_sudo "install system-wide + systemd unit"
"${SUDO[@]}" make install

# On some distros /usr/local/lib is not in the default dynamic loader path.
ensure_linux_dynamic_linker_path "/usr/local/lib"
run_ldconfig || true

# Create user and log dir
if ! id sshm &>/dev/null; then
  "${SUDO[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin --comment "SSHM daemon user" sshm
fi
"${SUDO[@]}" mkdir -p /var/log/sshm
"${SUDO[@]}" chown sshm:sshm /var/log/sshm
"${SUDO[@]}" chmod 0755 /var/log/sshm

# Install systemd unit
"${SUDO[@]}" install -Dm0644 systemd/sshmd.service /etc/systemd/system/sshmd.service
if command -v systemctl >/dev/null 2>&1; then
  "${SUDO[@]}" systemctl daemon-reload
  "${SUDO[@]}" systemctl enable --now sshmd
  echo "Installed and started sshmd. Try: sshmctl ping"
else
  echo "Installed systemd unit, but systemctl is not available. Start the daemon manually." >&2
fi
