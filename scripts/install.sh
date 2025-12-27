#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
SSHM install helper

Usage:
  bash scripts/install.sh [--prefix <path>] [--systemd]
  bash scripts/install.sh --uninstall [--prefix <path>] [--systemd]

Options:
  --prefix <path>   Install prefix passed to Makefile (default: /usr/local)
  --systemd         Also install/cleanup the systemd unit (Linux with systemd)
  --uninstall       Uninstall instead of install
  -h, --help        Show this help

Notes:
  - This script does NOT install OS dependencies (gcc/make/libsodium).
  - --systemd uses scripts/install-systemd.sh for install.
  - If you installed with a custom --prefix, pass the same --prefix on uninstall.
EOF
}

prefix=""
with_systemd=0
mode="install"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      prefix="${2:-}"
      if [[ -z "$prefix" ]]; then
        echo "error: --prefix requires a value" >&2
        exit 2
      fi
      shift 2
      ;;
    --systemd)
      with_systemd=1
      shift
      ;;
    --uninstall)
      mode="uninstall"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

is_root() {
  [[ "$(id -u)" -eq 0 ]]
}

needs_root_for_prefix() {
  local p="$1"
  [[ -z "$p" ]] && return 0
  [[ "$p" != /* ]] && return 1
  local probe="$p"
  while [[ ! -e "$probe" ]]; do
    probe="$(dirname "$probe")"
    [[ "$probe" == "/" ]] && break
  done
  [[ ! -w "$probe" ]]
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

detect_installed_libdir() {
  local prefix="$1"
  local candidates=("$prefix/lib" "$prefix/lib64")
  local dir
  for dir in "${candidates[@]}"; do
    if [[ -e "$dir/libsshm.so" || -e "$dir/libsshm.so.1" || -e "$dir/libsshm.so."* ]]; then
      echo "$dir"
      return 0
    fi
  done
  echo "$prefix/lib"
}

ensure_linux_dynamic_linker_path() {
  local libdir="$1"
  if [[ "$(uname -s)" != "Linux" ]]; then
    return 0
  fi

  # musl (e.g., Alpine) uses /etc/ld-musl-*.path rather than ld.so.conf.d.
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

  # glibc: ensure libdir is known to the dynamic loader.
  local drop_in="/etc/ld.so.conf.d/sshm.conf"
  local marker="# sshm (Secure-SHM) dynamic linker path"

  # If already referenced somewhere, don't touch.
  local conf_files=()
  [[ -f /etc/ld.so.conf ]] && conf_files+=(/etc/ld.so.conf)
  if [[ -d /etc/ld.so.conf.d ]]; then
    while IFS= read -r -d '' f; do
      conf_files+=("$f")
    done < <(find /etc/ld.so.conf.d -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null || true)
  fi

  local f
  for f in "${conf_files[@]}"; do
    if grep -Fq -- "$libdir" "$f" 2>/dev/null; then
      return 0
    fi
  done

  if [[ -d /etc/ld.so.conf.d ]]; then
    {
      echo "$marker"
      echo "$libdir"
    } | "${SUDO[@]}" tee "$drop_in" >/dev/null
  else
    echo "warning: /etc/ld.so.conf.d not found; you may need to add $libdir to your dynamic linker config manually" >&2
  fi
}

make_prefix_args=()
if [[ -n "$prefix" ]]; then
  make_prefix_args+=("PREFIX=$prefix")
fi

if [[ "$mode" == "install" ]]; then
  make

  if [[ $with_systemd -eq 1 ]]; then
    if [[ -n "$prefix" ]]; then
      echo "warning: --systemd path uses scripts/install-systemd.sh and ignores --prefix (installs to /usr/local)" >&2
    fi
    bash scripts/install-systemd.sh
    exit 0
  else
    install_prefix="${prefix:-/usr/local}"
    if needs_root_for_prefix "$install_prefix"; then
      ensure_sudo "install to $install_prefix"
    fi
    "${SUDO[@]}" make install "${make_prefix_args[@]}"
    install_prefix="${prefix:-/usr/local}"
    libdir="$(detect_installed_libdir "$install_prefix")"

    # Only adjust global loader config when installing into a system prefix.
    if needs_root_for_prefix "$install_prefix" || is_root; then
      ensure_sudo "update dynamic linker config for $libdir"
      ensure_linux_dynamic_linker_path "$libdir"
      run_ldconfig || true
    else
      echo "Note: installed under a user-writable prefix; you may need to set LD_LIBRARY_PATH=$libdir for this shell." >&2
    fi
  fi

  if [[ -n "$prefix" ]]; then
    echo "Installed under $prefix"
  else
    echo "Installed under /usr/local"
  fi
  echo "Start the daemon, then try: sshmctl ping"
  echo "(systemd: sudo systemctl enable --now sshmd)"
  exit 0
fi

# uninstall
if [[ $with_systemd -eq 1 ]]; then
  ensure_sudo "remove systemd unit"
  sudo systemctl disable --now sshmd 2>/dev/null || true
  sudo rm -f /etc/systemd/system/sshmd.service
  sudo systemctl daemon-reload 2>/dev/null || true
fi

uninstall_prefix="${prefix:-/usr/local}"
if needs_root_for_prefix "$uninstall_prefix" || [[ $with_systemd -eq 1 ]]; then
  ensure_sudo "uninstall from $uninstall_prefix"
fi
"${SUDO[@]}" make uninstall "${make_prefix_args[@]}"

# Cleanup our glibc loader drop-in if we created it.
if [[ "$(uname -s)" == "Linux" && -f /etc/ld.so.conf.d/sshm.conf ]]; then
  if grep -Fq -- "# sshm (Secure-SHM) dynamic linker path" /etc/ld.so.conf.d/sshm.conf 2>/dev/null; then
    ensure_sudo "remove dynamic linker drop-in"
    "${SUDO[@]}" rm -f /etc/ld.so.conf.d/sshm.conf
  fi
fi

if needs_root_for_prefix "$uninstall_prefix" || is_root; then
  run_ldconfig || true
fi

echo "Uninstalled."
