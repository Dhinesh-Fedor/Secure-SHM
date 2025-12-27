#!/usr/bin/env bash
set -euo pipefail

# Wrapper for uninstall with consistent sudo prompting/behavior.
# Mirrors scripts/install.sh --uninstall.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$script_dir/install.sh" --uninstall "$@"
