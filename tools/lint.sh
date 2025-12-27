#!/usr/bin/env bash
set -euo pipefail
echo "Running basic warnings build..."
make clean && make CFLAGS="-Wall -Wextra -Werror -O2 -g -Iinclude -fPIC"
echo "OK."
