# Examples

Build the project first:

```bash
make
```

Run examples (requires daemon running for encrypted segments):

```bash
# Start daemon in foreground for local dev (unprivileged)
export SSHM_SOCKET_PATH="/tmp/sshm.sock"
export SSHM_AUDIT_DIR="/tmp/sshm-log"
export SSHM_AUDIT_FILE="/tmp/sshm-log/audit.log"
export SSHM_RUNTIME_LOG="/tmp/sshm-log/sshm.log"
mkdir -p "$SSHM_AUDIT_DIR"

./build/bin/sshmd &
export LD_LIBRARY_PATH="$PWD/build/lib:${LD_LIBRARY_PATH:-}"

gcc -Iinclude -Lbuild/lib -Wl,-rpath,"$PWD/build/lib" -o demo_create examples/demo_create.c -lsshm -lsodium -lpthread
./demo_create

# Plaintext multi-process demo (no daemon required)
gcc -Iinclude -Lbuild/lib -Wl,-rpath,"$PWD/build/lib" -o demo_plain_writer examples/demo_plain_writer.c -lsshm -lsodium -lpthread
gcc -Iinclude -Lbuild/lib -Wl,-rpath,"$PWD/build/lib" -o demo_plain_reader examples/demo_plain_reader.c -lsshm -lsodium -lpthread

# Terminal 1
./demo_plain_writer demo_plain

# Terminal 2
./demo_plain_reader demo_plain

# Encrypted demo (daemon required)
gcc -Iinclude -Lbuild/lib -Wl,-rpath,"$PWD/build/lib" -o demo_encrypted examples/demo_encrypted.c -lsshm -lsodium -lpthread
./demo_encrypted demo_secret
```
