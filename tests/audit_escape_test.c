#include "sshm_utils.h"

#include <unistd.h>

int main(void) {
    // Intentionally include characters that must be JSON-escaped.
    const char *reason = "bad\"reason\nline\tend";
    return (log_json_event(getpid(), getuid(), "TEST", "escape", "OK", reason, NULL) == 0) ? 0 : 1;
}
