#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sshm_utils.h"

static int connect_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    const char *path = sshm_get_socket_path();
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void must_send(int fd, const char *s) {
    size_t n = strlen(s);
    ssize_t w = write(fd, s, n);
    if (w != (ssize_t)n) {
        perror("write");
        exit(1);
    }
}

static void must_read_line(int fd, char *buf, size_t cap) {
    size_t off = 0;
    while (off + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) {
            perror("read");
            exit(1);
        }
        buf[off++] = c;
        if (c == '\n') break;
    }
    buf[off] = '\0';
}

int main(void) {
    int fd = connect_daemon();
    if (fd < 0) {
        fprintf(stderr, "test_daemon_protocol: failed to connect to %s: %s\n", sshm_get_socket_path(), strerror(errno));
        return 1;
    }

    char line[256];

    must_send(fd, "PING\n");
    must_read_line(fd, line, sizeof line);
    if (strncmp(line, "OK PONG", 7) != 0) {
        fprintf(stderr, "PING response unexpected: %s\n", line);
        return 1;
    }

    close(fd);
    return 0;
}
