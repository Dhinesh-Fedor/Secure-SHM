#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int connect_daemon(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            perror("write");
            exit(1);
        }
        if (w == 0) {
            fprintf(stderr, "write: short write\n");
            exit(1);
        }
        off += (size_t)w;
    }
}

static void read_line(int fd, char *buf, size_t cap) {
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

static void must_prefix(const char *got, const char *prefix) {
    if (strncmp(got, prefix, strlen(prefix)) != 0) {
        fprintf(stderr, "unexpected response (wanted prefix '%s'): %s\n", prefix, got);
        exit(1);
    }
}

int main(void) {
    const char *path = getenv("SSHM_SOCKET_PATH");
    if (!path || !path[0]) {
        fprintf(stderr, "SSHM_SOCKET_PATH not set\n");
        return 1;
    }

    int fd = connect_daemon(path);
    if (fd < 0) {
        fprintf(stderr, "test_daemon_protocol_edges: failed to connect to %s: %s\n", path, strerror(errno));
        return 1;
    }

    char line[256];

    /* 1) Overlong line should be rejected and drained. */
    size_t big_len = 2048;
    char *big = (char *)malloc(big_len);
    if (!big) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    memset(big, 'A', big_len);
    memcpy(big, "PING ", 5);
    big[big_len - 1] = '\n';

    write_all(fd, big, big_len);
    free(big);

    read_line(fd, line, sizeof line);
    must_prefix(line, "ERR toolong");

    /* 2) Invalid segment name should be rejected. */
    write_all(fd, "REGISTER a/b\n", strlen("REGISTER a/b\n"));
    read_line(fd, line, sizeof line);
    must_prefix(line, "ERR name");

    close(fd);
    return 0;
}
