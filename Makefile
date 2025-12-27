CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -Iinclude -fPIC
LDFLAGS = -lsodium -lpthread

# ---- Packaging / install config ----
PREFIX ?= /usr/local
DESTDIR ?=
INCLUDEDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/bin
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig

VERSION ?= $(shell cat VERSION 2>/dev/null || echo 1.0.0)

SRC_DIR = src
INC_DIR = include
CLI_DIR = cli
OBJ_DIR = build/obj
LIB_DIR = build/lib
BIN_DIR = build/bin
DIST_DIR = build/dist
TEST_SCRIPT = tests/run_tests.sh

LIB_OBJS = $(OBJ_DIR)/sshm_core.o $(OBJ_DIR)/sshm_crypto.o $(OBJ_DIR)/sshm_sync.o $(OBJ_DIR)/sshm_utils.o
DAEMON_OBJS = $(OBJ_DIR)/sshm_daemon.o $(OBJ_DIR)/sshm_daemon_main.o $(OBJ_DIR)/sshm_utils.o
CLI_OBJS = $(OBJ_DIR)/sshmctl.o $(OBJ_DIR)/sshm_utils.o

STATIC_LIB = $(LIB_DIR)/libsshm.a
SHARED_LIB = $(LIB_DIR)/libsshm.so
DAEMON_BIN = $(BIN_DIR)/sshmd
CLI_BIN    = $(BIN_DIR)/sshmctl

PKGCONFIG_IN = pkgconfig/sshm.pc.in
PKGCONFIG_OUT = $(LIB_DIR)/pkgconfig/sshm.pc

all: dirs $(STATIC_LIB) $(SHARED_LIB) $(DAEMON_BIN) $(CLI_BIN) $(PKGCONFIG_OUT)

dirs:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR) $(LIB_DIR)/pkgconfig $(DIST_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/sshmctl.o: $(CLI_DIR)/sshmctl.c $(INC_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(STATIC_LIB): $(LIB_OBJS)
	ar rcs $@ $^

$(SHARED_LIB): $(LIB_OBJS)
	$(CC) -shared -Wl,-soname,libsshm.so -o $@ $^ $(LDFLAGS)

$(DAEMON_BIN): $(DAEMON_OBJS) $(SHARED_LIB)
	$(CC) -o $@ $(DAEMON_OBJS) $(SHARED_LIB) $(LDFLAGS)

$(CLI_BIN): $(CLI_OBJS) $(SHARED_LIB)
	$(CC) -o $@ $(CLI_OBJS) $(SHARED_LIB) $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

distclean: clean
	rm -rf $(DIST_DIR)

$(PKGCONFIG_OUT): $(PKGCONFIG_IN) | dirs
	@sed \
		-e 's|@PREFIX@|$(PREFIX)|g' \
		-e 's|@LIBDIR@|$(LIBDIR)|g' \
		-e 's|@INCLUDEDIR@|$(INCLUDEDIR)|g' \
		-e 's|@VERSION@|$(VERSION)|g' \
		$< > $@

install: all
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(PKGCONFIGDIR)
	install -m 0644 $(INC_DIR)/*.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 0644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 0755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 0755 $(DAEMON_BIN) $(DESTDIR)$(BINDIR)/
	install -m 0755 $(CLI_BIN) $(DESTDIR)$(BINDIR)/
	install -m 0644 $(PKGCONFIG_OUT) $(DESTDIR)$(PKGCONFIGDIR)/sshm.pc
	@echo "Installed to $(DESTDIR)$(PREFIX)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/sshmd $(DESTDIR)$(BINDIR)/sshmctl
	rm -f $(DESTDIR)$(LIBDIR)/libsshm.a
	rm -f $(DESTDIR)$(LIBDIR)/libsshm.so
	rm -f $(DESTDIR)$(LIBDIR)/libsshm.so.*
	rm -f $(DESTDIR)$(PKGCONFIGDIR)/sshm.pc
	@echo "Uninstalled from $(DESTDIR)$(PREFIX)"

dist: all
	@name=sshm-$(VERSION); \
	tar -czf $(DIST_DIR)/$$name.tar.gz \
		--exclude-vcs --exclude='build/*' \
		LICENSE README.md Makefile VERSION \
		include src cli tests examples docs scripts systemd tools pkgconfig .github 2>/dev/null || \
		(tar -czf $(DIST_DIR)/$$name.tar.gz \
			--exclude-vcs --exclude='build/*' \
			LICENSE README.md Makefile VERSION \
			include src cli tests examples docs scripts systemd tools pkgconfig)
	@echo "Wrote $(DIST_DIR)/sshm-$(VERSION).tar.gz"

test: all
	@bash $(TEST_SCRIPT)

.PHONY: all dirs clean distclean install uninstall dist test

