CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -std=c11 -O2
CFLAGS  += -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -I$(SRC)
LDFLAGS += -lpthread

SRC   = src
TESTS = tests
BUILD = build

# The traversal core needs only libsodium (punch MAC, key derivation).
# The other two are the Nostr signalling backend's, not the traversal's:
# drop signaling_nostr/nostr/ws and plug in your own rendezvous behind
# signaling.h and they go with it.
#
# libsodium      Argon2id, crypto_auth, constant-time compare
# libsecp256k1   BIP-340 Schnorr signatures for Nostr events   [signalling]
# OpenSSL        TLS for wss://, SHA-256, Nostr payload cipher [signalling]
#
#   Arch           pacman -S libsodium libsecp256k1 openssl
#   Debian/Ubuntu  apt install libsodium-dev libsecp256k1-dev libssl-dev
#   macOS          brew install libsodium secp256k1 openssl
LIBS = -lsodium -lsecp256k1 -lssl -lcrypto

# NAT traversal proper. This is the part you lift into another project.
CORE_OBJS = $(addprefix $(BUILD)/, netaddr.o candidate.o stun.o holepunch.o traverse.o crypto.o)

# Rendezvous over public Nostr relays. One implementation of signaling.h.
SIG_OBJS  = $(addprefix $(BUILD)/, signaling_nostr.o nostr.o ws.o)

OBJS = $(BUILD)/demo.o $(CORE_OBJS) $(SIG_OBJS)

all: nat_demo

nat_demo: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

# The traversal core on its own, to check it stands without the
# signalling backend or its dependencies.
libnat_traverse.a: $(CORE_OBJS)
	$(AR) rcs $@ $^

# -MMD -MP emits a .d per object listing the headers it used, so editing a
# header rebuilds what included it. Without it a header-only change leaves
# stale objects linked in, which is a genuinely confusing way to debug.
$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD):
	@mkdir -p $(BUILD)

test: $(BUILD)/test_punch $(BUILD)/test_matrix
	$(BUILD)/test_punch
	@echo
	$(BUILD)/test_matrix

$(BUILD)/test_punch: $(TESTS)/test_punch.c $(addprefix $(BUILD)/, netaddr.o candidate.o holepunch.o) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lsodium

$(BUILD)/test_matrix: $(TESTS)/test_matrix.c $(addprefix $(BUILD)/, netaddr.o holepunch.o) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lsodium

clean:
	rm -rf $(BUILD) nat_demo libnat_traverse.a

-include $(wildcard $(BUILD)/*.d)

.PHONY: all clean test
