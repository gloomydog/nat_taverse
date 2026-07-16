CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -std=c11 -O2
CFLAGS  += -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
LDFLAGS += -lpthread

# libsodium      Argon2id, X25519, XChaCha20-Poly1305, constant-time compare
# libsecp256k1   BIP-340 Schnorr signatures for Nostr events
# OpenSSL        TLS for wss://, SHA-256, and the Nostr payload cipher
#
#   Arch           pacman -S libsodium libsecp256k1 openssl
#   Debian/Ubuntu  apt install libsodium-dev libsecp256k1-dev libssl-dev
#   macOS          brew install libsodium secp256k1 openssl
LIBS = -lsodium -lsecp256k1 -lssl -lcrypto

OBJS = p2p_nostr.o netaddr.o crypto.o handshake.o channel.o \
       stun.o portmap.o holepunch.o signaling_nostr.o nostr.o ws.o

p2p_nostr: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o p2p_nostr

.PHONY: clean
