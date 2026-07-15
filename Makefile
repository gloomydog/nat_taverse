CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -std=c11 -O2
CFLAGS  += -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
LDFLAGS += -lpthread

# Only p2p_nostr needs external libraries:
#   libsecp256k1  BIP-340 Schnorr signatures for Nostr events
#   OpenSSL       TLS for wss://, SHA-256, ChaCha20-Poly1305
#
#   Arch          pacman -S openssl libsecp256k1
#   Debian/Ubuntu apt install libssl-dev libsecp256k1-dev
#   macOS         brew install openssl secp256k1
NOSTR_LIBS = -lsecp256k1 -lssl -lcrypto

CORE       = holepunch.o portmap.o
NOSTR_OBJS = p2p_nostr.o $(CORE) stun.o signaling_nostr.o nostr.o ws.o
P2P_OBJS   = p2p_connect.o $(CORE) relay_client.o relay_proto.o
SRV_OBJS   = relay_server.o relay_proto.o

all: p2p_nostr p2p_connect relay_server

# Everything except the Nostr client, for hosts without the libraries.
nolibs: p2p_connect relay_server

# Rendezvous over public Nostr relays. No server of your own.
p2p_nostr: $(NOSTR_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(NOSTR_LIBS)

# Rendezvous over your own server, with relayed fallback.
p2p_connect: $(P2P_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# The server for p2p_connect. Run it on a host with a public address.
relay_server: $(SRV_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o p2p_nostr p2p_connect relay_server

.PHONY: all nolibs clean
