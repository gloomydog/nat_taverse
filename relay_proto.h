#ifndef RELAY_PROTO_H
#define RELAY_PROTO_H

#include <stdint.h>
#include <netinet/in.h>

/*
 * A very small rendezvous + relay protocol.
 *
 * Same idea as Tailscale's DERP or Iroh's relay, minus everything we do
 * not need.  In particular this is deliberately *not* TURN (RFC 8656):
 * TURN is a large specification layered on STUN, with allocations,
 * permissions and channel bindings, and we need none of it.  The
 * application already encrypts end to end, so the server can stay a dumb
 * pipe, and there is no third-party TURN client to interoperate with.
 *
 * The server does two jobs:
 *
 *  1. Rendezvous -- the important one.
 *     It reports each peer's observed source address to the other (same
 *     effect as STUN, but folded into the signalling round trip), and
 *     nudges both sides at the same instant so they transmit
 *     simultaneously.  Compared with copying addresses around by hand,
 *     the delay between learning an address and using it drops to
 *     milliseconds -- which matters, because carrier NATs reallocate
 *     mappings quickly.
 *
 *  2. Relay -- the fallback.
 *     If punching fails, forward opaque payloads between the two peers.
 *     The server never inspects them.
 *
 * Security: rendezvous_id is derived from a shared secret, so the server
 * never sees the secret itself.  But it only pairs up two parties who
 * named the same meeting point; it is not peer authentication.  Verify
 * the peer in your application handshake.
 *
 * Limitation: UDP only.  Where UDP is blocked outright this is useless --
 * that is precisely why DERP runs over HTTPS on TCP 443.  Adding a TCP
 * transport is left as an exercise.
 */

#define RELAY_MAGIC      0x4E545256u  /* "NTRV" */
#define RELAY_VERSION    1
#define RELAY_ID_LEN     32
#define RELAY_MAX_PAYLOAD 1200        /* conservative, avoids fragmentation */

/* message types */
enum {
    RELAY_HELLO       = 0x01,  /* client -> server: join a meeting point */
    RELAY_HELLO_ACK   = 0x02,  /* server -> client: your observed address */
    RELAY_PEER_INFO   = 0x03,  /* server -> client: peer address + go signal */
    RELAY_KEEPALIVE   = 0x04,  /* client -> server: stay registered */
    RELAY_DATA        = 0x05,  /* both ways: relayed payload */
    RELAY_BYE         = 0x06,  /* client -> server: leave */
};

#pragma pack(push, 1)

/* common header, 40 bytes */
typedef struct {
    uint32_t magic;                  /* RELAY_MAGIC, network byte order */
    uint8_t  version;
    uint8_t  type;
    uint16_t reserved;
    uint8_t  rendezvous_id[RELAY_ID_LEN];
} relay_header_t;

/* RELAY_HELLO_ACK payload */
typedef struct {
    uint32_t observed_ip;    /* source address as the server saw it */
    uint16_t observed_port;  /* ditto, port */
    uint16_t reserved;
} relay_hello_ack_t;

/* RELAY_PEER_INFO payload */
typedef struct {
    uint32_t peer_ip;
    uint16_t peer_port;
    uint16_t punch_delay_ms; /* Wait this long after receiving, then
                              * punch.  The server sends both peers their
                              * PEER_INFO back to back, so the residual
                              * skew is only the difference in RTT -- and
                              * no clock synchronisation is required,
                              * since this is a relative delay. */
} relay_peer_info_t;

#pragma pack(pop)

/* Derive the meeting-point id from the shared secret, so the secret
 * itself never reaches the server.
 *
 * This is a simple one-way mixing function, NOT a real KDF.  Replace it
 * with Argon2id or similar before relying on it. */
void relay_derive_id(const char *shared_secret, uint8_t out[RELAY_ID_LEN]);

/* Fill in a header. */
void relay_build_header(relay_header_t *h, uint8_t type, const uint8_t id[RELAY_ID_LEN]);

/* Cheap sanity check on an inbound datagram.  Returns 1 if plausible. */
int relay_validate_header(const void *buf, size_t len);

#endif
