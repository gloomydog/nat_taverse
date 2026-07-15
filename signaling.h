#ifndef SIGNALING_H
#define SIGNALING_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/*
 * Pluggable rendezvous transport.
 *
 * Before two peers can punch a hole they must exchange candidate
 * addresses somehow.  Any channel will do, and the choice is orthogonal
 * to the punching itself:
 *
 *   nostr  -- public Nostr relays (signaling_nostr.c).  No server of your
 *             own.  Relays speak WebSocket over TCP, so they cannot see
 *             your UDP mapping; you must query STUN separately.
 *             Cannot carry data.
 *
 *   relay  -- your own rendezvous server (relay_server.c).  Needs a host
 *             with a public address, but the server observes your UDP
 *             source address directly (no STUN needed), can trigger both
 *             sides at the same instant, and can relay payloads when
 *             direct connectivity is impossible.
 *
 * A BitTorrent DHT or any existing messaging channel would fit the same
 * interface.
 *
 * Note that signalling and data relaying are separate problems: no choice
 * of signalling transport can make a direct path exist where the network
 * does not allow one.
 */

typedef struct signaling_backend signaling_backend_t;

struct signaling_backend {
    void *ctx;

    /* Announce our candidate address.  May be called repeatedly. */
    int (*publish)(void *ctx, const struct sockaddr_in *my_addr);

    /* Block until the peer's address is known.  Returns 0 on success.
     *
     * Punch immediately after this returns.  Every second of delay is a
     * chance for the peer's NAT mapping to be reallocated, which is the
     * single most common cause of failure. */
    int (*wait_peer)(void *ctx, struct sockaddr_in *peer_out, int timeout_ms);

    /* Whether this backend can forward payloads when the direct path
     * fails.  Nostr returns 0; the custom relay returns 1. */
    int (*supports_relay)(void *ctx);

    /* Only meaningful when supports_relay() returns 1. */
    int (*relay_send)(void *ctx, const void *payload, size_t len);
    int (*relay_recv)(void *ctx, void *payload, size_t maxlen, int timeout_ms);
    int (*relay_keepalive)(void *ctx);

    void (*close)(void *ctx);
};

#endif
