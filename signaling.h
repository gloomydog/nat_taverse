#ifndef SIGNALING_H
#define SIGNALING_H

#include <stdint.h>
#include <stddef.h>
#include "netaddr.h"

/*
 * Pluggable rendezvous transport.
 *
 * Before two peers can punch a hole they have to exchange candidate
 * addresses somehow. Any channel will do, and the choice is orthogonal to
 * the punching itself, so it sits behind this interface.
 *
 * Only one backend ships here, signaling_nostr.c, which rides public
 * Nostr relays and needs no server of your own. A BitTorrent DHT, an
 * existing messaging channel, or a rendezvous server you run yourself
 * would all fit the same shape.
 *
 * Note that signalling and data relaying are separate problems. Nothing
 * chosen here can make a direct path exist where the network does not
 * allow one; supports_relay() exists so a backend that can forward
 * payloads may say so, and the Nostr one cannot.
 */

#define SIG_MAX_CANDIDATES 8

typedef struct {
    netaddr_t addr[SIG_MAX_CANDIDATES];
    int n;
} sig_candidates_t;

typedef struct signaling_backend signaling_backend_t;

struct signaling_backend {
    void *ctx;

    /* Announce our candidates. May be called repeatedly. */
    int (*publish)(void *ctx, const sig_candidates_t *mine);

    /* Block until the peer's candidates are known. Returns 0 on success.
     *
     * Punch immediately after this returns. Every second of delay is
     * another chance for the peer's NAT mapping to be reallocated, which
     * is the most common cause of failure in practice. */
    int (*wait_peer)(void *ctx, sig_candidates_t *peer_out, int timeout_ms);

    /* Whether this backend can forward payloads when no direct path
     * exists. The Nostr backend returns 0. */
    int (*supports_relay)(void *ctx);

    /* Only meaningful when supports_relay() returns 1. */
    int (*relay_send)(void *ctx, const void *payload, size_t len);
    int (*relay_recv)(void *ctx, void *payload, size_t maxlen, int timeout_ms);
    int (*relay_keepalive)(void *ctx);

    void (*close)(void *ctx);
};

#endif
