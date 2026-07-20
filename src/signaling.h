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
 * Note that signalling and data relaying are separate problems, and this
 * interface covers only the first. Nothing chosen here can make a direct
 * path exist where the network does not allow one -- when both peers sit
 * behind symmetric NAT, the remedy is a relay that forwards bytes (TURN,
 * Tailscale's DERP), which is out of scope for this library. A backend
 * that can also forward payloads is free to expose that itself; the
 * traversal code neither knows nor needs to know.
 */

#define SIG_MAX_CANDIDATES 8

typedef struct {
    netaddr_t addr[SIG_MAX_CANDIDATES];
    int n;

    /* Which punch attempt these candidates belong to.
     *
     * Candidates are re-measured and re-exchanged before every punch
     * attempt (see traverse.c), so several rounds of them cross the same
     * channel. Tagging each round keeps a leftover message from an
     * earlier one from being mistaken for this one's answer, which would
     * point the punch at an address already known not to work.
     *
     * wait_peer() must ignore rounds *older* than the `round` field the
     * caller passed in, and must keep waiting -- not fail -- when it sees
     * one. A round *newer* than the caller asked for must be accepted and
     * reported back in `round`, so the caller can catch up.
     *
     * Accepting newer rounds is not an optimisation, it is what stops the
     * pair deadlocking. The two sides do not leave the discovery phase at
     * the same instant: whoever sees the other first moves on to round 1
     * and never announces round 0 again. On an ephemeral-event backend
     * nothing is stored, so a peer still waiting on round 0 would wait
     * forever for an announcement that will never be repeated -- and would
     * discard the round 1 announcements telling it exactly where to punch.
     * Taking the newer round instead lets whichever side is ahead pull the
     * other forward, and the two converge on the same round. */
    uint8_t round;
} sig_candidates_t;

typedef struct signaling_backend signaling_backend_t;

struct signaling_backend {
    void *ctx;

    /* Announce our candidates. May be called repeatedly. */
    int (*publish)(void *ctx, const sig_candidates_t *mine);

    /* Block until the peer's candidates for peer_out->round are known.
     * Returns 0 on success.
     *
     * The caller sets peer_out->round before calling; anything tagged
     * with a different round is ignored and waiting continues.
     *
     * Punch immediately after this returns. Every second of delay is
     * another chance for the peer's NAT mapping to be reallocated, which
     * is the most common cause of failure in practice. */
    int (*wait_peer)(void *ctx, sig_candidates_t *peer_out, int timeout_ms);

    void (*close)(void *ctx);
};

#endif
