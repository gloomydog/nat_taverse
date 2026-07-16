#ifndef SIGNALING_NOSTR_H
#define SIGNALING_NOSTR_H

#include "signaling.h"
#include "crypto.h"

/* Create a signalling backend backed by public Nostr relays.
 *
 * relay_urls: e.g. "wss://relay.damus.io". Give several; public relays go
 *             down often enough that losing the rendezvous to one outage
 *             would be a shame.
 * keys:       from nt_derive_keys(). Uses nostr_seed and
 *             nostr_content_key.
 *
 * No server of your own is needed, at the cost of two limitations:
 *   - It cannot relay data (supports_relay() returns 0). If hole punching
 *     fails, the connection fails.
 *   - Relays speak WebSocket over TCP and cannot observe your UDP
 *     mapping. The caller must gather candidates via STUN and pass them
 *     to publish().
 *
 * Returns 0 if at least one relay was reached. */
int signaling_nostr_create(signaling_backend_t *out,
                           const char **relay_urls, int nrelays,
                           const nt_keys_t *keys, int verbose);

#endif
