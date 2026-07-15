#ifndef SIGNALING_NOSTR_H
#define SIGNALING_NOSTR_H

#include "signaling.h"

/* Create a signalling backend backed by public Nostr relays.
 *
 * relay_urls: e.g. "wss://relay.damus.io".  Give several; if one is
 *             unreachable the others carry on.
 * shared_secret: must match exactly on both peers; all keys derive from it.
 *
 * No server of your own is needed, at the cost of two limitations:
 *   - It cannot relay data (supports_relay() returns 0).  If hole punching
 *     fails, the connection fails.
 *   - Relays speak WebSocket over TCP and therefore cannot observe your
 *     UDP mapping.  The caller must obtain its public address via STUN and
 *     pass it to publish().
 *
 * Returns 0 if at least one relay was reached. */
int signaling_nostr_create(signaling_backend_t *out,
                            const char **relay_urls, int nrelays,
                            const char *shared_secret, int verbose);

#endif
