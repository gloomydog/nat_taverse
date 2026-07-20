#ifndef CANDIDATE_H
#define CANDIDATE_H

#include <stdint.h>
#include "netaddr.h"

/*
 * Gathering the addresses a peer might reach us on.
 *
 * There is rarely one answer. A host typically has a private LAN address,
 * possibly a global IPv6 address, and a public address its NAT allocated
 * for this socket. Rather than guessing which will work, gather all of
 * them and let the punch race them in parallel (see holepunch.h): the
 * fastest working path wins naturally. A same-LAN or IPv6 path confirms
 * almost instantly, while a NATed IPv4 path costs a round trip through
 * the public internet.
 *
 * Two kinds:
 *
 *   host   an address on a local interface. Reaches a peer on the same
 *          LAN, and -- with a global IPv6 address -- sometimes the open
 *          internet. Free to gather; no server involved.
 *   srflx  server-reflexive: what a STUN server saw us come from, i.e.
 *          the mapping our NAT made for this socket. Gathered by stun.c.
 *
 * Host candidates are worth including even when they look useless. They
 * cost one extra datagram per punch round, and they are the only thing
 * that works when both peers sit behind the same NAT, where the srflx
 * candidates point at the router's external address and hairpinning may
 * not be supported.
 */

/* Local interface addresses, loopback excluded.
 *
 * Includes private IPv4 (192.168/16 and friends): those are exactly what
 * makes the same-LAN path work, so filtering to globally routable
 * addresses here would be a mistake. IPv6 link-local (fe80::/10) *is*
 * skipped -- it needs a scope id to be usable, which does not survive the
 * wire encoding and would not mean the same thing on the peer's host.
 *
 * Every returned address gets `port`, which should be the port the punch
 * socket is bound to: an address without our own port on it tells the
 * peer nothing about where to aim.
 *
 * Returns the number written, at most max. */
int cand_collect_host(netaddr_t *out, int max, uint16_t port);

/* Append src to dst if it is not already there, keeping dst within max.
 *
 * Deduplication matters more than it looks: on a dual stack socket a STUN
 * answer may come back v4-mapped and compare equal to a host candidate we
 * already have, and punching the same address twice per round is wasted
 * traffic. Returns 1 if it was added, 0 if it was a duplicate or dst is
 * full. */
int cand_add_unique(netaddr_t *dst, int *n, int max, const netaddr_t *src);

#endif
