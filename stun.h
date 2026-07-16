#ifndef STUN_H
#define STUN_H

#include <stdint.h>
#include "netaddr.h"

/*
 * Minimal STUN client (RFC 5389), Binding Request only, IPv4 and IPv6.
 *
 * Ask a public server what source address it saw us come from. That is
 * the address our NAT allocated for the mapping toward that server.
 *
 * The important caveat: the answer describes the mapping toward the STUN
 * server, not toward an arbitrary peer. On a NAT with endpoint-dependent
 * mapping the peer will see something else entirely. That is a property
 * of STUN, not a shortcoming of this code. See BACKGROUND.md.
 *
 * No dependencies beyond POSIX sockets.
 */

/* Query a STUN server.
 *
 * sockfd must already be bound, and must be the same socket used for the
 * peer traffic afterwards: NAT mappings are per socket, so an address
 * learned on a different socket is useless for punching.
 *
 * family selects which address family to reach the server over: pass
 * AF_INET or AF_INET6, or AF_UNSPEC to take whatever resolves first. On a
 * dual stack socket both work.
 *
 * Returns 0 on success, -1 on timeout or protocol error. */
int stun_query(int sockfd, const char *host, uint16_t port, int family,
               int timeout_ms, netaddr_t *out);

/* Compare the mappings two different servers report.
 *
 * Matching ports suggest endpoint-independent mapping; differing ports
 * mean endpoint-dependent mapping, where punching is unlikely to work.
 *
 * Only probes the mapping axis, says nothing about filtering, and is
 * weak evidence at best: two servers run by one operator may be reached
 * over the same path and agree while a real peer sees something else.
 * Observed in practice, see the notes in the README.
 *
 * Returns 0 for EIM-like, 1 for EDM, -1 if the probe failed. */
int stun_detect_mapping_behaviour(int sockfd,
                                  const char *host1, uint16_t port1,
                                  const char *host2, uint16_t port2,
                                  int family, int timeout_ms);

#endif
