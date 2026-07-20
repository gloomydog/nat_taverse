#ifndef STUN_H
#define STUN_H

#include <stdint.h>
#include "netaddr.h"

/*
 * Minimal STUN client (RFC 5389), Binding Request only, IPv4 and IPv6.
 *
 * Ask a public server what source address it saw us come from. That is
 * the address our NAT allocated for the mapping toward that server -- the
 * "server-reflexive" (srflx) candidate.
 *
 * The important caveat: the answer describes the mapping toward the STUN
 * server, not toward an arbitrary peer. On a NAT with endpoint-dependent
 * mapping the peer will see something else entirely. That is a property
 * of STUN, not a shortcoming of this code. See BACKGROUND.md.
 *
 * No dependencies beyond POSIX sockets.
 */

/* --- server list --------------------------------------------------------
 *
 * Servers are contacted in order until one answers, so a dead or blocked
 * provider costs a timeout rather than the whole srflx candidate.
 *
 * The built-in default deliberately spans several operators. Probing two
 * of them is what distinguishes endpoint-independent mapping from
 * endpoint-dependent (stun_nat_type), and a single-operator list makes
 * that test -- and the srflx candidate itself -- fail as one unit when
 * that operator is unreachable. Two probes to one provider also share
 * that provider's outage and its blocking, which is exactly the failure
 * the test is least able to notice.
 *
 * Override with NAT_TRAVERSE_STUN_SERVERS: a comma- or space-separated
 * list of `host[:port]`, port defaulting to 3478. IPv6 literals must be
 * bracketed to carry a port (`[2001:db8::1]:3478`). An unset, empty, or
 * wholly unparseable value leaves the defaults in place.
 *
 * Parsed once on first use and then read-only, so concurrent readers are
 * fine. A caller that STUNs from several threads should make its first
 * call from one thread, so the parse happens before the others start.
 */
#define STUN_MAX_SERVERS 8

/* Query one specific STUN server.
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

/* Server-reflexive lookup over the configured server list, trying each in
 * turn until one answers.
 *
 * stun_srflx()  reaches the server over IPv4, learning the public IPv4
 *               ip:port the NAT mapped for this socket.
 * stun_srflx6() reaches the server over *real* IPv6, learning the exact
 *               global v6 ip:port the kernel sources from toward the
 *               internet. Returns -1 on an IPv4-only socket, or when the
 *               host has no IPv6 path.
 *
 * The v6 form matters more than "IPv6 has no NAT" suggests. A modern host
 * has many global v6 addresses on one interface: a stable SLAAC address
 * plus a rotating set of RFC 4941 privacy addresses. The kernel picks the
 * source for an outbound flow by its own rules, usually a privacy address.
 * So advertising host v6 addresses points the peer at an address this host
 * never actually sends from, and a stateful firewall drops every inbound
 * punch, because it belongs to no flow we originated -- the punch fails
 * even though both peers have perfectly good IPv6. The v6 srflx is the
 * address really in use, so both sides open a pinhole for, and aim at, the
 * same one. See BACKGROUND.md.
 *
 * Returns 0 on success. */
int stun_srflx(int sockfd, int timeout_ms, netaddr_t *out);
int stun_srflx6(int sockfd, int timeout_ms, netaddr_t *out);

/* --- NAT mapping behaviour --------------------------------------------- */

typedef enum {
    NAT_UNKNOWN = 0,   /* fewer than two servers answered */
    NAT_CONE,          /* endpoint-independent mapping: punchable */
    NAT_SYMMETRIC,     /* endpoint-dependent mapping: punch may fail */
} nat_type_t;

const char *nat_type_str(nat_type_t t);

/* Two STUN probes to *different* servers from the same socket, comparing
 * the mappings they report.
 *
 * Same mapping  => endpoint-independent ("cone"): the address one server
 *                  saw is the address any peer will see, so punching works.
 * Different     => endpoint-dependent ("symmetric"): the NAT allocates a
 *                  fresh mapping per destination, so the srflx candidate is
 *                  already wrong for the peer.
 *
 * Uses the first two configured servers that answer, so one being down
 * degrades to NAT_UNKNOWN rather than a wrong verdict.
 *
 * This is diagnostic only, and weak evidence at best: it probes the
 * mapping axis and says nothing about filtering, and two servers run by
 * one operator may be reached over the same path and agree while a real
 * peer sees something else. Never gate punching on it -- punch anyway and
 * let the result decide.
 *
 * *mapped, if non-NULL, receives a discovered srflx address whenever any
 * server answered, including when the verdict is NAT_UNKNOWN. That matters:
 * one reachable server is enough for a usable candidate but not enough for
 * a verdict, and dropping the candidate along with the verdict would
 * quietly cripple traversal. */
nat_type_t stun_nat_type(int sockfd, int timeout_ms, netaddr_t *mapped);

#endif
