#ifndef NETADDR_H
#define NETADDR_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * Address handling that works for both IPv4 and IPv6.
 *
 * Sockets in this project are created as dual stack (AF_INET6 with
 * IPV6_V6ONLY off), so IPv4 peers show up as v4-mapped addresses like
 * ::ffff:192.0.2.1. That keeps one socket and one code path for both
 * families, at the cost of having to normalise v4-mapped addresses when
 * comparing or printing them.
 *
 * The wire encoding is fixed at 19 bytes so candidates can be packed into
 * a datagram without length prefixes:
 *
 *     family(1)  4 or 6
 *     addr(16)   IPv4 in the first 4 bytes, zero padded; IPv6 in full
 *     port(2)    network byte order
 */

#define NETADDR_WIRE_LEN 19
#define NETADDR_STRLEN   (INET6_ADDRSTRLEN + 8)  /* room for [addr]:port */

typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
} netaddr_t;

/* Build from a raw sockaddr. Returns 0 on success. */
int netaddr_from_sockaddr(netaddr_t *a, const struct sockaddr *sa, socklen_t len);

/* Parse "192.0.2.1", "2001:db8::1" or "[2001:db8::1]" plus a port. */
int netaddr_from_string(netaddr_t *a, const char *host, uint16_t port);

/* AF_INET or AF_INET6. v4-mapped v6 addresses report AF_INET. */
int netaddr_family(const netaddr_t *a);

uint16_t netaddr_port(const netaddr_t *a);
void netaddr_set_port(netaddr_t *a, uint16_t port);

/* Compares address and port. v4-mapped and plain v4 forms compare equal. */
int netaddr_equal(const netaddr_t *a, const netaddr_t *b);

/* "192.0.2.1:1234" or "[2001:db8::1]:1234". Returns buf. */
const char *netaddr_to_string(const netaddr_t *a, char *buf, size_t buflen);

/* Fixed 19-byte encoding. out must have room for NETADDR_WIRE_LEN. */
int netaddr_encode(const netaddr_t *a, uint8_t *out);
int netaddr_decode(netaddr_t *a, const uint8_t *in);

/* Rewrite a plain IPv4 address as v4-mapped IPv6, so it can be used with a
 * dual stack socket. No-op for addresses that are already v6. */
void netaddr_to_v4mapped(netaddr_t *a);


/* Open a dual stack UDP socket bound to *port (0 picks one). On return
 * *port holds the port actually bound. Falls back to IPv4 only if the
 * system refuses to turn IPV6_V6ONLY off.
 *
 * Returns the fd, or -1. */
int netaddr_open_dualstack_udp(uint16_t *port);

#endif
