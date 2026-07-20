#include "candidate.h"

#include <string.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Usable as a candidate: not loopback, not link-local, not unspecified.
 *
 * Link-local is excluded because it is only meaningful together with a
 * scope id (the interface it lives on). The wire encoding carries no
 * scope, and even if it did, the peer's interface indices are its own.
 * A peer aiming at fe80:: would either fail to send or send out the wrong
 * interface. */
static int v6_usable(const uint8_t a[16]) {
    static const uint8_t loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
    if (memcmp(a, loopback, 16) == 0) return 0;       /* ::1       */
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 0;  /* fe80::/10 */

    for (int i = 0; i < 16; i++) if (a[i]) return 1;
    return 0;                                          /* ::        */
}

int cand_collect_host(netaddr_t *out, int max, uint16_t port) {
    struct ifaddrs *ifa;
    if (getifaddrs(&ifa) != 0) return 0;

    int n = 0;
    for (struct ifaddrs *p = ifa; p && n < max; p = p->ifa_next) {
        if (!p->ifa_addr) continue;

        netaddr_t a;

        if (p->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)p->ifa_addr;
            if ((ntohl(s->sin_addr.s_addr) >> 24) == 127) continue;  /* 127/8 */
            if (netaddr_from_sockaddr(&a, p->ifa_addr, sizeof(*s)) != 0) continue;

        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)p->ifa_addr;
            if (!v6_usable(s->sin6_addr.s6_addr)) continue;
            if (netaddr_from_sockaddr(&a, p->ifa_addr, sizeof(*s)) != 0) continue;

        } else {
            continue;
        }

        /* getifaddrs reports the address, never a port. Ours is the one
         * the punch socket is bound to. */
        netaddr_set_port(&a, port);
        if (cand_add_unique(out, &n, max, &a)) { /* counted by the helper */ }
    }

    freeifaddrs(ifa);
    return n;
}

int cand_add_unique(netaddr_t *dst, int *n, int max, const netaddr_t *src) {
    if (*n >= max) return 0;
    for (int i = 0; i < *n; i++)
        if (netaddr_equal(&dst[i], src)) return 0;
    dst[(*n)++] = *src;
    return 1;
}
