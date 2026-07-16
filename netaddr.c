#include "netaddr.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

static const struct in6_addr *as_v6(const netaddr_t *a) {
    return &((const struct sockaddr_in6 *)&a->ss)->sin6_addr;
}

int netaddr_from_sockaddr(netaddr_t *a, const struct sockaddr *sa, socklen_t len) {
    if (len > (socklen_t)sizeof(a->ss)) return -1;
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) return -1;
    memset(a, 0, sizeof(*a));
    memcpy(&a->ss, sa, len);
    a->len = len;
    return 0;
}

int netaddr_from_string(netaddr_t *a, const char *host, uint16_t port) {
    memset(a, 0, sizeof(*a));

    /* Accept a bracketed literal so callers can pass what they read back
     * from netaddr_to_string(). */
    char tmp[INET6_ADDRSTRLEN + 2];
    size_t hl = strlen(host);
    if (hl >= 2 && host[0] == '[' && host[hl - 1] == ']') {
        if (hl - 2 >= sizeof(tmp)) return -1;
        memcpy(tmp, host + 1, hl - 2);
        tmp[hl - 2] = '\0';
        host = tmp;
    }

    struct in_addr v4;
    if (inet_pton(AF_INET, host, &v4) == 1) {
        struct sockaddr_in *s = (struct sockaddr_in *)&a->ss;
        s->sin_family = AF_INET;
        s->sin_addr = v4;
        s->sin_port = htons(port);
        a->len = sizeof(*s);
        return 0;
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, host, &v6) == 1) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&a->ss;
        s->sin6_family = AF_INET6;
        s->sin6_addr = v6;
        s->sin6_port = htons(port);
        a->len = sizeof(*s);
        return 0;
    }
    return -1;
}

int netaddr_family(const netaddr_t *a) {
    if (a->ss.ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(as_v6(a)))
        return AF_INET;
    return a->ss.ss_family;
}

uint16_t netaddr_port(const netaddr_t *a) {
    if (a->ss.ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)&a->ss)->sin_port);
    return ntohs(((const struct sockaddr_in6 *)&a->ss)->sin6_port);
}

void netaddr_set_port(netaddr_t *a, uint16_t port) {
    if (a->ss.ss_family == AF_INET)
        ((struct sockaddr_in *)&a->ss)->sin_port = htons(port);
    else
        ((struct sockaddr_in6 *)&a->ss)->sin6_port = htons(port);
}

/* Reduce to (family, 16 raw bytes, port) so that the v4 and v4-mapped
 * spellings of the same address compare equal. */
static void canonical(const netaddr_t *a, int *fam, uint8_t out[16], uint16_t *port) {
    *fam = netaddr_family(a);
    *port = netaddr_port(a);
    memset(out, 0, 16);

    if (a->ss.ss_family == AF_INET) {
        memcpy(out, &((const struct sockaddr_in *)&a->ss)->sin_addr, 4);
    } else if (*fam == AF_INET) {
        memcpy(out, as_v6(a)->s6_addr + 12, 4);   /* strip ::ffff: prefix */
    } else {
        memcpy(out, as_v6(a)->s6_addr, 16);
    }
}

int netaddr_equal(const netaddr_t *a, const netaddr_t *b) {
    int fa, fb;
    uint8_t ba[16], bb[16];
    uint16_t pa, pb;
    canonical(a, &fa, ba, &pa);
    canonical(b, &fb, bb, &pb);
    return fa == fb && pa == pb && memcmp(ba, bb, 16) == 0;
}

const char *netaddr_to_string(const netaddr_t *a, char *buf, size_t buflen) {
    int fam;
    uint8_t raw[16];
    uint16_t port;
    canonical(a, &fam, raw, &port);

    char ip[INET6_ADDRSTRLEN];
    if (fam == AF_INET) {
        struct in_addr v4;
        memcpy(&v4, raw, 4);
        if (!inet_ntop(AF_INET, &v4, ip, sizeof(ip))) {
            snprintf(buf, buflen, "?");
            return buf;
        }
        snprintf(buf, buflen, "%s:%u", ip, port);
    } else {
        struct in6_addr v6;
        memcpy(&v6, raw, 16);
        if (!inet_ntop(AF_INET6, &v6, ip, sizeof(ip))) {
            snprintf(buf, buflen, "?");
            return buf;
        }
        snprintf(buf, buflen, "[%s]:%u", ip, port);
    }
    return buf;
}

int netaddr_encode(const netaddr_t *a, uint8_t *out) {
    int fam;
    uint8_t raw[16];
    uint16_t port;
    canonical(a, &fam, raw, &port);

    out[0] = (fam == AF_INET) ? 4 : 6;
    memcpy(out + 1, raw, 16);
    uint16_t np = htons(port);
    memcpy(out + 17, &np, 2);
    return 0;
}

int netaddr_decode(netaddr_t *a, const uint8_t *in) {
    uint16_t np;
    memcpy(&np, in + 17, 2);
    uint16_t port = ntohs(np);

    memset(a, 0, sizeof(*a));

    if (in[0] == 4) {
        struct sockaddr_in *s = (struct sockaddr_in *)&a->ss;
        s->sin_family = AF_INET;
        memcpy(&s->sin_addr, in + 1, 4);
        s->sin_port = htons(port);
        a->len = sizeof(*s);
        return 0;
    }
    if (in[0] == 6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&a->ss;
        s->sin6_family = AF_INET6;
        memcpy(&s->sin6_addr, in + 1, 16);
        s->sin6_port = htons(port);
        a->len = sizeof(*s);
        return 0;
    }
    return -1;
}

void netaddr_to_v4mapped(netaddr_t *a) {
    if (a->ss.ss_family != AF_INET) return;

    struct sockaddr_in v4 = *(struct sockaddr_in *)&a->ss;
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&a->ss;

    memset(s, 0, sizeof(*s));
    s->sin6_family = AF_INET6;
    s->sin6_port = v4.sin_port;
    s->sin6_addr.s6_addr[10] = 0xFF;
    s->sin6_addr.s6_addr[11] = 0xFF;
    memcpy(s->sin6_addr.s6_addr + 12, &v4.sin_addr, 4);
    a->len = sizeof(*s);
}

int netaddr_is_global(const netaddr_t *a) {
    int fam;
    uint8_t r[16];
    uint16_t port;
    canonical(a, &fam, r, &port);

    if (fam == AF_INET) {
        if (r[0] == 10) return 0;                              /* 10/8 */
        if (r[0] == 127) return 0;                             /* loopback */
        if (r[0] == 0) return 0;
        if (r[0] == 172 && r[1] >= 16 && r[1] <= 31) return 0; /* 172.16/12 */
        if (r[0] == 192 && r[1] == 168) return 0;              /* 192.168/16 */
        if (r[0] == 169 && r[1] == 254) return 0;              /* link-local */
        if (r[0] == 100 && r[1] >= 64 && r[1] <= 127) return 0;/* CGNAT */
        return 1;
    }

    /* IPv6 */
    static const uint8_t loopback[16] = { [15] = 1 };
    if (memcmp(r, loopback, 16) == 0) return 0;
    {
        int all_zero = 1;
        for (int i = 0; i < 16; i++) if (r[i]) { all_zero = 0; break; }
        if (all_zero) return 0;
    }
    if ((r[0] & 0xFE) == 0xFC) return 0;                       /* fc00::/7 ULA */
    if (r[0] == 0xFE && (r[1] & 0xC0) == 0x80) return 0;       /* fe80::/10 */
    return 1;
}

int netaddr_open_dualstack_udp(uint16_t *port) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd >= 0) {
        int off = 0;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) == 0) {
            struct sockaddr_in6 a;
            memset(&a, 0, sizeof(a));
            a.sin6_family = AF_INET6;
            a.sin6_addr = in6addr_any;
            a.sin6_port = htons(*port);
            if (bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
                socklen_t l = sizeof(a);
                if (getsockname(fd, (struct sockaddr *)&a, &l) == 0)
                    *port = ntohs(a.sin6_port);
                return fd;
            }
        }
        close(fd);
    }

    /* No usable IPv6 stack, or V6ONLY could not be cleared. */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(*port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t l = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &l) == 0)
        *port = ntohs(a.sin_port);
    return fd;
}
