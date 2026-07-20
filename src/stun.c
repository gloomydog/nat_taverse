#include "stun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#define STUN_MAGIC_COOKIE       0x2112A442u
#define STUN_BINDING_REQUEST    0x0001
#define STUN_BINDING_RESPONSE   0x0101
#define ATTR_MAPPED_ADDRESS     0x0001
#define ATTR_XOR_MAPPED_ADDRESS 0x0020

#define FAM_V4 0x01
#define FAM_V6 0x02

#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t  transaction_id[12];
} stun_header_t;
#pragma pack(pop)

static void fill_random_bytes(uint8_t *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(buf, 1, n, f) == n) { fclose(f); return; }
        fclose(f);
    }
    /* The transaction id only has to match a reply to its request; it is
     * not a security parameter. */
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rand();
}

static int resolve(const char *host, uint16_t port, int family, netaddr_t *out) {
    struct addrinfo hints, *res;
    char portstr[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(portstr, sizeof(portstr), "%u", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;

    int rc = netaddr_from_sockaddr(out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return rc;
}

/* XOR-MAPPED-ADDRESS hides the address behind the magic cookie so that
 * NATs rewriting payloads in flight do not silently corrupt it.
 *
 * IPv4: port ^ (cookie >> 16), address ^ cookie
 * IPv6: port ^ (cookie >> 16), address ^ (cookie || transaction_id)
 */
static int parse_xor_mapped(const uint8_t *v, uint16_t len,
                            const uint8_t txid[12], netaddr_t *out) {
    if (len < 4) return -1;
    uint8_t fam = v[1];

    uint16_t xport;
    memcpy(&xport, v + 2, 2);
    uint16_t port = ntohs(xport) ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);

    uint8_t key[16];
    uint32_t cookie_be = htonl(STUN_MAGIC_COOKIE);
    memcpy(key, &cookie_be, 4);
    memcpy(key + 4, txid, 12);

    memset(out, 0, sizeof(*out));

    if (fam == FAM_V4) {
        if (len < 8) return -1;
        struct sockaddr_in *s = (struct sockaddr_in *)&out->ss;
        uint8_t a[4];
        for (int i = 0; i < 4; i++) a[i] = v[4 + i] ^ key[i];
        s->sin_family = AF_INET;
        memcpy(&s->sin_addr, a, 4);
        s->sin_port = htons(port);
        out->len = sizeof(*s);
        return 0;
    }

    if (fam == FAM_V6) {
        if (len < 20) return -1;
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&out->ss;
        uint8_t a[16];
        for (int i = 0; i < 16; i++) a[i] = v[4 + i] ^ key[i];
        s->sin6_family = AF_INET6;
        memcpy(&s->sin6_addr, a, 16);
        s->sin6_port = htons(port);
        out->len = sizeof(*s);
        return 0;
    }
    return -1;
}

/* The pre-RFC5389 form, kept for servers that only send this. */
static int parse_mapped(const uint8_t *v, uint16_t len, netaddr_t *out) {
    if (len < 4) return -1;
    uint8_t fam = v[1];

    uint16_t port;
    memcpy(&port, v + 2, 2);   /* already network order */

    memset(out, 0, sizeof(*out));

    if (fam == FAM_V4) {
        if (len < 8) return -1;
        struct sockaddr_in *s = (struct sockaddr_in *)&out->ss;
        s->sin_family = AF_INET;
        memcpy(&s->sin_addr, v + 4, 4);
        s->sin_port = port;
        out->len = sizeof(*s);
        return 0;
    }
    if (fam == FAM_V6) {
        if (len < 20) return -1;
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&out->ss;
        s->sin6_family = AF_INET6;
        memcpy(&s->sin6_addr, v + 4, 16);
        s->sin6_port = port;
        out->len = sizeof(*s);
        return 0;
    }
    return -1;
}

int stun_query(int sockfd, const char *host, uint16_t port, int family,
               int timeout_ms, netaddr_t *out) {
    netaddr_t server;
    if (resolve(host, port, family, &server) != 0) return -1;

    /* A dual stack socket needs v4 destinations expressed as v4-mapped. */
    int sock_family = AF_INET6;
    {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(sockfd, (struct sockaddr *)&ss, &sl) == 0)
            sock_family = ss.ss_family;
    }
    if (sock_family == AF_INET6) netaddr_to_v4mapped(&server);

    uint8_t request[20];
    stun_header_t *hdr = (stun_header_t *)request;
    hdr->type = htons(STUN_BINDING_REQUEST);
    hdr->length = htons(0);
    hdr->magic_cookie = htonl(STUN_MAGIC_COOKIE);
    fill_random_bytes(hdr->transaction_id, sizeof(hdr->transaction_id));

    if (sendto(sockfd, request, sizeof(request), 0,
               (struct sockaddr *)&server.ss, server.len) < 0)
        return -1;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Anything else already in the queue is not our reply; keep reading
     * until the transaction id matches or we run out of time. */
    for (int attempt = 0; attempt < 8; attempt++) {
        uint8_t response[1024];
        ssize_t n = recvfrom(sockfd, response, sizeof(response), 0, NULL, NULL);
        if (n < (ssize_t)sizeof(stun_header_t)) return -1;

        stun_header_t *rhdr = (stun_header_t *)response;
        if (ntohs(rhdr->type) != STUN_BINDING_RESPONSE) continue;
        if (memcmp(rhdr->transaction_id, hdr->transaction_id, 12) != 0) continue;

        uint8_t *p = response + sizeof(stun_header_t);
        uint8_t *end = p + ntohs(rhdr->length);
        if (end > response + n) end = response + n;

        int got_xor = 0, got_plain = 0;
        netaddr_t xor_addr, plain_addr;

        while (p + 4 <= end) {
            uint16_t at, al;
            memcpy(&at, p, 2);
            memcpy(&al, p + 2, 2);
            at = ntohs(at);
            al = ntohs(al);
            p += 4;
            if (p + al > end) break;

            if (at == ATTR_XOR_MAPPED_ADDRESS) {
                if (parse_xor_mapped(p, al, hdr->transaction_id, &xor_addr) == 0)
                    got_xor = 1;
            } else if (at == ATTR_MAPPED_ADDRESS) {
                if (parse_mapped(p, al, &plain_addr) == 0) got_plain = 1;
            }
            p += (al + 3) & ~3u;   /* attributes pad to 4 bytes */
        }

        if (got_xor)   { *out = xor_addr;   return 0; }
        if (got_plain) { *out = plain_addr; return 0; }
        return -1;
    }
    return -1;
}

/* ------------------------------ server list ----------------------------- */

typedef struct {
    char     host[128];
    uint16_t port;
} stun_server_t;

/* Spread across operators on purpose: see the note in stun.h. */
static const stun_server_t DEFAULT_SERVERS[] = {
    { "stun.l.google.com",     19302 },
    { "stun.cloudflare.com",    3478 },
    { "stun.nextcloud.com",      443 },
    { "stun.sipgate.net",       3478 },
};
#define N_DEFAULT (int)(sizeof(DEFAULT_SERVERS) / sizeof(DEFAULT_SERVERS[0]))

static stun_server_t g_servers[STUN_MAX_SERVERS];
static int g_nservers = 0;

/* Parse one `host`, `host:port`, `[v6]` or `[v6]:port` entry. */
static int parse_server(const char *tok, stun_server_t *out) {
    size_t len = strlen(tok);
    if (len == 0 || len >= sizeof(out->host)) return -1;

    out->port = 3478;

    if (tok[0] == '[') {
        const char *close = strchr(tok, ']');
        if (!close) return -1;
        size_t hlen = (size_t)(close - tok - 1);
        if (hlen == 0 || hlen >= sizeof(out->host)) return -1;
        memcpy(out->host, tok + 1, hlen);
        out->host[hlen] = '\0';
        if (close[1] == ':') {
            int p = atoi(close + 2);
            if (p <= 0 || p > 65535) return -1;
            out->port = (uint16_t)p;
        } else if (close[1] != '\0') {
            return -1;
        }
        return 0;
    }

    /* A bare IPv6 literal has several colons; only treat the last colon as
     * a port separator when there is exactly one, which is the host:port
     * case. Unbracketed v6 with a port is ambiguous and rejected above. */
    const char *colon = strchr(tok, ':');
    if (colon && strchr(colon + 1, ':') == NULL) {
        size_t hlen = (size_t)(colon - tok);
        if (hlen == 0 || hlen >= sizeof(out->host)) return -1;
        int p = atoi(colon + 1);
        if (p <= 0 || p > 65535) return -1;
        memcpy(out->host, tok, hlen);
        out->host[hlen] = '\0';
        out->port = (uint16_t)p;
        return 0;
    }

    /* Anything left holding a colon can only be an unbracketed IPv6
     * literal, which is fine without a port but must actually be one --
     * otherwise junk like ":::" sails through as a "hostname" and we
     * spend a DNS timeout per lookup discovering it is not. */
    if (strchr(tok, ':')) {
        struct in6_addr probe;
        if (inet_pton(AF_INET6, tok, &probe) != 1) return -1;
    }

    memcpy(out->host, tok, len + 1);
    return 0;
}

/* Parsed once, then read-only. See the threading note in stun.h. */
static void servers_init(void) {
    if (g_nservers) return;

    const char *env = getenv("NAT_TRAVERSE_STUN_SERVERS");
    if (env && *env) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", env);
        for (char *tok = strtok(buf, ", \t");
             tok && g_nservers < STUN_MAX_SERVERS;
             tok = strtok(NULL, ", \t")) {
            if (parse_server(tok, &g_servers[g_nservers]) == 0) g_nservers++;
        }
    }

    /* An unset, empty, or wholly unparseable override leaves the defaults
     * in place rather than leaving us with no servers at all. */
    if (g_nservers == 0) {
        for (int i = 0; i < N_DEFAULT && i < STUN_MAX_SERVERS; i++)
            g_servers[g_nservers++] = DEFAULT_SERVERS[i];
    }
}

/* ------------------------------- srflx ---------------------------------- */

static int socket_is_v6(int sockfd) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(sockfd, (struct sockaddr *)&ss, &sl) != 0) return 0;
    return ss.ss_family == AF_INET6;
}

static int srflx_over(int sockfd, int family, int timeout_ms, netaddr_t *out) {
    servers_init();
    for (int i = 0; i < g_nservers; i++) {
        if (stun_query(sockfd, g_servers[i].host, g_servers[i].port,
                       family, timeout_ms, out) == 0)
            return 0;
    }
    return -1;
}

int stun_srflx(int sockfd, int timeout_ms, netaddr_t *out) {
    return srflx_over(sockfd, AF_INET, timeout_ms, out);
}

int stun_srflx6(int sockfd, int timeout_ms, netaddr_t *out) {
    /* An IPv4-only socket cannot reach a v6 server at all; fail up front
     * rather than burning one timeout per configured server. */
    if (!socket_is_v6(sockfd)) return -1;
    return srflx_over(sockfd, AF_INET6, timeout_ms, out);
}

/* ---------------------------- mapping behaviour ------------------------- */

const char *nat_type_str(nat_type_t t) {
    switch (t) {
    case NAT_CONE:      return "cone (endpoint-independent, punchable)";
    case NAT_SYMMETRIC: return "symmetric (endpoint-dependent, punch may fail)";
    default:            return "unknown";
    }
}

nat_type_t stun_nat_type(int sockfd, int timeout_ms, netaddr_t *mapped) {
    servers_init();

    netaddr_t seen[2];
    int got = 0;

    /* First two servers that answer. One being down costs us the verdict,
     * not the candidate. */
    for (int i = 0; i < g_nservers && got < 2; i++) {
        if (stun_query(sockfd, g_servers[i].host, g_servers[i].port,
                       AF_INET, timeout_ms, &seen[got]) == 0)
            got++;
    }

    /* Hand back a candidate from whatever answered, even when that was
     * only one server and the verdict has to be NAT_UNKNOWN. */
    if (mapped && got > 0) *mapped = seen[0];

    if (got < 2) return NAT_UNKNOWN;
    return netaddr_equal(&seen[0], &seen[1]) ? NAT_CONE : NAT_SYMMETRIC;
}
