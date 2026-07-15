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
        if (fread(buf, 1, n, f) == n) {
            fclose(f);
            return;
        }
        fclose(f);
    }
    /* Fallback. The transaction id only needs to be unique enough to
     * match a reply to its request; it is not a security parameter. */
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rand();
}

static int resolve_host(const char *host, uint16_t port, struct sockaddr_in *out) {
    struct addrinfo hints, *res;
    char portstr[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(portstr, sizeof(portstr), "%u", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    memcpy(out, res->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(res);
    return 0;
}

/* XOR-MAPPED-ADDRESS obfuscates the address with the magic cookie so that
 * naive NATs do not rewrite it while passing the packet through. */
static int parse_xor_mapped_address(const uint8_t *v, uint16_t len,
                                    struct sockaddr_in *out) {
    if (len < 8) return -1;
    if (v[1] != 0x01) return -1;  /* IPv4 only */

    uint16_t xport;
    memcpy(&xport, v + 2, 2);
    xport = ntohs(xport) ^ (STUN_MAGIC_COOKIE >> 16);

    uint32_t xaddr;
    memcpy(&xaddr, v + 4, 4);
    xaddr = ntohl(xaddr) ^ STUN_MAGIC_COOKIE;

    out->sin_family = AF_INET;
    out->sin_port = htons(xport);
    out->sin_addr.s_addr = htonl(xaddr);
    return 0;
}

/* MAPPED-ADDRESS is the pre-RFC5389 form, kept for older servers. */
static int parse_mapped_address(const uint8_t *v, uint16_t len,
                                struct sockaddr_in *out) {
    if (len < 8) return -1;
    if (v[1] != 0x01) return -1;

    uint16_t port;
    uint32_t addr;
    memcpy(&port, v + 2, 2);
    memcpy(&addr, v + 4, 4);

    out->sin_family = AF_INET;
    out->sin_port = port;         /* already network byte order */
    out->sin_addr.s_addr = addr;
    return 0;
}

int stun_get_mapped_address(int sockfd, const char *stun_host, uint16_t stun_port,
                            int timeout_ms, stun_result_t *out) {
    struct sockaddr_in server;
    if (resolve_host(stun_host, stun_port, &server) != 0) return -1;

    uint8_t request[20];
    stun_header_t *hdr = (stun_header_t *)request;
    hdr->type = htons(STUN_BINDING_REQUEST);
    hdr->length = htons(0);
    hdr->magic_cookie = htonl(STUN_MAGIC_COOKIE);
    fill_random_bytes(hdr->transaction_id, sizeof(hdr->transaction_id));

    if (sendto(sockfd, request, sizeof(request), 0,
               (struct sockaddr *)&server, sizeof(server)) < 0)
        return -1;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t response[512];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    ssize_t n = recvfrom(sockfd, response, sizeof(response), 0,
                         (struct sockaddr *)&from, &fromlen);
    if (n < (ssize_t)sizeof(stun_header_t)) return -1;

    stun_header_t *rhdr = (stun_header_t *)response;
    if (ntohs(rhdr->type) != STUN_BINDING_RESPONSE) return -1;
    if (memcmp(rhdr->transaction_id, hdr->transaction_id, 12) != 0) return -1;

    uint8_t *p = response + sizeof(stun_header_t);
    uint8_t *end = p + ntohs(rhdr->length);
    if (end > response + n) end = response + n;

    int got_xor = 0, got_plain = 0;
    struct sockaddr_in xor_addr, plain_addr;

    while (p + 4 <= end) {
        uint16_t attr_type, attr_len;
        memcpy(&attr_type, p, 2);
        memcpy(&attr_len, p + 2, 2);
        attr_type = ntohs(attr_type);
        attr_len = ntohs(attr_len);
        p += 4;
        if (p + attr_len > end) break;

        if (attr_type == ATTR_XOR_MAPPED_ADDRESS) {
            if (parse_xor_mapped_address(p, attr_len, &xor_addr) == 0) got_xor = 1;
        } else if (attr_type == ATTR_MAPPED_ADDRESS) {
            if (parse_mapped_address(p, attr_len, &plain_addr) == 0) got_plain = 1;
        }
        p += (attr_len + 3) & ~3u;  /* attributes are padded to 4 bytes */
    }

    if (got_xor) {
        out->mapped_addr = xor_addr;
        out->ok = 1;
        return 0;
    }
    if (got_plain) {
        out->mapped_addr = plain_addr;
        out->ok = 1;
        return 0;
    }
    return -1;
}

int stun_detect_mapping_behaviour(int sockfd,
                                  const char *host1, uint16_t port1,
                                  const char *host2, uint16_t port2,
                                  int timeout_ms) {
    stun_result_t r1, r2;
    if (stun_get_mapped_address(sockfd, host1, port1, timeout_ms, &r1) != 0) return -1;
    if (stun_get_mapped_address(sockfd, host2, port2, timeout_ms, &r2) != 0) return -1;

    if (r1.mapped_addr.sin_addr.s_addr == r2.mapped_addr.sin_addr.s_addr &&
        r1.mapped_addr.sin_port == r2.mapped_addr.sin_port)
        return 0;  /* same mapping for two destinations -> EIM-like */
    return 1;      /* mapping varies with destination -> EDM */
}
