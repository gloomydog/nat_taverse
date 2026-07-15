#define _POSIX_C_SOURCE 200809L

#include "relay_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull;
}

static int resolve(const char *host, uint16_t port, struct sockaddr_in *out) {
    struct addrinfo hints, *res = NULL;
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

int relay_client_init(relay_client_t *c, int sockfd,
                       const char *server_host, uint16_t server_port,
                       const char *shared_secret) {
    memset(c, 0, sizeof(*c));
    c->sockfd = sockfd;
    if (resolve(server_host, server_port, &c->server) != 0) return -1;
    relay_derive_id(shared_secret, c->id);
    return 0;
}

static void send_simple(relay_client_t *c, uint8_t type) {
    relay_header_t h;
    relay_build_header(&h, type, c->id);
    sendto(c->sockfd, &h, sizeof(h), 0,
           (struct sockaddr *)&c->server, sizeof(c->server));
}

static int from_server(relay_client_t *c, const struct sockaddr_in *from) {
    return from->sin_addr.s_addr == c->server.sin_addr.s_addr &&
           from->sin_port == c->server.sin_port;
}

int relay_rendezvous(relay_client_t *c, int timeout_ms) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    uint64_t last_hello = 0;

    /* short receive timeout so we can keep re-sending HELLO while waiting */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 250 * 1000 };
    setsockopt(c->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (now_ms() < deadline) {
        /* Re-send HELLO every second.  While waiting for the peer this
         * doubles as keepalive for our own NAT mapping. */
        if (now_ms() - last_hello >= 1000) {
            send_simple(c, RELAY_HELLO);
            last_hello = now_ms();
        }

        uint8_t buf[2048];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(c->sockfd, buf, sizeof(buf), 0,
                              (struct sockaddr *)&from, &fromlen);
        if (n <= 0) continue;

        /* Ignore anything not from the server.  Stale datagrams from a
         * previous session can turn up here. */
        if (!from_server(c, &from)) continue;
        if (!relay_validate_header(buf, (size_t)n)) continue;

        relay_header_t *h = (relay_header_t *)buf;
        if (memcmp(h->rendezvous_id, c->id, RELAY_ID_LEN) != 0) continue;

        if (h->type == RELAY_HELLO_ACK &&
            (size_t)n >= sizeof(relay_header_t) + sizeof(relay_hello_ack_t)) {
            relay_hello_ack_t *ack = (relay_hello_ack_t *)(buf + sizeof(relay_header_t));
            memset(&c->observed, 0, sizeof(c->observed));
            c->observed.sin_family = AF_INET;
            c->observed.sin_addr.s_addr = ack->observed_ip;
            c->observed.sin_port = ack->observed_port;
            c->have_observed = 1;
            continue;
        }

        if (h->type == RELAY_PEER_INFO &&
            (size_t)n >= sizeof(relay_header_t) + sizeof(relay_peer_info_t)) {
            relay_peer_info_t *pi = (relay_peer_info_t *)(buf + sizeof(relay_header_t));
            memset(&c->peer, 0, sizeof(c->peer));
            c->peer.sin_family = AF_INET;
            c->peer.sin_addr.s_addr = pi->peer_ip;
            c->peer.sin_port = pi->peer_port;
            c->punch_delay_ms = ntohs(pi->punch_delay_ms);
            c->have_peer = 1;
            return 0;
        }
    }
    return -1; /* nobody arrived */
}

int relay_send(relay_client_t *c, const void *payload, size_t len) {
    if (len > RELAY_MAX_PAYLOAD) return -1;

    uint8_t buf[sizeof(relay_header_t) + RELAY_MAX_PAYLOAD];
    relay_header_t *h = (relay_header_t *)buf;
    relay_build_header(h, RELAY_DATA, c->id);
    memcpy(buf + sizeof(relay_header_t), payload, len);

    ssize_t n = sendto(c->sockfd, buf, sizeof(relay_header_t) + len, 0,
                        (struct sockaddr *)&c->server, sizeof(c->server));
    return n > 0 ? 0 : -1;
}

int relay_recv(relay_client_t *c, void *payload, size_t maxlen, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(c->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[2048];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    ssize_t n = recvfrom(c->sockfd, buf, sizeof(buf), 0,
                          (struct sockaddr *)&from, &fromlen);
    if (n <= 0) return 0; /* timeout */

    if (!from_server(c, &from)) return 0;  /* not relayed traffic */
    if (!relay_validate_header(buf, (size_t)n)) return 0;

    relay_header_t *h = (relay_header_t *)buf;
    if (h->type != RELAY_DATA) return 0;
    if (memcmp(h->rendezvous_id, c->id, RELAY_ID_LEN) != 0) return 0;

    size_t plen = (size_t)n - sizeof(relay_header_t);
    if (plen > maxlen) plen = maxlen;
    memcpy(payload, buf + sizeof(relay_header_t), plen);
    return (int)plen;
}

int relay_keepalive(relay_client_t *c) {
    send_simple(c, RELAY_KEEPALIVE);
    return 0;
}

void relay_bye(relay_client_t *c) {
    send_simple(c, RELAY_BYE);
}
