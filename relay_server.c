#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "relay_proto.h"

/*
 * Rendezvous + relay server.  Run it on a host with a public address.
 *
 *   ./relay_server [listen_port] [-v]
 *
 * Single thread, single UDP socket, one table mapping a meeting id to at
 * most two peers.  That is the entire design.
 *
 * The server never inspects payloads.  It pairs up whoever names the same
 * meeting id and, if asked, forwards opaque bytes between them.
 */

#define MAX_SESSIONS      1024
#define SESSION_TIMEOUT_S 120
#define PUNCH_DELAY_MS    200   /* peers wait this long after PEER_INFO
                                 * before punching, absorbing RTT skew */

typedef struct {
    struct sockaddr_in addr;
    time_t last_seen;
    int in_use;
} peer_slot_t;

typedef struct {
    uint8_t id[RELAY_ID_LEN];
    peer_slot_t peers[2];
    int in_use;
    time_t created;
    uint64_t relayed_bytes;
} session_t;

static session_t g_sessions[MAX_SESSIONS];
static volatile sig_atomic_t g_running = 1;
static int g_verbose = 0;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static const char *addr_str(const struct sockaddr_in *a, char *buf, size_t len) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
    snprintf(buf, len, "%s:%u", ip, ntohs(a->sin_port));
    return buf;
}

static int same_addr(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static session_t *find_session(const uint8_t id[RELAY_ID_LEN]) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use && memcmp(g_sessions[i].id, id, RELAY_ID_LEN) == 0)
            return &g_sessions[i];
    }
    return NULL;
}

static session_t *create_session(const uint8_t id[RELAY_ID_LEN]) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            memset(&g_sessions[i], 0, sizeof(session_t));
            memcpy(g_sessions[i].id, id, RELAY_ID_LEN);
            g_sessions[i].in_use = 1;
            g_sessions[i].created = time(NULL);
            return &g_sessions[i];
        }
    }
    return NULL; /* table full */
}

/* Reap stale sessions.  Peers behind carrier NAT vanish without saying
 * goodbye, so without this the table would fill up. */
static void expire_sessions(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (!s->in_use) continue;

        int alive = 0;
        for (int p = 0; p < 2; p++) {
            if (!s->peers[p].in_use) continue;
            if (now - s->peers[p].last_seen > SESSION_TIMEOUT_S) {
                s->peers[p].in_use = 0;
            } else {
                alive = 1;
            }
        }
        if (!alive) s->in_use = 0;
    }
}

/* the other peer in this session, if any */
static peer_slot_t *other_peer(session_t *s, const struct sockaddr_in *me) {
    for (int p = 0; p < 2; p++) {
        if (s->peers[p].in_use && !same_addr(&s->peers[p].addr, me))
            return &s->peers[p];
    }
    return NULL;
}

/* Register a peer, or refresh it if already present.
 * Returns NULL when both slots are taken. */
static peer_slot_t *register_peer(session_t *s, const struct sockaddr_in *from) {
    /* refresh an existing entry */
    for (int p = 0; p < 2; p++) {
        if (s->peers[p].in_use && same_addr(&s->peers[p].addr, from)) {
            s->peers[p].last_seen = time(NULL);
            return &s->peers[p];
        }
    }
    /* claim a free slot */
    for (int p = 0; p < 2; p++) {
        if (!s->peers[p].in_use) {
            s->peers[p].addr = *from;
            s->peers[p].last_seen = time(NULL);
            s->peers[p].in_use = 1;
            return &s->peers[p];
        }
    }
    return NULL;
}

static void send_hello_ack(int sock, const struct sockaddr_in *to,
                            const uint8_t id[RELAY_ID_LEN]) {
    uint8_t buf[sizeof(relay_header_t) + sizeof(relay_hello_ack_t)];
    relay_header_t *h = (relay_header_t *)buf;
    relay_build_header(h, RELAY_HELLO_ACK, id);

    relay_hello_ack_t *ack = (relay_hello_ack_t *)(buf + sizeof(relay_header_t));
    ack->observed_ip = to->sin_addr.s_addr;
    ack->observed_port = to->sin_port;
    ack->reserved = 0;

    sendto(sock, buf, sizeof(buf), 0, (const struct sockaddr *)to, sizeof(*to));
}

/* Tell each peer about the other.  Sending both messages back to back is
 * the whole point: it is what lines up the simultaneous transmission. */
static void send_peer_info_both(int sock, session_t *s) {
    if (!s->peers[0].in_use || !s->peers[1].in_use) return;

    for (int p = 0; p < 2; p++) {
        const peer_slot_t *me = &s->peers[p];
        const peer_slot_t *other = &s->peers[1 - p];

        uint8_t buf[sizeof(relay_header_t) + sizeof(relay_peer_info_t)];
        relay_header_t *h = (relay_header_t *)buf;
        relay_build_header(h, RELAY_PEER_INFO, s->id);

        relay_peer_info_t *pi = (relay_peer_info_t *)(buf + sizeof(relay_header_t));
        pi->peer_ip = other->addr.sin_addr.s_addr;
        pi->peer_port = other->addr.sin_port;
        pi->punch_delay_ms = htons(PUNCH_DELAY_MS);

        sendto(sock, buf, sizeof(buf), 0,
               (const struct sockaddr *)&me->addr, sizeof(me->addr));
    }

    if (g_verbose) {
        char a[64], b[64];
        addr_str(&s->peers[0].addr, a, sizeof(a));
        addr_str(&s->peers[1].addr, b, sizeof(b));
        printf("[match] %s <-> %s (told both to punch)\n", a, b);
        fflush(stdout);
    }
}

static void handle_packet(int sock, const uint8_t *buf, ssize_t n,
                           const struct sockaddr_in *from) {
    if (!relay_validate_header(buf, (size_t)n)) return;

    const relay_header_t *h = (const relay_header_t *)buf;
    session_t *s = find_session(h->rendezvous_id);

    switch (h->type) {
    case RELAY_HELLO: {
        if (!s) {
            s = create_session(h->rendezvous_id);
            if (!s) {
                fprintf(stderr, "[warn] session table full\n");
                return;
            }
        }
        peer_slot_t *slot = register_peer(s, from);
        if (!slot) {
            /* A third party: either the id leaked or it collided. */
            if (g_verbose) {
                char a[64];
                printf("[reject] %s (session already full)\n", addr_str(from, a, sizeof(a)));
                fflush(stdout);
            }
            return;
        }

        /* Echo back the source address we observed -- this is what
         * makes a separate STUN query unnecessary. */
        send_hello_ack(sock, from, h->rendezvous_id);

        if (g_verbose) {
            char a[64];
            printf("[hello] %s\n", addr_str(from, a, sizeof(a)));
            fflush(stdout);
        }

        /* both here: introduce them at once */
        if (s->peers[0].in_use && s->peers[1].in_use)
            send_peer_info_both(sock, s);
        break;
    }

    case RELAY_KEEPALIVE: {
        if (!s) return;
        register_peer(s, from);
        break;
    }

    case RELAY_DATA: {
        /* forward verbatim; never look inside */
        if (!s) return;
        peer_slot_t *dst = other_peer(s, from);
        if (!dst) return;

        /* only registered peers may relay, or we become an open reflector */
        int known = 0;
        for (int p = 0; p < 2; p++)
            if (s->peers[p].in_use && same_addr(&s->peers[p].addr, from)) known = 1;
        if (!known) return;

        sendto(sock, buf, (size_t)n, 0,
               (const struct sockaddr *)&dst->addr, sizeof(dst->addr));
        s->relayed_bytes += (uint64_t)n;
        break;
    }

    case RELAY_BYE: {
        if (!s) return;
        for (int p = 0; p < 2; p++) {
            if (s->peers[p].in_use && same_addr(&s->peers[p].addr, from))
                s->peers[p].in_use = 0;
        }
        if (!s->peers[0].in_use && !s->peers[1].in_use) s->in_use = 0;
        if (g_verbose) {
            char a[64];
            printf("[bye] %s\n", addr_str(from, a, sizeof(a)));
            fflush(stdout);
        }
        break;
    }

    default:
        break;
    }
}

int main(int argc, char **argv) {
    uint16_t port = 3478; /* same as STUN; tends to pass through more networks */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) g_verbose = 1;
        else port = (uint16_t)atoi(argv[i]);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    /* wake up regularly so expire_sessions() runs even when idle */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("relay_server listening on UDP %u%s\n", port, g_verbose ? " (verbose)" : "");
    printf("press Ctrl+C to stop\n");
    fflush(stdout);

    while (g_running) {
        uint8_t buf[2048];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);

        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                              (struct sockaddr *)&from, &fromlen);
        if (n > 0) handle_packet(sock, buf, n, &from);

        expire_sessions();
    }

    printf("\nshutting down\n");
    close(sock);
    return 0;
}
