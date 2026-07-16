#include "holepunch.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sodium.h>

/*
 * Punch packets are shaped like STUN Binding Requests and Responses
 * rather than using a bespoke format, for two reasons.
 *
 * Some carrier networks appear to treat unrecognised small UDP payloads
 * differently from STUN traffic; looking like STUN measurably improved
 * reachability during testing on a mobile network. And the 12-byte
 * transaction id field is a natural place to carry the token.
 *
 * A real STUN server receiving one of these ignores it, since the
 * transaction id matches nothing it issued.
 */

#define STUN_MAGIC_COOKIE 0x2112A442u
#define PUNCH_TYPE 0x0001   /* looks like Binding Request  */
#define ACK_TYPE   0x0101   /* looks like Binding Response */

#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t  transaction_id[NT_TOKEN_LEN];
} punch_packet_t;
#pragma pack(pop)

static void build_packet(punch_packet_t *p, uint16_t type,
                         const uint8_t token[NT_TOKEN_LEN]) {
    p->type = htons(type);
    p->length = htons(0);
    p->magic_cookie = htonl(STUN_MAGIC_COOKIE);
    memcpy(p->transaction_id, token, NT_TOKEN_LEN);
}

/* Constant time: a byte-at-a-time comparison would leak how much of a
 * guessed token was right, letting an attacker find it a byte at a time. */
static int token_matches(const punch_packet_t *p, const uint8_t token[NT_TOKEN_LEN]) {
    return sodium_memcmp(p->transaction_id, token, NT_TOKEN_LEN) == 0;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull;
}

static void sleep_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

int holepunch_is_control_packet(const void *buf, size_t len) {
    if (len < sizeof(punch_packet_t)) return 0;
    const punch_packet_t *p = (const punch_packet_t *)buf;
    if (ntohl(p->magic_cookie) != STUN_MAGIC_COOKIE) return 0;
    uint16_t type = ntohs(p->type);
    return type == PUNCH_TYPE || type == ACK_TYPE;
}

int holepunch_run(const holepunch_config_t *cfg, holepunch_result_t *result) {
    memset(result, 0, sizeof(*result));
    if (cfg->npeers <= 0) return -1;

    /* Short receive timeout so sending and polling alternate. */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = cfg->burst_interval_ms * 1000;
    setsockopt(cfg->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* A dual stack socket needs v4 destinations as v4-mapped. Do the
     * conversion once rather than on every round. */
    netaddr_t dst[HP_MAX_CANDIDATES];
    int sock_v6 = 0;
    {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(cfg->sockfd, (struct sockaddr *)&ss, &sl) == 0)
            sock_v6 = (ss.ss_family == AF_INET6);
    }
    int ndst = 0;
    for (int i = 0; i < cfg->npeers && i < HP_MAX_CANDIDATES; i++) {
        netaddr_t a = cfg->peers[i];
        if (sock_v6) netaddr_to_v4mapped(&a);
        /* An IPv4-only socket cannot reach an IPv6 candidate. */
        if (!sock_v6 && netaddr_family(&a) == AF_INET6) continue;
        dst[ndst++] = a;
    }
    if (ndst == 0) return -1;

    uint64_t deadline = now_ms() + cfg->overall_timeout_ms;

    /* Transmit for the whole window rather than a fixed burst. The two
     * sides are never perfectly aligned, and a wide window costs nothing
     * but a handful of tiny datagrams. */
    while (now_ms() < deadline) {
        punch_packet_t punch;
        build_packet(&punch, PUNCH_TYPE, cfg->session_token);
        for (int i = 0; i < ndst; i++)
            sendto(cfg->sockfd, &punch, sizeof(punch), 0,
                   (struct sockaddr *)&dst[i].ss, dst[i].len);

        uint8_t buf[64];
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(cfg->sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n < (ssize_t)sizeof(punch_packet_t)) continue;

        punch_packet_t *in = (punch_packet_t *)buf;
        if (ntohl(in->magic_cookie) != STUN_MAGIC_COOKIE) continue;
        if (!token_matches(in, cfg->session_token)) continue;

        netaddr_t src;
        if (netaddr_from_sockaddr(&src, (struct sockaddr *)&from, fromlen) != 0)
            continue;

        uint16_t type = ntohs(in->type);

        if (type == PUNCH_TYPE) {
            /* Reply to where it actually came from, not to any candidate
             * we were told about. If the peer's NAT gave us a different
             * mapping than it advertised, this is the only address that
             * works. */
            punch_packet_t ack;
            build_packet(&ack, ACK_TYPE, cfg->session_token);
            sendto(cfg->sockfd, &ack, sizeof(ack), 0,
                   (struct sockaddr *)&from, fromlen);
            result->success = 1;
            result->confirmed_peer = src;
            return 0;
        }
        if (type == ACK_TYPE) {
            result->success = 1;
            result->confirmed_peer = src;
            return 0;
        }
    }
    return 0;   /* success stays 0 */
}

/* ------------------------------- keepalive ------------------------------ */

static pthread_t g_thread;
static volatile int g_running = 0;
static int g_sockfd;
static netaddr_t g_peer;
static uint8_t g_token[NT_TOKEN_LEN];
static int g_interval_ms;

static void *keepalive_loop(void *arg) {
    (void)arg;
    while (g_running) {
        punch_packet_t ka;
        build_packet(&ka, PUNCH_TYPE, g_token);
        sendto(g_sockfd, &ka, sizeof(ka), 0,
               (struct sockaddr *)&g_peer.ss, g_peer.len);
        /* Wake up often enough that stopping is prompt, rather than
         * blocking the caller for a whole interval on shutdown. */
        for (int slept = 0; slept < g_interval_ms && g_running; slept += 100)
            sleep_ms(100);
    }
    return NULL;
}

int holepunch_start_keepalive(int sockfd, const netaddr_t *peer,
                              const uint8_t session_token[NT_TOKEN_LEN],
                              int interval_ms) {
    g_sockfd = sockfd;
    g_peer = *peer;
    memcpy(g_token, session_token, NT_TOKEN_LEN);
    g_interval_ms = interval_ms;
    g_running = 1;
    return pthread_create(&g_thread, NULL, keepalive_loop, NULL);
}

void holepunch_stop_keepalive(void) {
    if (g_running) {
        g_running = 0;
        pthread_join(g_thread, NULL);
        sodium_memzero(g_token, sizeof(g_token));
    }
}
