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

/*
 * Punch packets are shaped like STUN Binding Requests / Responses
 * (RFC 5389) rather than using a bespoke format.  Two reasons:
 *
 *  1. Some carrier networks appear to treat unrecognised small UDP
 *     payloads differently from STUN traffic.  Looking like STUN measurably
 *     improved reachability during testing on a mobile network.
 *  2. The 12-byte transaction id field is a natural place to carry the
 *     session token.
 *
 * A real STUN server receiving one of these would simply ignore it (the
 * transaction id will not match anything it issued), so this is harmless.
 */

#define STUN_MAGIC_COOKIE 0x2112A442u
#define PUNCH_TYPE 0x0001   /* looks like Binding Request  */
#define ACK_TYPE   0x0101   /* looks like Binding Response */

#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t  transaction_id[12];  /* carries session_token */
} punch_packet_t;
#pragma pack(pop)

static void build_packet(punch_packet_t *p, uint16_t type, const uint8_t token[12]) {
    p->type = htons(type);
    p->length = htons(0);
    p->magic_cookie = htonl(STUN_MAGIC_COOKIE);
    memcpy(p->transaction_id, token, 12);
}

static int token_matches(const punch_packet_t *p, const uint8_t token[12]) {
    return memcmp(p->transaction_id, token, 12) == 0;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
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

    if (cfg->start_at_epoch_ms > 0) {
        uint64_t n = now_ms();
        if (cfg->start_at_epoch_ms > n)
            sleep_ms((int)(cfg->start_at_epoch_ms - n));
    }

    /* Short receive timeout so we alternate between sending and polling. */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = cfg->burst_interval_ms * 1000;
    setsockopt(cfg->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint64_t deadline = now_ms() + cfg->overall_timeout_ms;

    /* Transmit for the whole window rather than a fixed number of bursts.
     * The two sides are never perfectly synchronised, and a wide window
     * costs nothing but a handful of tiny datagrams. */
    while (now_ms() < deadline) {
        punch_packet_t punch;
        build_packet(&punch, PUNCH_TYPE, cfg->session_token);
        sendto(cfg->sockfd, &punch, sizeof(punch), 0,
               (struct sockaddr *)&cfg->peer, sizeof(cfg->peer));

        uint8_t buf[64];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(cfg->sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n < (ssize_t)sizeof(punch_packet_t)) continue;

        punch_packet_t *in = (punch_packet_t *)buf;
        if (ntohl(in->magic_cookie) != STUN_MAGIC_COOKIE) continue;
        if (!token_matches(in, cfg->session_token)) continue;

        uint16_t type = ntohs(in->type);

        if (type == PUNCH_TYPE) {
            /* Reply to where the packet actually came from, not to the
             * address we were told to expect.  If the peer sits behind a
             * NAT that allocated a different mapping for us than for the
             * STUN server, this is the only address that works. */
            punch_packet_t ack;
            build_packet(&ack, ACK_TYPE, cfg->session_token);
            sendto(cfg->sockfd, &ack, sizeof(ack), 0,
                   (struct sockaddr *)&from, fromlen);
            result->success = 1;
            result->confirmed_peer = from;
            return 0;
        }
        if (type == ACK_TYPE) {
            result->success = 1;
            result->confirmed_peer = from;
            return 0;
        }
    }
    return 0;  /* success stays 0 */
}

/* ------------------------------- keepalive ------------------------------ */

static pthread_t g_thread;
static volatile int g_running = 0;
static int g_sockfd;
static struct sockaddr_in g_peer;
static uint8_t g_token[12];
static int g_interval_ms;

static void *keepalive_loop(void *arg) {
    (void)arg;
    while (g_running) {
        punch_packet_t ka;
        build_packet(&ka, PUNCH_TYPE, g_token);
        sendto(g_sockfd, &ka, sizeof(ka), 0,
               (struct sockaddr *)&g_peer, sizeof(g_peer));
        sleep_ms(g_interval_ms);
    }
    return NULL;
}

int holepunch_start_keepalive(int sockfd, struct sockaddr_in peer,
                              const uint8_t session_token[12], int interval_ms) {
    g_sockfd = sockfd;
    g_peer = peer;
    memcpy(g_token, session_token, 12);
    g_interval_ms = interval_ms;
    g_running = 1;
    return pthread_create(&g_thread, NULL, keepalive_loop, NULL);
}

void holepunch_stop_keepalive(void) {
    if (g_running) {
        g_running = 0;
        pthread_join(g_thread, NULL);
    }
}
