#include "holepunch.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sodium.h>

/*
 * Punch packets are shaped like STUN Binding Requests and Responses
 * rather than using a bespoke format, for two reasons.
 *
 * Some carrier networks appear to treat unrecognised small UDP payloads
 * differently from STUN traffic; looking like STUN measurably improved
 * reachability during testing on a mobile network. And the 12-byte
 * transaction id field is a natural place to carry a challenge.
 *
 * A real STUN server receiving one of these ignores it, since the
 * transaction id matches nothing it issued. In the other direction, a
 * stray real STUN response arriving on this socket fails our MAC and is
 * dropped, so the disguise costs us no confusion.
 *
 * Wire format (52 bytes):
 *
 *   off  field       size   value
 *   0    type        be16   0x0001 punch / 0x0101 ack   (STUN message type)
 *   2    length      be16   32                          (STUN attribute len)
 *   4    cookie      be32   0x2112A442                  (STUN magic cookie)
 *   8    challenge   8      sender's per-run nonce   \  occupies the STUN
 *   16   pad         4      zero                     /  12-byte txid field
 *   20   mac         32     crypto_auth over bytes 0..19
 */

#define STUN_MAGIC_COOKIE 0x2112A442u
#define PUNCH_TYPE 0x0001   /* looks like a Binding Request  */
#define ACK_TYPE   0x0101   /* looks like a Binding Response */

#define HDR_LEN   20                    /* type + length + cookie + txid */
#define CHAL_LEN  8
#define CHAL_OFF  8
#define MAC_LEN   crypto_auth_BYTES     /* 32 */

/* Asserted rather than trusted: a mismatch would show up only on the
 * wire, against the *other* peer's build, which is a miserable way to
 * find out. */
_Static_assert(HDR_LEN + MAC_LEN == HP_PACKET_LEN, "punch packet size");
_Static_assert(MAC_LEN == 32, "crypto_auth output size");

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void build_packet(uint8_t pkt[HP_PACKET_LEN], uint16_t type,
                         const uint8_t challenge[CHAL_LEN],
                         const uint8_t key[NT_PUNCH_KEY_LEN]) {
    put16(pkt, type);
    put16(pkt + 2, MAC_LEN);
    put32(pkt + 4, STUN_MAGIC_COOKIE);
    memcpy(pkt + CHAL_OFF, challenge, CHAL_LEN);
    memset(pkt + CHAL_OFF + CHAL_LEN, 0, HDR_LEN - CHAL_OFF - CHAL_LEN);
    crypto_auth(pkt + HDR_LEN, pkt, HDR_LEN, key);
}

/* Shape plus authenticity.
 *
 * crypto_auth_verify is constant time, so an attacker probing the port
 * learns nothing from timing about whether a guessed key was partially
 * right. */
static int packet_valid(const uint8_t *pkt, ssize_t n,
                        const uint8_t key[NT_PUNCH_KEY_LEN]) {
    if (n != HP_PACKET_LEN) return 0;
    if (get32(pkt + 4) != STUN_MAGIC_COOKIE) return 0;

    uint16_t type = get16(pkt);
    if (type != PUNCH_TYPE && type != ACK_TYPE) return 0;

    return crypto_auth_verify(pkt + HDR_LEN, pkt, HDR_LEN, key) == 0;
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
    if (len != HP_PACKET_LEN) return 0;
    const uint8_t *p = buf;
    if (get32(p + 4) != STUN_MAGIC_COOKIE) return 0;
    uint16_t type = get16(p);
    return type == PUNCH_TYPE || type == ACK_TYPE;
}

int holepunch_run(const holepunch_config_t *cfg, holepunch_result_t *result) {
    memset(result, 0, sizeof(*result));
    if (cfg->npeers <= 0) return -1;

    int interval = cfg->resend_interval_ms > 0 ? cfg->resend_interval_ms : 60;

    /* Our own challenge for this run. An ack only counts if it echoes
     * this, which is what stops an ack captured from an earlier run being
     * replayed to fake a working path. */
    uint8_t challenge[CHAL_LEN];
    randombytes_buf(challenge, sizeof(challenge));

    /* A dual stack socket needs v4 destinations as v4-mapped. Do the
     * conversion once rather than on every round. */
    int sock_v6 = 0;
    {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(cfg->sockfd, (struct sockaddr *)&ss, &sl) == 0)
            sock_v6 = (ss.ss_family == AF_INET6);
    }

    netaddr_t dst[HP_MAX_CANDIDATES];
    int ndst = 0;
    for (int i = 0; i < cfg->npeers && i < HP_MAX_CANDIDATES; i++) {
        netaddr_t a = cfg->peers[i];
        /* An IPv4-only socket cannot reach an IPv6 candidate at all. */
        if (!sock_v6 && netaddr_family(&a) == AF_INET6) continue;
        if (sock_v6) netaddr_to_v4mapped(&a);
        dst[ndst++] = a;
    }
    if (ndst == 0) {
        sodium_memzero(challenge, sizeof(challenge));
        return -1;
    }

    uint64_t deadline = now_ms() + (uint64_t)cfg->overall_timeout_ms;
    uint64_t last_send = 0;
    int sent_once = 0;
    int rc = 0;

    /* Transmit for the whole window rather than a fixed burst. The two
     * sides are never perfectly aligned, and a wide window costs nothing
     * but a handful of tiny datagrams. */
    while (now_ms() < deadline) {
        uint64_t now = now_ms();
        if (!sent_once || now - last_send >= (uint64_t)interval) {
            uint8_t punch[HP_PACKET_LEN];
            build_packet(punch, PUNCH_TYPE, challenge, cfg->punch_key);
            for (int i = 0; i < ndst; i++)
                sendto(cfg->sockfd, punch, sizeof(punch), 0,
                       (struct sockaddr *)&dst[i].ss, dst[i].len);
            last_send = now;
            sent_once = 1;
        }

        struct pollfd pfd = { .fd = cfg->sockfd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, interval);
        if (pr < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }
        if (pr == 0 || !(pfd.revents & POLLIN)) continue;

        uint8_t buf[128];
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(cfg->sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            rc = -1;
            break;
        }

        /* Forged, replayed, unrelated, or a stray real STUN response. */
        if (!packet_valid(buf, n, cfg->punch_key)) continue;

        netaddr_t src;
        if (netaddr_from_sockaddr(&src, (struct sockaddr *)&from, fromlen) != 0)
            continue;

        uint16_t type = get16(buf);

        if (type == PUNCH_TYPE) {
            /* The peer's authenticated punch reached us, so the path works.
             * Ack to where it *actually came from*, not to any candidate we
             * were told about: if the peer's NAT gave us a different mapping
             * than it advertised, this is the only address that works. Echo
             * their challenge so they confirm too. */
            uint8_t ack[HP_PACKET_LEN];
            build_packet(ack, ACK_TYPE, buf + CHAL_OFF, cfg->punch_key);
            sendto(cfg->sockfd, ack, sizeof(ack), 0,
                   (struct sockaddr *)&from, fromlen);

            result->success = 1;
            result->confirmed_peer = src;
            connect(cfg->sockfd, (struct sockaddr *)&from, fromlen);
            break;
        }

        /* An ack is a live round trip back from something we punched. It
         * only counts if it echoes the challenge from *this* run. */
        if (sodium_memcmp(buf + CHAL_OFF, challenge, CHAL_LEN) == 0) {
            result->success = 1;
            result->confirmed_peer = src;
            connect(cfg->sockfd, (struct sockaddr *)&from, fromlen);
            break;
        }
    }

    sodium_memzero(challenge, sizeof(challenge));
    return rc;
}

/* ------------------------------- keepalive ------------------------------ */

static pthread_t g_thread;
static volatile int g_running = 0;
static int g_sockfd;
static uint8_t g_key[NT_PUNCH_KEY_LEN];
static int g_interval_ms;

static void *keepalive_loop(void *arg) {
    (void)arg;
    while (g_running) {
        /* A fresh challenge each time. Nothing waits on the reply; the
         * peer's punch loop treats the packet as an ordinary punch and
         * confirms on it, which is how a peer still in its punch window
         * catches up with one that has already moved on. */
        uint8_t challenge[CHAL_LEN];
        randombytes_buf(challenge, sizeof(challenge));

        uint8_t ka[HP_PACKET_LEN];
        build_packet(ka, PUNCH_TYPE, challenge, g_key);
        send(g_sockfd, ka, sizeof(ka), 0);   /* socket is connect()ed */
        sodium_memzero(challenge, sizeof(challenge));

        /* Wake up often enough that stopping is prompt, rather than
         * blocking the caller for a whole interval on shutdown. */
        for (int slept = 0; slept < g_interval_ms && g_running; slept += 100)
            sleep_ms(100);
    }
    return NULL;
}

int holepunch_start_keepalive(int sockfd,
                              const uint8_t punch_key[NT_PUNCH_KEY_LEN],
                              int interval_ms) {
    if (g_running) return -1;

    g_sockfd = sockfd;
    memcpy(g_key, punch_key, sizeof(g_key));
    g_interval_ms = interval_ms > 0 ? interval_ms : 15000;
    g_running = 1;

    if (pthread_create(&g_thread, NULL, keepalive_loop, NULL) != 0) {
        g_running = 0;
        sodium_memzero(g_key, sizeof(g_key));
        return -1;
    }
    return 0;
}

void holepunch_stop_keepalive(void) {
    if (g_running) {
        g_running = 0;
        pthread_join(g_thread, NULL);
        sodium_memzero(g_key, sizeof(g_key));
    }
}
