#include "channel.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull;
}

static void set_rcv_timeout(int fd, int ms) {
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int send_typed(int fd, const netaddr_t *peer, uint8_t type,
                      const void *body, size_t len) {
    uint8_t buf[1 + CH_MAX_PLAINTEXT + HS_OVERHEAD];
    if (1 + len > sizeof(buf)) return -1;
    buf[0] = type;
    memcpy(buf + 1, body, len);
    ssize_t n = sendto(fd, buf, 1 + len, 0,
                       (const struct sockaddr *)&peer->ss, peer->len);
    return n > 0 ? 0 : -1;
}

int channel_handshake(int sockfd, const netaddr_t *peer,
                      const uint8_t psk[NT_PSK_LEN],
                      int timeout_ms, hs_session_t *out) {
    hs_state_t st;
    uint8_t msg1[HS_MSG1_LEN];
    uint8_t my_msg2[HS_MSG2_LEN];
    int have_my_msg2 = 0;

    if (hs_start(&st, psk, msg1) != 0) return -1;

    /* The peer must be reachable at a concrete address; a v4 candidate
     * needs mapping if we are on a dual stack socket. */
    netaddr_t dst = *peer;
    {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(sockfd, (struct sockaddr *)&ss, &sl) == 0 &&
            ss.ss_family == AF_INET6)
            netaddr_to_v4mapped(&dst);
    }

    uint64_t deadline = now_ms() + timeout_ms;
    uint64_t last_send = 0;
    set_rcv_timeout(sockfd, 100);

    while (now_ms() < deadline) {
        /* Resend what we have. Until the peer's msg1 arrives we only have
         * msg1; after that we send msg2 as well, since the peer may have
         * lost it. */
        if (now_ms() - last_send >= 250) {
            send_typed(sockfd, &dst, CH_TYPE_HS1, msg1, sizeof(msg1));
            if (have_my_msg2)
                send_typed(sockfd, &dst, CH_TYPE_HS2, my_msg2, sizeof(my_msg2));
            last_send = now_ms();
        }

        uint8_t buf[256];
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n < 1) continue;

        /* Only listen to the peer we punched. Not a security control on
         * its own, since a source address can be forged, but it keeps
         * unrelated traffic out of the state machine. The tag inside is
         * what actually decides. */
        netaddr_t src;
        if (netaddr_from_sockaddr(&src, (struct sockaddr *)&from, fromlen) != 0)
            continue;
        if (!netaddr_equal(&src, peer)) continue;

        if (buf[0] == CH_TYPE_HS1 && n == 1 + HS_MSG1_LEN) {
            if (have_my_msg2) continue;   /* already processed one */
            if (hs_process_msg1(&st, psk, buf + 1, my_msg2) != 0) {
                /* Wrong passphrase, or a forgery. Ignore and keep waiting
                 * rather than aborting: the real peer may still arrive. */
                continue;
            }
            have_my_msg2 = 1;
            send_typed(sockfd, &dst, CH_TYPE_HS2, my_msg2, sizeof(my_msg2));
            last_send = now_ms();
            continue;
        }

        if (buf[0] == CH_TYPE_HS2 && n == 1 + HS_MSG2_LEN) {
            if (!have_my_msg2) continue;  /* their msg1 has not arrived yet */
            if (hs_process_msg2(&st, buf + 1, out) != 0) continue;

            /* Send our msg2 a few more times: the peer may still be
             * waiting for it, and once we return we stop retransmitting. */
            for (int i = 0; i < 3; i++) {
                send_typed(sockfd, &dst, CH_TYPE_HS2, my_msg2, sizeof(my_msg2));
                struct timespec ts = { 0, 60 * 1000000L };
                nanosleep(&ts, NULL);
            }
            hs_state_wipe(&st);
            return 0;
        }
        /* Anything else, including keepalives, is not our concern here. */
    }

    hs_state_wipe(&st);
    nt_wipe(my_msg2, sizeof(my_msg2));
    return -1;
}

int channel_send(int sockfd, const netaddr_t *peer, hs_session_t *s,
                 const void *data, size_t len) {
    uint8_t ct[CH_MAX_PLAINTEXT + HS_OVERHEAD];
    int clen = hs_seal(s, data, len, ct, sizeof(ct));
    if (clen < 0) return -1;
    int rc = send_typed(sockfd, peer, CH_TYPE_DATA, ct, (size_t)clen);
    nt_wipe(ct, sizeof(ct));
    return rc;
}

int channel_recv(int sockfd, hs_session_t *s, void *out, size_t outcap,
                 int timeout_ms) {
    set_rcv_timeout(sockfd, timeout_ms);

    uint8_t buf[1 + CH_MAX_PLAINTEXT + HS_OVERHEAD];
    ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    if (n < 1) return 0;
    if (buf[0] != CH_TYPE_DATA) return 0;   /* keepalive or stray */

    int plen = hs_open(s, buf + 1, (size_t)n - 1, out, outcap);
    if (plen < 0) return 0;   /* forged, corrupted, or replayed: drop quietly */
    return plen;
}
