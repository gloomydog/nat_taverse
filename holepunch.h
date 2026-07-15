#ifndef HOLEPUNCH_H
#define HOLEPUNCH_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/*
 * UDP hole punching by simultaneous transmission.
 *
 * Both peers send to each other at roughly the same time.  Each outbound
 * packet creates state in the sender's own NAT and stateful firewall,
 * which then permits the reply.  The first packets may well be dropped by
 * the peer's filter -- that is expected.  They still open the path, so a
 * retransmission a few hundred milliseconds later gets through.
 *
 * This retry loop is what makes the code tolerate the strictest filtering
 * behaviour (address- and port-dependent, "port-restricted cone"), so we
 * do not need to detect the filtering type at all.
 *
 * Requires only POSIX sockets and pthreads.
 */

typedef struct {
    int sockfd;                 /* bound UDP socket; the same one used for STUN */
    struct sockaddr_in peer;    /* peer address learned from signalling */

    int burst_interval_ms;      /* gap between retransmissions (200-300 works) */
    int overall_timeout_ms;     /* keep trying for this long */

    /* Optional: wait until this absolute time (ms since epoch) before the
     * first packet.  Requires synchronised clocks, so it is usually better
     * to leave this at 0 and let the signalling layer trigger both sides. */
    uint64_t start_at_epoch_ms;

    /* 12-byte token shared out-of-band via the signalling channel.  It is
     * embedded in every punch packet and checked on receipt.
     *
     * This exists so that a stray packet from an unrelated host cannot be
     * mistaken for the peer.  It is NOT authentication: the token travels
     * in clear text.  Verify the peer cryptographically in your
     * application handshake once the path is open. */
    uint8_t session_token[12];
} holepunch_config_t;

typedef struct {
    int success;
    /* The address the peer's packets actually arrived from.  This can
     * differ from cfg->peer if the peer's NAT allocated a different
     * mapping than the one signalling advertised -- common on carrier-grade
     * NAT.  Always use this value afterwards, not the one you signalled. */
    struct sockaddr_in confirmed_peer;
} holepunch_result_t;

/* Blocking.  Returns 0 when the function ran to completion; check
 * result->success to see whether a path was established. */
int holepunch_run(const holepunch_config_t *cfg, holepunch_result_t *result);

/* Keep the NAT mapping and firewall state alive after the path is open.
 *
 * Pick an interval well below the shortest timeout on the path.  Linux
 * conntrack defaults to 30 s for unconfirmed UDP flows and 120 s once
 * traffic has been seen in both directions; carrier NATs are often much
 * more aggressive.  15 s is a reasonable default.
 */
int holepunch_start_keepalive(int sockfd, struct sockaddr_in peer,
                              const uint8_t session_token[12], int interval_ms);

void holepunch_stop_keepalive(void);

/* True if the datagram is one of ours (punch / ack / keepalive) rather
 * than application data.  Keepalives keep flowing on the same socket after
 * the connection is up, so the receive path must filter them out. */
int holepunch_is_control_packet(const void *buf, size_t len);

#endif
