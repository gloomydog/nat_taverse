#ifndef HOLEPUNCH_H
#define HOLEPUNCH_H

#include <stdint.h>
#include <stddef.h>
#include "netaddr.h"
#include "crypto.h"

/*
 * UDP hole punching by simultaneous transmission, IPv4 and IPv6.
 *
 * Both peers send to each other at roughly the same time. Each outbound
 * packet creates state in the sender's own NAT and stateful firewall,
 * which then lets the reply through. The first packets are expected to be
 * dropped by the peer's filter; they still open the path, so a
 * retransmission a few hundred milliseconds later gets through.
 *
 * Retrying like this covers the strictest filtering behaviour (address
 * and port dependent), which is why the filtering type never needs to be
 * detected.
 *
 * Multiple candidates
 * -------------------
 * A host often has more than one way to be reached: an IPv4 address via
 * NAT and a global IPv6 address, say. Rather than guessing which will
 * work, punch all of them at once and keep whichever answers first. IPv6
 * usually wins when both are available, since there is no NAT in the way,
 * only a firewall to open.
 *
 * Requires POSIX sockets, pthreads, and libsodium (for constant-time
 * token comparison).
 */

#define HP_MAX_CANDIDATES 8

typedef struct {
    int sockfd;                  /* bound socket, same one used for STUN */

    netaddr_t peers[HP_MAX_CANDIDATES];  /* candidates from signalling */
    int npeers;

    int burst_interval_ms;       /* gap between rounds; 200-300 works */
    int overall_timeout_ms;      /* keep trying this long */

    /* Token from nt_derive_keys(), embedded in every punch packet and
     * checked on receipt.
     *
     * This only stops an unrelated datagram being mistaken for the peer.
     * It is not authentication: it travels in clear text, and anyone who
     * captures one packet can replay it. Run hs_* over the path
     * afterwards to actually authenticate and encrypt. */
    uint8_t session_token[NT_TOKEN_LEN];
} holepunch_config_t;

typedef struct {
    int success;
    /* Where the peer's packets actually came from. This can differ from
     * every candidate we were given, because the peer's NAT may allocate
     * a different mapping toward us than the one it advertised. Common on
     * carrier NAT. Always use this afterwards. */
    netaddr_t confirmed_peer;
} holepunch_result_t;

/* Blocking. Returns 0 when it ran to completion; check result->success. */
int holepunch_run(const holepunch_config_t *cfg, holepunch_result_t *result);

/* Keep the NAT mapping and firewall state alive once the path is open.
 *
 * Use an interval well under the shortest timeout on the path. Linux
 * conntrack defaults to 30s for unconfirmed UDP and 120s once traffic has
 * been seen both ways; carrier NATs are often far more aggressive. 15s is
 * a reasonable default. */
int holepunch_start_keepalive(int sockfd, const netaddr_t *peer,
                              const uint8_t session_token[NT_TOKEN_LEN],
                              int interval_ms);
void holepunch_stop_keepalive(void);

/* True for our own punch, ack, and keepalive packets. Keepalives keep
 * flowing on the same socket after the path is up, so the receive path
 * must filter them out from application data. */
int holepunch_is_control_packet(const void *buf, size_t len);

#endif
