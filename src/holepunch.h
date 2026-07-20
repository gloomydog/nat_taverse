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
 * retransmission a moment later gets through.
 *
 * Retrying like this covers the strictest filtering behaviour (address
 * and port dependent), which is why the filtering type never needs to be
 * detected.
 *
 * Multiple candidates
 * -------------------
 * A host often has more than one way to be reached: a LAN address, an
 * IPv4 address via NAT, a global IPv6 address. Rather than guessing which
 * will work, punch all of them at once and keep whichever answers first.
 * IPv6 and same-LAN paths usually win when available -- no NAT round trip,
 * only a firewall to open.
 *
 * Authentication
 * --------------
 * Every packet carries a crypto_auth MAC over its header, keyed by
 * cfg.punch_key. So the punch is authenticated: an observer cannot forge
 * or inject one, and only a peer holding the key can open the path.
 * Stray datagrams, replayed captures, and stray real STUN responses all
 * fail the MAC and are dropped.
 *
 * The key must therefore be a real shared secret established *before*
 * punching -- over the signalling channel, typically. nt_derive_keys()
 * produces one from a passphrase; an application with its own key
 * exchange should feed in a key from that instead. See crypto.h.
 *
 * What this does not give you: the punch authenticates the *path*, not
 * the application data that follows. Anyone holding the punch key is
 * treated as the peer, and nothing here encrypts your traffic. If that
 * matters, run your own authenticated, encrypted protocol over the socket
 * afterwards -- this library deliberately stops at the open path.
 *
 * Requires POSIX sockets, pthreads, and libsodium.
 */

#define HP_MAX_CANDIDATES 8

/* Wire size of a punch packet. Exposed so a receive path can size a
 * buffer or cheaply reject by length. */
#define HP_PACKET_LEN 52

typedef struct {
    int sockfd;                  /* bound socket, same one used for STUN */

    netaddr_t peers[HP_MAX_CANDIDATES];  /* candidates from signalling */
    int npeers;

    int resend_interval_ms;      /* gap between rounds; 60 is a good default */
    int overall_timeout_ms;      /* keep trying this long */

    /* MAC key for every punch, ack, and keepalive packet. Must match on
     * both peers, and must not be public: see the note above. */
    uint8_t punch_key[NT_PUNCH_KEY_LEN];
} holepunch_config_t;

typedef struct {
    int success;
    /* Where the peer's packets actually came from. This can differ from
     * every candidate we were given, because the peer's NAT may allocate
     * a different mapping toward us than the one it advertised. Common on
     * carrier NAT, and that mapping is the only address that works.
     * Always use this afterwards. */
    netaddr_t confirmed_peer;
} holepunch_result_t;

/* Punch every candidate in parallel until one confirms.
 *
 * Blocking. Returns 0 when it ran to completion; check result->success.
 *
 * On success the socket is connect()ed to the confirmed peer, which locks
 * the flow: the kernel then drops anything from another source, so later
 * reads cannot be spoofed by an off-path sender who guesses the port, and
 * the socket can be used with plain send() and recv().
 *
 * A single failed attempt is often just a near miss -- the two punch
 * windows only partly overlapped, or the first packets hit a NAT mapping
 * that had not warmed yet. Calling this again is worthwhile, and better
 * still after re-running STUN and re-exchanging candidates; see
 * traverse.h, which does exactly that. */
int holepunch_run(const holepunch_config_t *cfg, holepunch_result_t *result);

/* Keep the NAT mapping and firewall state alive once the path is open.
 *
 * sockfd must be the connect()ed socket holepunch_run() returned with.
 *
 * Use an interval well under the shortest timeout on the path. Linux
 * conntrack defaults to 30s for unconfirmed UDP and 120s once traffic has
 * been seen both ways; carrier NATs are often far more aggressive. 15s is
 * a reasonable default.
 *
 * This doubles as continued punching: a peer that has not confirmed yet
 * will confirm on the next keepalive it receives, which is what lets one
 * side move on while the other is still in its punch loop. */
int holepunch_start_keepalive(int sockfd,
                              const uint8_t punch_key[NT_PUNCH_KEY_LEN],
                              int interval_ms);
void holepunch_stop_keepalive(void);

/* True for our own punch, ack, and keepalive packets.
 *
 * Keepalives keep flowing on the same socket after the path is up, so an
 * application reading from that socket must filter them out rather than
 * handing them to its own parser. Shape only -- it does not verify the
 * MAC, so treat the answer as "not application data", never as
 * "authentic". */
int holepunch_is_control_packet(const void *buf, size_t len);

#endif
