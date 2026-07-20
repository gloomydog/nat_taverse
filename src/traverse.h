#ifndef TRAVERSE_H
#define TRAVERSE_H

#include <stdint.h>
#include "netaddr.h"
#include "stun.h"
#include "crypto.h"
#include "signaling.h"

/*
 * The whole traversal, in one call.
 *
 * netaddr / stun / candidate / holepunch are usable on their own, and an
 * application with its own ideas should reach for those. This file is the
 * assembled default: bind a socket, gather candidates, swap them with the
 * peer over whatever signalling backend you hand it, punch, retry, and
 * hand back a connected UDP socket.
 *
 *     nt_config_t cfg;
 *     nt_config_default(&cfg);
 *     memcpy(cfg.punch_key, my_shared_key, NT_PUNCH_KEY_LEN);
 *
 *     nt_session_t s;
 *     if (nt_connect(&cfg, &sig, &s) == 0) {
 *         send(s.sockfd, ...);      // socket is connect()ed to the peer
 *         nt_close(&s);
 *     }
 *
 * What you get back is a path, nothing more. The socket carries plain
 * UDP: no encryption, no authentication of what flows over it, no
 * ordering, no reliability. Run your own protocol on top. The punch key
 * proves whoever opened the path holds the shared secret, and connect()
 * means the kernel drops packets from anyone else, but neither is a
 * substitute for authenticating your own traffic.
 *
 * Retries
 * -------
 * One punch window is easy to miss: signalling latency staggers when each
 * side starts punching, and the first packets may hit a NAT mapping that
 * has not warmed yet. So a failed attempt is not the end. Before each
 * retry the candidates are re-measured and re-exchanged, which does two
 * things at once: it refreshes a reflexive port that may have drifted,
 * and the exchange doubles as a barrier both peers pass through together,
 * re-aligning their punch windows instead of letting them drift further
 * apart.
 *
 * From the second attempt on the socket is also closed and rebound to a
 * fresh ephemeral port. On carrier-CGNAT and commercial-VPN paths the
 * external port a socket is granted is endpoint-dependent luck that
 * re-STUNning cannot change: reuse the same socket and a run that drew an
 * unpunchable mapping stays unpunchable for all of its attempts. That is
 * exactly why quitting and relaunching by hand often connects when an
 * in-process retry loop will not -- a new socket draws a mapping the peer
 * has never seen. Rebinding does that without a human in the loop.
 *
 * This is why cfg.local_port only covers the first attempt (see the field
 * comment). It is an acceptable trade: rebinding only happens once the
 * fixed port has already failed.
 */

typedef struct {
    /* UDP port to bind. 0 picks a free one.
     *
     * A fixed port is worth setting if you want to name it in a firewall
     * rule, since it is the only port that can be known in advance. It
     * only applies to the first punch attempt: retries rebind to a fresh
     * ephemeral port, which no static rule can name. Those attempts rely
     * on the stateful RELATED,ESTABLISHED accept that most host firewalls
     * (ufw, firewalld, Windows Defender) already have, which is what
     * carries the punch in the common case anyway. Set rebind_on_retry to
     * 0 if you are behind a genuinely stateless firewall and need every
     * attempt to land on the port you opened. */
    uint16_t local_port;

    int punch_attempts;      /* punch windows before giving up (5)      */
    int punch_timeout_ms;    /* length of one punch window (10000)      */
    int rebind_on_retry;     /* fresh ephemeral port per retry (1)      */
    int stun_timeout_ms;     /* per STUN server (2000)                  */
    int sync_timeout_ms;     /* per-retry candidate re-exchange (5000)  */
    int discovery_timeout_ms;/* how long to wait for the peer (120000)  */
    int keepalive_ms;        /* 0 disables; see nt_session_t (15000)    */
    int verbose;             /* progress to stderr                      */

    /* MAC key for the punch. Must match on both peers and must be a real
     * shared secret established before punching. See holepunch.h. */
    uint8_t punch_key[NT_PUNCH_KEY_LEN];
} nt_config_t;

typedef struct {
    /* Connected UDP socket, ready for send() and recv(). Owned by the
     * session: nt_close() closes it. */
    int sockfd;

    netaddr_t  peer;      /* where the peer's packets actually came from */
    netaddr_t  local;     /* our bound address                           */
    nat_type_t nat;       /* diagnostic only; see stun.h                 */
    int        attempts_used;

    /* Set when keepalive_ms was non-zero. The keepalive keeps sending
     * punch packets on this socket, so a reader must drop them with
     * holepunch_is_control_packet() rather than treat them as data. */
    int keepalive_running;
} nt_session_t;

/* Fill cfg with the defaults quoted above. punch_key is zeroed; set it
 * yourself before calling nt_connect. */
void nt_config_default(nt_config_t *cfg);

/* Run the whole traversal. Returns 0 on success.
 *
 * sig is used for the candidate exchange and is not closed here -- the
 * caller owns it, and may want it afterwards. It must stay open for the
 * duration, since every retry re-exchanges through it.
 *
 * On failure nothing is left behind: the socket is closed. The common
 * cause is both peers behind symmetric NAT, where no direct path exists to
 * find and only a relay would help. */
int nt_connect(const nt_config_t *cfg, signaling_backend_t *sig,
               nt_session_t *out);

/* Stop the keepalive and close the socket. Safe to call on a zeroed
 * session. */
void nt_close(nt_session_t *s);

#endif
