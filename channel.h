#ifndef CHANNEL_H
#define CHANNEL_H

#include <stdint.h>
#include <stddef.h>
#include "netaddr.h"
#include "crypto.h"
#include "handshake.h"

/*
 * Runs the handshake over a punched UDP path and carries encrypted
 * application data afterwards.
 *
 * Framing
 * -------
 * Everything on the socket is multiplexed by a leading type byte:
 *
 *   0x10  handshake message 1
 *   0x11  handshake message 2
 *   0x12  encrypted data
 *
 * Punch and keepalive packets are shaped like STUN, so their first byte
 * is 0x00 or 0x01. Choosing type bytes outside that range keeps the two
 * unambiguous, rather than relying on probabilistic checks against the
 * STUN magic cookie, which a random ephemeral public key could match by
 * chance.
 *
 * Retransmission
 * --------------
 * The handshake is two round trips over UDP, so any message can be lost.
 * Both sides resend until they see what they need, which also handles the
 * two peers reaching this point a little apart.
 */

#define CH_TYPE_HS1  0x10
#define CH_TYPE_HS2  0x11
#define CH_TYPE_DATA 0x12

#define CH_MAX_PLAINTEXT HS_MAX_PLAINTEXT

/* Authenticate the peer and establish session keys.
 *
 * Blocking. Retransmits until it succeeds or timeout_ms elapses.
 *
 * Returns 0 on success. -1 means the peer never completed, or never
 * proved it holds the passphrase, in which case whoever is on the other
 * end of the path is not who you wanted. */
int channel_handshake(int sockfd, const netaddr_t *peer,
                      const uint8_t psk[NT_PSK_LEN],
                      int timeout_ms, hs_session_t *out);

/* Encrypt and send. Returns 0 on success. */
int channel_send(int sockfd, const netaddr_t *peer, hs_session_t *s,
                 const void *data, size_t len);

/* Receive and decrypt.
 *
 * Returns the plaintext length, 0 on timeout or if the datagram was not
 * application data (a keepalive, say, or a forgery), and -1 on a socket
 * error. Anything that fails to authenticate is silently dropped: an
 * attacker who can reach the port should not be able to make us do
 * anything by sending noise. */
int channel_recv(int sockfd, hs_session_t *s, void *out, size_t outcap,
                 int timeout_ms);

#endif
