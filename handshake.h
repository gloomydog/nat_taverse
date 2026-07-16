#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

/*
 * Mutual authentication and an encrypted channel, run over a UDP path
 * once hole punching has opened one.
 *
 * This matters more than it might look. Punching gets you a path, nothing
 * else: no idea who is on the other end, no confidentiality, no
 * integrity. The punch token is a filter against stray datagrams, not a
 * secret worth anything, and it travels in clear. Without a handshake,
 * anyone who can reach the port can talk to you and anyone on the path
 * can read and rewrite what you send.
 *
 *
 * Protocol
 * --------
 *
 * Symmetric, one round trip, both sides send the same message shape at
 * the same time. This fits the punching model, where there is no natural
 * client or server.
 *
 *   psk = subkey of Argon2id(passphrase)
 *
 *   both:  e_priv, e_pub <- fresh X25519 keypair, per session
 *          n <- 16 random bytes
 *          tag = BLAKE2b(key=psk, "nt-hs-commit-v1" || e_pub || n)
 *          send  e_pub || n || tag
 *
 *   on receipt:
 *          verify tag                          (peer knows the psk)
 *          dh = X25519(e_priv, peer_e_pub)
 *          order the two (e_pub, n) pairs by e_pub bytes so both sides
 *          build an identical transcript regardless of who is who
 *          master = BLAKE2b(key=psk, dh || transcript)
 *          k_lo->hi, k_hi->lo = subkeys of master
 *
 *   both:  send BLAKE2b(key=master, "nt-hs-confirm-v1" || own_role)
 *          verify the peer's, which proves both derived the same master
 *
 * The ephemeral keys give forward secrecy: they are discarded when the
 * session ends, so a passphrase leaking later does not decrypt recorded
 * traffic. The tag gives mutual authentication, since only a psk holder
 * can produce one. Confirmation catches a key mismatch immediately
 * instead of leaving it to fail confusingly later.
 *
 *
 * What this does not protect against
 * ----------------------------------
 *
 * An observer who captures a handshake can test passphrase guesses
 * against the tag offline, at their leisure, without contacting anyone.
 * Argon2id makes each guess expensive but does not change the shape of
 * the attack. A password-authenticated key exchange such as CPace closes
 * this properly, at the cost of a much larger and easier to misimplement
 * protocol.
 *
 * The mitigation here is to make guessing pointless: generate the
 * passphrase with nt_generate_secret() and transfer it the way you would
 * an SSH key. A guessable passphrase is not safe here regardless of how
 * much stretching sits behind it.
 *
 *
 * Transport
 * ---------
 *
 * XChaCha20-Poly1305, one key per direction. The nonce is a 16-byte
 * per-direction prefix from the KDF plus a 64-bit counter, so nonces
 * never repeat and never collide between directions. The counter is sent
 * in the clear and authenticated as associated data.
 *
 * Datagrams can be lost, reordered, or replayed by an attacker, so the
 * receiver keeps a sliding window of recently seen counters and rejects
 * anything already accepted or too old, the same approach IPsec and
 * WireGuard use.
 */

#define HS_MSG1_LEN   (32 + 16 + 16)   /* e_pub || nonce || tag */
#define HS_MSG2_LEN   32               /* confirmation */
#define HS_OVERHEAD   (8 + 16)         /* counter + Poly1305 tag */
#define HS_MAX_PLAINTEXT 1024

typedef struct {
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint8_t  send_nonce_prefix[16];
    uint8_t  recv_nonce_prefix[16];
    uint64_t send_counter;

    /* Anti-replay: highest counter accepted, plus a bitmap of the 64
     * below it. */
    uint64_t recv_highest;
    uint64_t recv_window;

    int established;
} hs_session_t;

/* Build our handshake message. Call once per session.
 *
 * st carries the ephemeral private key between the two steps and must
 * live until hs_process_msg1() returns. */
typedef struct {
    uint8_t e_priv[32];
    uint8_t e_pub[32];
    uint8_t nonce[16];
    uint8_t master[32];
    int is_lo;          /* role, decided by comparing public keys */
    int have_master;
} hs_state_t;

int hs_start(hs_state_t *st, const uint8_t psk[NT_PSK_LEN],
             uint8_t out_msg1[HS_MSG1_LEN]);

/* Verify the peer's message and derive the session keys.
 * Returns 0 on success, -1 if the tag does not verify, which means the
 * sender does not hold the passphrase. */
int hs_process_msg1(hs_state_t *st, const uint8_t psk[NT_PSK_LEN],
                    const uint8_t msg1[HS_MSG1_LEN],
                    uint8_t out_msg2[HS_MSG2_LEN]);

/* Check the peer's confirmation and finalise the session.
 * Returns 0 on success, -1 on mismatch. */
int hs_process_msg2(hs_state_t *st, const uint8_t msg2[HS_MSG2_LEN],
                    hs_session_t *out);

void hs_state_wipe(hs_state_t *st);
void hs_session_wipe(hs_session_t *s);

/* Encrypt. out needs len + HS_OVERHEAD bytes.
 * Returns the ciphertext length, or -1. */
int hs_seal(hs_session_t *s, const void *plain, size_t len,
            uint8_t *out, size_t outcap);

/* Decrypt and check for replay. out needs len bytes.
 * Returns the plaintext length, or -1 if forged, corrupted, or replayed. */
int hs_open(hs_session_t *s, const uint8_t *in, size_t len,
            void *out, size_t outcap);

#endif
