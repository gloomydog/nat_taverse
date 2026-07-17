#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"
#include "cpace.h"

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
 * Protocol: CPace (RFC 9382, ristretto255)
 * -----------------------------------------
 *
 * Symmetric, one round trip, both sides send the same message shape at
 * the same time. This fits the punching model, where there is no natural
 * client or server. Unlike a plain PSK-authenticated DH, this is a real
 * password-authenticated key exchange: the DH generator itself is derived
 * from the passphrase, so an observer who records the whole exchange gains
 * no ability to test a passphrase guess offline. Each guess costs one live
 * impersonation attempt against a peer, not a hash computation on captured
 * traffic.
 *
 *   psk = subkey of Argon2id(passphrase)
 *
 *   both:  g <- hash_to_group(psk, "nt-handshake-v1")   (cpace_init)
 *          y <- random scalar; Y = y*g
 *          send Y
 *
 *   on receipt:
 *          reject if peer's Y equals our own (reflection defense)
 *          reject if peer's Y is not a valid group element
 *          order the pair by comparing the two Y values as bytes, so both
 *          sides agree on an A/B labelling regardless of who sent first
 *          K = y * Y_peer  (= y_a*y_b*g on both sides)
 *          session_key = H(K || g || Y_A || Y_B)
 *
 *   both:  send H(key=session_key, "confirm" || own_role)
 *          verify the peer's, which proves both derived the same key from
 *          the same passphrase
 *
 * A wrong passphrase is not detectable from the first message alone -
 * every point is valid regardless of password, by construction. It only
 * surfaces at confirmation, when the MAC fails. This is expected: it is
 * what makes offline testing impossible in the first place.
 *
 * The ephemeral scalars give forward secrecy: they are discarded when the
 * session ends, so a passphrase leaking later does not decrypt recorded
 * traffic.
 *
 *
 * What this does not protect against
 * ----------------------------------
 *
 * CPace removes the offline dictionary attack against *this* exchange.
 * It does not, by itself, make the rest of the system safe for a
 * memorable passphrase: the Nostr rendezvous pubkey and the punch token
 * (crypto.c) are still derived deterministically from the same
 * Argon2id-stretched passphrase and are visible to anyone who can see the
 * relay traffic or the punch packets. Testing a passphrase guess against
 * those is still possible, just Argon2id-costed rather than impossible.
 * `nt_generate_secret()` remains the recommended way to obtain a
 * passphrase; see the README security notes.
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

#define HS_MSG1_LEN   CPACE_POINTBYTES   /* Y */
#define HS_MSG2_LEN   CPACE_MACBYTES     /* confirmation */
#define HS_OVERHEAD   (8 + 16)           /* counter + Poly1305 tag */
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

typedef struct {
    cpace_ctx cpace;
    uint8_t master[32];   /* copy of cpace.session_key once derived */
    int is_lo;             /* role, decided by comparing the two Y values */
    int have_master;
} hs_state_t;

/* Build our handshake message (our CPace public point). Call once per
 * session. */
int hs_start(hs_state_t *st, const uint8_t psk[NT_PSK_LEN],
             uint8_t out_msg1[HS_MSG1_LEN]);

/* Process the peer's point and derive the session key. A wrong
 * passphrase is not detectable here by design - see the protocol note
 * above - only a malformed or reflected point is rejected here.
 * Returns 0 on success, -1 if the point is invalid or reflected. */
int hs_process_msg1(hs_state_t *st, const uint8_t msg1[HS_MSG1_LEN],
                    uint8_t out_msg2[HS_MSG2_LEN]);

/* Check the peer's confirmation and finalise the session. This is where
 * a passphrase mismatch actually surfaces.
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
