#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/*
 * Key material for NAT traversal, derived from one passphrase.
 *
 * This library does not authenticate or encrypt application data -- that
 * is the caller's business. Only two things here need keys, and both are
 * part of getting the path open:
 *
 *   punch_key   MACs every hole punch packet, so a stray, forged, or
 *               replayed datagram cannot be mistaken for the peer. See
 *               holepunch.h.
 *   nostr_*     the signalling identity the two peers meet at, and the
 *               key their candidate lists are sealed under, so a public
 *               relay does not carry addresses in clear text. See nostr.h.
 *
 * Both peers must arrive at identical keys from the same passphrase with
 * nothing exchanged beforehand, so derivation is deterministic: Argon2id
 * stretches the passphrase once, then crypto_kdf splits the result into
 * independent subkeys. A leak of one tells you nothing about the others.
 *
 * Nothing forces you to use this file. The punch key is just 32 bytes; an
 * application that already has a shared secret -- from its own key
 * exchange, a PAKE, a TLS exporter -- should derive the punch key from
 * that and skip nt_derive_keys() entirely. holepunch.h takes a key rather
 * than a passphrase precisely so that choice stays open.
 *
 * Argon2id makes each passphrase guess cost real time and memory, but it
 * only buys a fixed factor: a guessable passphrase is still guessable.
 * Use nt_generate_secret() and treat the result like an SSH private key.
 */

#define NT_MASTER_LEN      32
#define NT_PUNCH_KEY_LEN   32   /* MAC key for hole punch packets */
#define NT_SEED_LEN        32   /* Nostr signing key seed         */
#define NT_CONTENT_KEY_LEN 32   /* Nostr payload encryption       */

typedef struct {
    uint8_t master[NT_MASTER_LEN];
    uint8_t punch_key[NT_PUNCH_KEY_LEN];
    uint8_t nostr_seed[NT_SEED_LEN];
    uint8_t nostr_content_key[NT_CONTENT_KEY_LEN];
} nt_keys_t;

/* Must be called once before anything else here. Returns 0 on success. */
int nt_crypto_init(void);

/* Stretch the passphrase and derive every subkey.
 *
 * Deliberately slow: expect a noticeable pause on a laptop. Both peers
 * must use identical parameters, so the cost is compiled in rather than
 * negotiated.
 *
 * Returns 0 on success, -1 if Argon2id could not allocate memory. */
int nt_derive_keys(const char *passphrase, nt_keys_t *out);

/* Wipe the struct. Call when done. */
void nt_keys_wipe(nt_keys_t *k);

void nt_random(void *buf, size_t len);
void nt_wipe(void *buf, size_t len);

/* Generate a passphrase with 128 bits of entropy, formatted as words for
 * transcription. buf should be at least 96 bytes. */
void nt_generate_secret(char *buf, size_t buflen);

#endif
