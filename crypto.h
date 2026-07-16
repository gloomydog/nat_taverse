#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/*
 * All key material in this project comes from one passphrase, stretched
 * once with Argon2id and then split into independent subkeys.
 *
 * Why Argon2id and not a plain hash: the passphrase is the only secret,
 * and parts of the protocol are unavoidably offline-attackable. An
 * observer who captures a handshake can test passphrase guesses against
 * it without talking to anyone. Argon2id makes each guess cost real time
 * and memory, which is the difference between a wordlist falling in
 * seconds and it not being worth attempting.
 *
 * That said, stretching only buys a fixed factor. A guessable passphrase
 * is still guessable. Use nt_generate_secret() and treat the result as
 * you would an SSH private key. See the security notes in the README.
 */

#define NT_MASTER_LEN     32
#define NT_TOKEN_LEN      12   /* punch packet token */
#define NT_RENDEZVOUS_LEN 32   /* meeting id for relay_server */
#define NT_SEED_LEN       32   /* Nostr signing key seed */
#define NT_CONTENT_KEY_LEN 32  /* Nostr payload encryption */
#define NT_PSK_LEN        32   /* handshake pre-shared key */

typedef struct {
    uint8_t master[NT_MASTER_LEN];
    uint8_t token[NT_TOKEN_LEN];
    uint8_t rendezvous[NT_RENDEZVOUS_LEN];
    uint8_t nostr_seed[NT_SEED_LEN];
    uint8_t nostr_content_key[NT_CONTENT_KEY_LEN];
    uint8_t psk[NT_PSK_LEN];
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

/* Constant-time comparison. Returns 1 when equal.
 *
 * Never use memcmp on secrets: it returns early on the first differing
 * byte, which leaks how much of a guess was correct. */
int nt_equal(const void *a, const void *b, size_t len);

void nt_random(void *buf, size_t len);
void nt_wipe(void *buf, size_t len);

/* Generate a passphrase with 128 bits of entropy, formatted as words for
 * transcription. buf should be at least 96 bytes. */
void nt_generate_secret(char *buf, size_t buflen);

#endif
