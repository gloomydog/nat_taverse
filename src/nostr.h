#ifndef NOSTR_H
#define NOSTR_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

/*
 * Minimal Nostr (NIP-01) client -- only what signalling needs:
 *   - key derivation from a shared secret
 *   - event serialisation and id computation (SHA-256)
 *   - Schnorr signatures (BIP-340, via libsecp256k1)
 *   - EVENT publish / REQ subscribe
 *
 * Kinds 20000-29999 are "ephemeral": relays forward them but do not store
 * them.  Signalling data is worthless a few seconds later, so that is
 * exactly the range we want.
 */

#define NOSTR_SECKEY_LEN 32
#define NOSTR_PUBKEY_LEN 32   /* x-only pubkey (BIP-340) */
#define NOSTR_ID_LEN     32
#define NOSTR_SIG_LEN    64

/* our ephemeral event kind */
#define NOSTR_KIND_SIGNAL 20117

typedef struct {
    uint8_t seckey[NOSTR_SECKEY_LEN];
    uint8_t pubkey[NOSTR_PUBKEY_LEN];   /* x-only, BIP-340 */
    uint8_t enckey[32];                 /* payload encryption */
} nostr_identity_t;

/* Turn derived key material into a Nostr identity.
 *
 * Both peers derive the same signing key from the same passphrase. To a
 * relay they look like one identity posting twice, which is exactly what
 * makes the rendezvous work: each side subscribes with an `authors`
 * filter on that pubkey and sees the other's events. The meeting point is
 * the pubkey itself.
 *
 * This proves knowledge of the passphrase and nothing more. It is not
 * peer authentication; anyone holding the passphrase can join the
 * rendezvous, and this library has no notion of identity beyond it. An
 * application that needs to know *who* is on the far end must establish
 * that itself, over the path once it is open.
 *
 * The encryption key is separate, so a signing key leak does not expose
 * previously published addresses.
 *
 * Returns 0 on success. */
int nostr_identity_from_keys(const nt_keys_t *keys, nostr_identity_t *out);

void nostr_identity_wipe(nostr_identity_t *id);

/* Encrypt and base64-encode a payload (ChaCha20-Poly1305).
 * Mandatory: whatever goes in `content` is world-readable on the relay.
 * Returns 0 on success. */
int nostr_encrypt_payload(const nostr_identity_t *id,
                           const void *plain, size_t plen,
                           char *out_b64, size_t outlen);

/* Decrypt. Returns the plaintext length, or -1 on failure -- which also
 * covers tampering, since the AEAD tag is verified. */
int nostr_decrypt_payload(const nostr_identity_t *id,
                           const char *b64,
                           void *out, size_t maxlen);

/* Build a signed EVENT object.  content_b64 comes from
 * nostr_encrypt_payload().  Returns 0 on success. */
int nostr_build_event(const nostr_identity_t *id, int kind,
                       const char *content_b64,
                       char *out_json, size_t outlen);

/* Wrap an event as ["EVENT", <event>] for publishing. */
int nostr_build_publish(const char *event_json, char *out, size_t outlen);

/* Build ["REQ", <subid>, {"kinds":[...],"authors":[...],"since":...}]. */
int nostr_build_req(const nostr_identity_t *id, int kind, const char *subid,
                     int64_t since, char *out, size_t outlen);

/* If msg is ["EVENT", subid, {...}], extract its content field.
 * Returns 0 on success, -1 if the message is not an event. */
int nostr_extract_content(const char *msg, char *out_content, size_t outlen);

#endif
