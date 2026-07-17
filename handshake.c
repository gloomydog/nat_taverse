#include "handshake.h"

#include <string.h>
#include <sodium.h>

#define CTX_TRAFFIC "nt-traff"

/* Domain-separates this handshake's CPace generator from any other use
 * of psk elsewhere (psk is already context-separated at derivation time
 * in crypto.c; this is defense in depth on top of that). */
#define CPACE_CHANNEL_ID "nt-handshake-v1"

int hs_start(hs_state_t *st, const uint8_t psk[NT_PSK_LEN],
             uint8_t out_msg1[HS_MSG1_LEN]) {
    memset(st, 0, sizeof(*st));

    if (cpace_init(&st->cpace, (const char *)psk, NT_PSK_LEN,
                   CPACE_CHANNEL_ID, sizeof(CPACE_CHANNEL_ID) - 1, 0) != 0)
        return -1;

    memcpy(out_msg1, st->cpace.my_point, CPACE_POINTBYTES);
    return 0;
}

int hs_process_msg1(hs_state_t *st, const uint8_t msg1[HS_MSG1_LEN],
                    uint8_t out_msg2[HS_MSG2_LEN]) {
    /* Reject our own message echoed back, which would otherwise let an
     * attacker reflect it and have us derive a key with ourselves. */
    if (sodium_memcmp(msg1, st->cpace.my_point, CPACE_POINTBYTES) == 0)
        return -1;

    /* Both sides must land on the same A/B labelling, so order by
     * comparing the two points rather than by who sent first. Note: a
     * wrong passphrase is not detectable here - every point is valid
     * regardless of password, by construction. That only surfaces at
     * confirmation (hs_process_msg2). */
    st->is_lo = sodium_compare(st->cpace.my_point, msg1, CPACE_POINTBYTES) < 0;
    st->cpace.is_initiator = st->is_lo;

    if (cpace_derive_session_key(&st->cpace, msg1) != 0)
        return -1;   /* rejects the identity element / invalid points */

    memcpy(st->master, st->cpace.session_key, sizeof(st->master));
    st->have_master = 1;

    cpace_compute_confirmation(&st->cpace, st->is_lo ? "A" : "B", out_msg2);
    return 0;
}

int hs_process_msg2(hs_state_t *st, const uint8_t msg2[HS_MSG2_LEN],
                    hs_session_t *out) {
    if (!st->have_master) return -1;

    /* The peer confirms with the opposite role to ours. */
    uint8_t expect[CPACE_MACBYTES];
    cpace_compute_confirmation(&st->cpace, st->is_lo ? "B" : "A", expect);
    int ok = sodium_memcmp(expect, msg2, CPACE_MACBYTES) == 0;
    sodium_memzero(expect, sizeof(expect));
    if (!ok) return -1;   /* wrong passphrase, or an active attacker */

    memset(out, 0, sizeof(*out));

    /* One key and nonce prefix per direction, so the two sides never
     * produce the same (key, nonce) pair. */
    uint8_t lo_to_hi[32], hi_to_lo[32];
    uint8_t lo_pfx[16], hi_pfx[16];
    crypto_kdf_derive_from_key(lo_to_hi, 32, 1, CTX_TRAFFIC, st->master);
    crypto_kdf_derive_from_key(hi_to_lo, 32, 2, CTX_TRAFFIC, st->master);
    crypto_kdf_derive_from_key(lo_pfx, 16, 3, CTX_TRAFFIC, st->master);
    crypto_kdf_derive_from_key(hi_pfx, 16, 4, CTX_TRAFFIC, st->master);

    if (st->is_lo) {
        memcpy(out->send_key, lo_to_hi, 32);
        memcpy(out->recv_key, hi_to_lo, 32);
        memcpy(out->send_nonce_prefix, lo_pfx, 16);
        memcpy(out->recv_nonce_prefix, hi_pfx, 16);
    } else {
        memcpy(out->send_key, hi_to_lo, 32);
        memcpy(out->recv_key, lo_to_hi, 32);
        memcpy(out->send_nonce_prefix, hi_pfx, 16);
        memcpy(out->recv_nonce_prefix, lo_pfx, 16);
    }

    sodium_memzero(lo_to_hi, sizeof(lo_to_hi));
    sodium_memzero(hi_to_lo, sizeof(hi_to_lo));
    sodium_memzero(lo_pfx, sizeof(lo_pfx));
    sodium_memzero(hi_pfx, sizeof(hi_pfx));

    out->send_counter = 0;
    out->recv_highest = 0;
    out->recv_window = 0;
    out->established = 1;

    hs_state_wipe(st);
    return 0;
}

void hs_state_wipe(hs_state_t *st) {
    sodium_memzero(st, sizeof(*st));
}

void hs_session_wipe(hs_session_t *s) {
    sodium_memzero(s, sizeof(*s));
}

/* nonce = 16-byte per-direction prefix || 64-bit counter, big endian */
static void make_nonce(const uint8_t prefix[16], uint64_t counter, uint8_t out[24]) {
    memcpy(out, prefix, 16);
    for (int i = 0; i < 8; i++)
        out[16 + i] = (uint8_t)(counter >> (56 - i * 8));
}

static void put_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - i * 8));
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

int hs_seal(hs_session_t *s, const void *plain, size_t len,
            uint8_t *out, size_t outcap) {
    if (!s->established) return -1;
    if (len > HS_MAX_PLAINTEXT) return -1;
    if (outcap < len + HS_OVERHEAD) return -1;

    /* Wrapping would reuse a nonce, which is catastrophic for the cipher.
     * At any plausible packet rate this cannot be reached, but refusing
     * costs nothing. */
    if (s->send_counter == UINT64_MAX) return -1;

    uint64_t counter = s->send_counter++;
    put_u64(out, counter);

    uint8_t nonce[24];
    make_nonce(s->send_nonce_prefix, counter, nonce);

    unsigned long long clen = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out + 8, &clen,
        plain, len,
        out, 8,              /* counter authenticated as associated data */
        NULL, nonce, s->send_key);

    sodium_memzero(nonce, sizeof(nonce));
    if (rc != 0) return -1;
    return (int)(8 + clen);
}

/* Standard sliding window. Returns 1 if the counter is acceptable. */
static int replay_check(const hs_session_t *s, uint64_t counter) {
    if (counter > s->recv_highest) return 1;

    uint64_t diff = s->recv_highest - counter;
    if (diff >= 64) return 0;                 /* too old to judge */
    if (s->recv_window & (1ULL << diff)) return 0;  /* already seen */
    return 1;
}

static void replay_commit(hs_session_t *s, uint64_t counter) {
    if (counter > s->recv_highest) {
        uint64_t shift = counter - s->recv_highest;
        s->recv_window = (shift >= 64) ? 0 : (s->recv_window << shift);
        s->recv_window |= 1ULL;
        s->recv_highest = counter;
    } else {
        s->recv_window |= 1ULL << (s->recv_highest - counter);
    }
}

int hs_open(hs_session_t *s, const uint8_t *in, size_t len,
            void *out, size_t outcap) {
    if (!s->established) return -1;
    if (len < HS_OVERHEAD) return -1;

    uint64_t counter = get_u64(in);

    /* Check before spending time on the cipher, but do not commit until
     * the tag verifies, or a forged packet could poison the window. */
    if (!replay_check(s, counter)) return -1;

    uint8_t nonce[24];
    make_nonce(s->recv_nonce_prefix, counter, nonce);

    unsigned long long plen = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        out, &plen, NULL,
        in + 8, len - 8,
        in, 8,
        nonce, s->recv_key);

    sodium_memzero(nonce, sizeof(nonce));
    if (rc != 0) return -1;
    if (plen > outcap) return -1;

    replay_commit(s, counter);
    return (int)plen;
}
