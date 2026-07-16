#include "handshake.h"

#include <string.h>
#include <arpa/inet.h>
#include <sodium.h>

#define LBL_COMMIT  "nt-hs-commit-v1"
#define LBL_MASTER  "nt-hs-master-v1"
#define LBL_CONFIRM "nt-hs-confirm-v1"

#define CTX_TRAFFIC "nt-traff"

/* tag = BLAKE2b(key=psk, LBL_COMMIT || e_pub || nonce) */
static void commit_tag(const uint8_t psk[NT_PSK_LEN],
                       const uint8_t e_pub[32], const uint8_t nonce[16],
                       uint8_t out[16]) {
    crypto_generichash_state h;
    crypto_generichash_init(&h, psk, NT_PSK_LEN, 16);
    crypto_generichash_update(&h, (const uint8_t *)LBL_COMMIT, sizeof(LBL_COMMIT) - 1);
    crypto_generichash_update(&h, e_pub, 32);
    crypto_generichash_update(&h, nonce, 16);
    crypto_generichash_final(&h, out, 16);
    sodium_memzero(&h, sizeof(h));
}

static void confirm_tag(const uint8_t master[32], int is_lo, uint8_t out[32]) {
    uint8_t role = is_lo ? 0 : 1;
    crypto_generichash_state h;
    crypto_generichash_init(&h, master, 32, 32);
    crypto_generichash_update(&h, (const uint8_t *)LBL_CONFIRM, sizeof(LBL_CONFIRM) - 1);
    crypto_generichash_update(&h, &role, 1);
    crypto_generichash_final(&h, out, 32);
    sodium_memzero(&h, sizeof(h));
}

int hs_start(hs_state_t *st, const uint8_t psk[NT_PSK_LEN],
             uint8_t out_msg1[HS_MSG1_LEN]) {
    memset(st, 0, sizeof(*st));

    crypto_box_keypair(st->e_pub, st->e_priv);
    randombytes_buf(st->nonce, sizeof(st->nonce));

    memcpy(out_msg1, st->e_pub, 32);
    memcpy(out_msg1 + 32, st->nonce, 16);
    commit_tag(psk, st->e_pub, st->nonce, out_msg1 + 48);
    return 0;
}

int hs_process_msg1(hs_state_t *st, const uint8_t psk[NT_PSK_LEN],
                    const uint8_t msg1[HS_MSG1_LEN],
                    uint8_t out_msg2[HS_MSG2_LEN]) {
    const uint8_t *peer_pub = msg1;
    const uint8_t *peer_nonce = msg1 + 32;
    const uint8_t *peer_tag = msg1 + 48;

    uint8_t expect[16];
    commit_tag(psk, peer_pub, peer_nonce, expect);
    if (sodium_memcmp(expect, peer_tag, 16) != 0) {
        sodium_memzero(expect, sizeof(expect));
        return -1;   /* not someone who holds the passphrase */
    }
    sodium_memzero(expect, sizeof(expect));

    /* Reject our own message echoed back, which would otherwise let an
     * attacker reflect it and have us derive a key with ourselves. */
    if (sodium_memcmp(peer_pub, st->e_pub, 32) == 0) return -1;

    uint8_t dh[32];
    if (crypto_scalarmult(dh, st->e_priv, peer_pub) != 0) {
        sodium_memzero(dh, sizeof(dh));
        return -1;   /* rejects low-order points */
    }

    /* Both sides must hash the same transcript, so order the two
     * contributions by public key rather than by who sent first. */
    st->is_lo = sodium_compare(st->e_pub, peer_pub, 32) < 0;

    const uint8_t *lo_pub   = st->is_lo ? st->e_pub   : peer_pub;
    const uint8_t *lo_nonce = st->is_lo ? st->nonce   : peer_nonce;
    const uint8_t *hi_pub   = st->is_lo ? peer_pub    : st->e_pub;
    const uint8_t *hi_nonce = st->is_lo ? peer_nonce  : st->nonce;

    crypto_generichash_state h;
    crypto_generichash_init(&h, psk, NT_PSK_LEN, 32);
    crypto_generichash_update(&h, (const uint8_t *)LBL_MASTER, sizeof(LBL_MASTER) - 1);
    crypto_generichash_update(&h, dh, 32);
    crypto_generichash_update(&h, lo_pub, 32);
    crypto_generichash_update(&h, lo_nonce, 16);
    crypto_generichash_update(&h, hi_pub, 32);
    crypto_generichash_update(&h, hi_nonce, 16);
    crypto_generichash_final(&h, st->master, 32);

    sodium_memzero(&h, sizeof(h));
    sodium_memzero(dh, sizeof(dh));

    /* The private key has done its job; drop it now so it cannot leak
     * from memory later in the session. */
    sodium_memzero(st->e_priv, sizeof(st->e_priv));

    st->have_master = 1;
    confirm_tag(st->master, st->is_lo, out_msg2);
    return 0;
}

int hs_process_msg2(hs_state_t *st, const uint8_t msg2[HS_MSG2_LEN],
                    hs_session_t *out) {
    if (!st->have_master) return -1;

    /* The peer confirms with the opposite role to ours. */
    uint8_t expect[32];
    confirm_tag(st->master, !st->is_lo, expect);
    int ok = sodium_memcmp(expect, msg2, 32) == 0;
    sodium_memzero(expect, sizeof(expect));
    if (!ok) return -1;

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
