#include "cpace.h"
#include <string.h>

/* Domain separation labels, mixed into every hash computation. */
#define DSI_GENERATOR "CPaceRistretto255-v1-generator"
#define DSI_SESSKEY   "CPaceRistretto255-v1-sesskey"
#define DSI_CONFIRM   "CPaceRistretto255-v1-confirm"

/* Derives the ristretto255 generator g from a 64-byte hash value.
 * Corresponds to generate_generator() in RFC 9382.
 * room_code (the weak password) and room_id (the channel identifier) are
 * fed in separately, so the same room_code in a different room_id yields
 * a different group element. */
static int derive_generator(uint8_t out[CPACE_POINTBYTES],
                             const char *room_code, size_t room_code_len,
                             const char *room_id,   size_t room_id_len)
{
    crypto_hash_sha512_state st;
    uint8_t h[crypto_hash_sha512_BYTES]; /* 64 bytes */
    uint64_t len_be;

    if (crypto_hash_sha512_init(&st) != 0) return -1;

    crypto_hash_sha512_update(&st, (const uint8_t *)DSI_GENERATOR, strlen(DSI_GENERATOR));

    len_be = (uint64_t)room_code_len;
    crypto_hash_sha512_update(&st, (const uint8_t *)&len_be, sizeof(len_be));
    crypto_hash_sha512_update(&st, (const uint8_t *)room_code, room_code_len);

    len_be = (uint64_t)room_id_len;
    crypto_hash_sha512_update(&st, (const uint8_t *)&len_be, sizeof(len_be));
    crypto_hash_sha512_update(&st, (const uint8_t *)room_id, room_id_len);

    if (crypto_hash_sha512_final(&st, h) != 0) return -1;

    /* from_hash maps a 64-byte uniformly random value uniformly onto a
     * point of the group (Elligator2-based), so nobody can know the
     * discrete log of g. */
    crypto_core_ristretto255_from_hash(out, h);
    sodium_memzero(h, sizeof(h));
    return 0;
}

int cpace_init(cpace_ctx *ctx,
                const char *room_code, size_t room_code_len,
                const char *room_id,   size_t room_id_len,
                int is_initiator)
{
    if (sodium_init() < 0) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->is_initiator = is_initiator;

    if (derive_generator(ctx->generator, room_code, room_code_len, room_id, room_id_len) != 0)
        return -1;

    /* Generate our own secret scalar with the CSPRNG. */
    crypto_core_ristretto255_scalar_random(ctx->my_scalar);

    /* Y = y * g */
    if (crypto_scalarmult_ristretto255(ctx->my_point, ctx->my_scalar, ctx->generator) != 0)
        return -1;

    return 0;
}

int cpace_derive_session_key(cpace_ctx *ctx, const uint8_t peer_point[CPACE_POINTBYTES])
{
    uint8_t shared[CPACE_POINTBYTES];
    crypto_generichash_state st;
    const uint8_t *point_a, *point_b;

    /* Small-subgroup / invalid-point countermeasure: always verify that the
     * peer's point is a legitimate element of the group. Skipping this
     * lets a malicious peer send the identity element or a low-order
     * point and steer the DH output to a fixed value. */
    if (crypto_core_ristretto255_is_valid_point(peer_point) != 1)
        return -1;

    memcpy(ctx->peer_point, peer_point, CPACE_POINTBYTES);

    /* K = y * Y_peer (= y_a*y_b*g, both sides arrive at the same value) */
    if (crypto_scalarmult_ristretto255(shared, ctx->my_scalar, peer_point) != 0)
        return -1;

    /* Fix the transcript ordering regardless of role (A=initiator, B=responder). */
    point_a = ctx->is_initiator ? ctx->my_point : ctx->peer_point;
    point_b = ctx->is_initiator ? ctx->peer_point : ctx->my_point;

    crypto_generichash_init(&st, NULL, 0, CPACE_SESSIONKEYBYTES);
    crypto_generichash_update(&st, (const uint8_t *)DSI_SESSKEY, strlen(DSI_SESSKEY));
    crypto_generichash_update(&st, shared, sizeof(shared));
    crypto_generichash_update(&st, ctx->generator, CPACE_POINTBYTES);
    crypto_generichash_update(&st, point_a, CPACE_POINTBYTES);
    crypto_generichash_update(&st, point_b, CPACE_POINTBYTES);
    crypto_generichash_final(&st, ctx->session_key, CPACE_SESSIONKEYBYTES);

    sodium_memzero(shared, sizeof(shared));
    return 0;
}

void cpace_compute_confirmation(const cpace_ctx *ctx, const char *role, uint8_t out_mac[CPACE_MACBYTES])
{
    crypto_generichash_state st;
    /* Use session_key as the MAC key and include the role string (who the
     * sender is) so the MAC intended for A and the MAC intended for B can
     * never be confused (reflection-attack prevention). */
    crypto_generichash_init(&st, ctx->session_key, CPACE_SESSIONKEYBYTES, CPACE_MACBYTES);
    crypto_generichash_update(&st, (const uint8_t *)DSI_CONFIRM, strlen(DSI_CONFIRM));
    crypto_generichash_update(&st, (const uint8_t *)role, strlen(role));
    crypto_generichash_final(&st, out_mac, CPACE_MACBYTES);
}
