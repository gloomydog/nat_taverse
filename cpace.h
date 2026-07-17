#ifndef CPACE_H
#define CPACE_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

#define CPACE_SCALARBYTES   crypto_core_ristretto255_SCALARBYTES  /* 32 */
#define CPACE_POINTBYTES    crypto_core_ristretto255_BYTES        /* 32 */
#define CPACE_SESSIONKEYBYTES 32
#define CPACE_MACBYTES      32

typedef struct {
    uint8_t generator[CPACE_POINTBYTES];   /* g */
    uint8_t my_scalar[CPACE_SCALARBYTES];  /* y_a or y_b (secret) */
    uint8_t my_point[CPACE_POINTBYTES];    /* Y_a or Y_b (public, send this) */
    uint8_t peer_point[CPACE_POINTBYTES];  /* received from peer */
    uint8_t session_key[CPACE_SESSIONKEYBYTES];
    int is_initiator;
} cpace_ctx;

/*
 * Round 1: derive the generator g from the room_code (shared password) and
 * room_id (channel identifier / Nostr tag), generate our own scalar y, and
 * compute the public point Y = y*g.
 * Send ctx->my_point to the peer.
 * Returns: 0 = success, -1 = failure
 */
int cpace_init(cpace_ctx *ctx,
                const char *room_code, size_t room_code_len,
                const char *room_id,   size_t room_id_len,
                int is_initiator);

/*
 * Round 2: receive the peer's public point, compute the shared DH point
 * y*Y_peer, and derive the session key including the transcript.
 * If peer_point is the identity element (an invalid point) this must
 * always fail (small-subgroup attack countermeasure).
 * Returns: 0 = success, -1 = failure (invalid point or computation error)
 */
int cpace_derive_session_key(cpace_ctx *ctx, const uint8_t peer_point[CPACE_POINTBYTES]);

/*
 * Compute the key-confirmation MAC. role should be "A" (initiator) or
 * "B" (responder). Send your own role's MAC to the peer and compare it
 * against the peer's MAC using a constant-time comparison (sodium_memcmp).
 */
void cpace_compute_confirmation(const cpace_ctx *ctx, const char *role, uint8_t out_mac[CPACE_MACBYTES]);

#endif
