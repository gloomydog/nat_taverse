#define _POSIX_C_SOURCE 200809L

#include "relay_proto.h"

#include <string.h>
#include <arpa/inet.h>

void relay_derive_id(const char *shared_secret, uint8_t out[RELAY_ID_LEN]) {
    /* FNV-1a stretched to 32 bytes.  This only has to keep the secret
     * off the wire and produce a collision-resistant meeting id.  It
     * offers essentially no resistance to brute force -- swap in a real
     * KDF (Argon2id) before depending on it. */
    size_t len = strlen(shared_secret);

    for (int i = 0; i < RELAY_ID_LEN; i++) {
        uint64_t h = 1469598103934665603ULL ^ (uint64_t)(i * 0x9E3779B97F4A7C15ULL);
        for (size_t j = 0; j < len; j++) {
            h ^= (uint8_t)shared_secret[j];
            h *= 1099511628211ULL;
        }
        out[i] = (uint8_t)(h ^ (h >> 32) ^ (h >> 16));
    }
}

void relay_build_header(relay_header_t *h, uint8_t type, const uint8_t id[RELAY_ID_LEN]) {
    h->magic = htonl(RELAY_MAGIC);
    h->version = RELAY_VERSION;
    h->type = type;
    h->reserved = 0;
    memcpy(h->rendezvous_id, id, RELAY_ID_LEN);
}

int relay_validate_header(const void *buf, size_t len) {
    if (len < sizeof(relay_header_t)) return 0;
    const relay_header_t *h = (const relay_header_t *)buf;
    if (ntohl(h->magic) != RELAY_MAGIC) return 0;
    if (h->version != RELAY_VERSION) return 0;
    return 1;
}
