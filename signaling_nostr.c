#define _POSIX_C_SOURCE 200809L

#include "signaling_nostr.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/rand.h>

#include "ws.h"
#include "nostr.h"

/*
 * Rendezvous over public Nostr relays.  No server of your own.
 *
 * How it works:
 *   1. Derive a signing keypair and an encryption key from the shared
 *      secret.  Both peers derive the *same* signing key, so to a relay
 *      they are one identity posting twice -- and each side can find the
 *      other with an `authors` filter.
 *   2. Publish our STUN-discovered address, encrypted, as an ephemeral
 *      event.  Relays are public; nothing goes out in clear text.
 *   3. Decrypt the peer's event to learn their address.
 *
 * Differences from the custom relay backend:
 *   - The custom relay sees our UDP source address directly.  Nostr rides
 *     a separate TCP connection and cannot, so STUN is required.
 *   - Nostr cannot carry data (supports_relay() == 0).  If punching fails
 *     the connection fails.  (Small application payloads such as chat
 *     could of course ride Nostr at the application layer -- but that is
 *     not this module's job.)
 *
 * On synchronisation: a rendezvous server can trigger both sides at once.
 * Nostr has no such primitive, so each peer starts punching the moment it
 * sees the other's event.  The resulting skew is just the difference in
 * relay delivery latency, which the punch retry loop absorbs.
 */

#define MAX_RELAYS 4

typedef struct {
    ws_conn_t *ws[MAX_RELAYS];
    int nrelays;

    nostr_identity_t id;
    char subid[17];
    uint8_t self_tag[8];   /* lets us ignore our own events echoed back by the relay */
    int64_t since;
    int verbose;
} nostr_ctx_t;

/* Published payload, encrypted then base64'd into `content`:
 *   self_tag(8) || ip(4) || port(2) = 14 bytes */
#define PAYLOAD_LEN 14

static void log_v(nostr_ctx_t *c, const char *fmt, ...) {
    if (!c->verbose) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int ns_publish(void *ctx, const struct sockaddr_in *my_addr) {
    nostr_ctx_t *c = ctx;

    uint8_t payload[PAYLOAD_LEN];
    memcpy(payload, c->self_tag, 8);
    memcpy(payload + 8, &my_addr->sin_addr.s_addr, 4);
    memcpy(payload + 12, &my_addr->sin_port, 2);

    char content[512];
    if (nostr_encrypt_payload(&c->id, payload, sizeof(payload),
                              content, sizeof(content)) != 0) return -1;

    char event[4096];
    if (nostr_build_event(&c->id, NOSTR_KIND_SIGNAL, content,
                          event, sizeof(event)) != 0) return -1;

    char msg[4200];
    if (nostr_build_publish(event, msg, sizeof(msg)) != 0) return -1;

    int sent = 0;
    for (int i = 0; i < c->nrelays; i++) {
        if (!c->ws[i]) continue;
        if (ws_send_text(c->ws[i], msg, strlen(msg)) == 0) sent++;
        else {
            log_v(c, "[nostr] relay %d send failed, dropping it\n", i);
            ws_close(c->ws[i]);
            c->ws[i] = NULL;
        }
    }
    return sent > 0 ? 0 : -1;
}

static int ns_wait_peer(void *ctx, struct sockaddr_in *peer_out, int timeout_ms) {
    nostr_ctx_t *c = ctx;

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                       (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= timeout_ms) return -1;

        int alive = 0;
        for (int i = 0; i < c->nrelays; i++) {
            if (!c->ws[i]) continue;
            alive = 1;

            char msg[8192];
            int n = ws_recv_text(c->ws[i], msg, sizeof(msg), 100);
            if (n < 0) {
                log_v(c, "[nostr] relay %d disconnected\n", i);
                ws_close(c->ws[i]);
                c->ws[i] = NULL;
                continue;
            }
            if (n == 0) continue;

            char content[600];
            if (nostr_extract_content(msg, content, sizeof(content)) != 0) continue;

            uint8_t payload[64];
            int plen = nostr_decrypt_payload(&c->id, content, payload, sizeof(payload));
            if (plen != PAYLOAD_LEN) continue;  /* decryption failed: not our peer */

            /* relays echo our own events back; skip them */
            if (memcmp(payload, c->self_tag, 8) == 0) continue;

            memset(peer_out, 0, sizeof(*peer_out));
            peer_out->sin_family = AF_INET;
            memcpy(&peer_out->sin_addr.s_addr, payload + 8, 4);
            memcpy(&peer_out->sin_port, payload + 12, 2);
            return 0;
        }

        if (!alive) {
            log_v(c, "[nostr] all relays disconnected\n");
            return -1;
        }
    }
}

static int ns_supports_relay(void *ctx) {
    (void)ctx;
    /* Signalling only.  Event size limits, rate limits, and simple
     * courtesy towards public infrastructure rule out using relays as a
     * general byte pipe. */
    return 0;
}

static int ns_relay_send(void *ctx, const void *p, size_t len) {
    (void)ctx; (void)p; (void)len;
    return -1;
}

static int ns_relay_recv(void *ctx, void *p, size_t maxlen, int timeout_ms) {
    (void)ctx; (void)p; (void)maxlen; (void)timeout_ms;
    return -1;
}

static int ns_relay_keepalive(void *ctx) {
    (void)ctx;
    return -1;
}

static void ns_close(void *ctx) {
    nostr_ctx_t *c = ctx;
    if (!c) return;
    for (int i = 0; i < c->nrelays; i++)
        if (c->ws[i]) ws_close(c->ws[i]);
    free(c);
}

int signaling_nostr_create(signaling_backend_t *out,
                            const char **relay_urls, int nrelays,
                            const char *shared_secret, int verbose) {
    if (nrelays < 1) return -1;
    if (nrelays > MAX_RELAYS) nrelays = MAX_RELAYS;

    nostr_ctx_t *c = calloc(1, sizeof(nostr_ctx_t));
    if (!c) return -1;
    c->verbose = verbose;

    if (nostr_derive_identity(shared_secret, &c->id) != 0) {
        free(c);
        return -1;
    }

    /* random tag so we can recognise our own posts */
    if (RAND_bytes(c->self_tag, sizeof(c->self_tag)) != 1) {
        free(c);
        return -1;
    }

    /* random subscription id */
    uint8_t sub[8];
    RAND_bytes(sub, sizeof(sub));
    for (int i = 0; i < 8; i++)
        snprintf(c->subid + i * 2, 3, "%02x", sub[i]);

    /* Ask for slightly older events too.  Ephemeral events are not
     * stored, so this is mostly a no-op, but some relays are lenient. */
    c->since = (int64_t)time(NULL) - 60;

    char req[512];
    if (nostr_build_req(&c->id, NOSTR_KIND_SIGNAL, c->subid,
                        c->since, req, sizeof(req)) != 0) {
        free(c);
        return -1;
    }

    /* Connect to several relays: public ones are frequently unreachable,
     * and losing the rendezvous to a single outage would be a shame. */
    int connected = 0;
    for (int i = 0; i < nrelays; i++) {
        if (verbose) fprintf(stderr, "[nostr] connecting to %s\n", relay_urls[i]);
        c->ws[connected] = ws_connect(relay_urls[i], 5000);
        if (!c->ws[connected]) {
            if (verbose) fprintf(stderr, "[nostr] %s unreachable\n", relay_urls[i]);
            continue;
        }
        if (ws_send_text(c->ws[connected], req, strlen(req)) != 0) {
            ws_close(c->ws[connected]);
            c->ws[connected] = NULL;
            continue;
        }
        if (verbose) fprintf(stderr, "[nostr] subscribed on %s\n", relay_urls[i]);
        connected++;
    }
    c->nrelays = connected;

    if (connected == 0) {
        free(c);
        return -1;
    }

    out->ctx = c;
    out->publish = ns_publish;
    out->wait_peer = ns_wait_peer;
    out->supports_relay = ns_supports_relay;
    out->relay_send = ns_relay_send;
    out->relay_recv = ns_relay_recv;
    out->relay_keepalive = ns_relay_keepalive;
    out->close = ns_close;
    return 0;
}
