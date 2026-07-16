#include "signaling_nostr.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "ws.h"
#include "nostr.h"
#include "crypto.h"

/*
 * Rendezvous over public Nostr relays. No server of your own.
 *
 *   1. Both peers derive the same signing key from the passphrase, so to
 *      a relay they look like one identity posting twice, and each side
 *      can find the other with an `authors` filter.
 *   2. Publish our candidate addresses, encrypted, as an ephemeral event.
 *      Relays are public; nothing goes out in clear text.
 *   3. Decrypt the peer's event to learn their candidates.
 *
 * Differences from the custom relay backend: that server sees our UDP
 * source address directly, whereas Nostr rides a separate TCP connection
 * and cannot, so STUN is required. And Nostr cannot carry data
 * (supports_relay() == 0): if punching fails, the connection fails.
 *
 * On synchronisation: a rendezvous server can trigger both sides at once.
 * Nostr has no such primitive, so each peer starts punching the moment it
 * sees the other's event. The resulting skew is only the difference in
 * relay delivery latency, which the punch retry loop absorbs.
 */

#define MAX_RELAYS 4

/* Published payload, encrypted then base64'd into `content`:
 *
 *   self_tag(8) || count(1) || candidate[count] * NETADDR_WIRE_LEN
 *
 * self_tag lets us ignore our own events, which relays echo back. */
#define TAG_LEN 8
#define PAYLOAD_MAX (TAG_LEN + 1 + SIG_MAX_CANDIDATES * NETADDR_WIRE_LEN)

typedef struct {
    ws_conn_t *ws[MAX_RELAYS];
    int nrelays;

    nostr_identity_t id;
    char subid[17];
    uint8_t self_tag[TAG_LEN];
    int64_t since;
    int verbose;
} nostr_ctx_t;

static void log_v(nostr_ctx_t *c, const char *fmt, ...) {
    if (!c->verbose) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int ns_publish(void *ctx, const sig_candidates_t *mine) {
    nostr_ctx_t *c = ctx;
    if (mine->n <= 0 || mine->n > SIG_MAX_CANDIDATES) return -1;

    uint8_t payload[PAYLOAD_MAX];
    size_t off = 0;
    memcpy(payload, c->self_tag, TAG_LEN);
    off += TAG_LEN;
    payload[off++] = (uint8_t)mine->n;
    for (int i = 0; i < mine->n; i++) {
        netaddr_encode(&mine->addr[i], payload + off);
        off += NETADDR_WIRE_LEN;
    }

    char content[1024];
    if (nostr_encrypt_payload(&c->id, payload, off, content, sizeof(content)) != 0)
        return -1;

    char event[4096];
    if (nostr_build_event(&c->id, NOSTR_KIND_SIGNAL, content,
                          event, sizeof(event)) != 0) return -1;

    char msg[4200];
    if (nostr_build_publish(event, msg, sizeof(msg)) != 0) return -1;

    int sent = 0;
    for (int i = 0; i < c->nrelays; i++) {
        if (!c->ws[i]) continue;
        if (ws_send_text(c->ws[i], msg, strlen(msg)) == 0) {
            sent++;
        } else {
            log_v(c, "[nostr] relay %d send failed, dropping it\n", i);
            ws_close(c->ws[i]);
            c->ws[i] = NULL;
        }
    }
    return sent > 0 ? 0 : -1;
}

static int ns_wait_peer(void *ctx, sig_candidates_t *peer_out, int timeout_ms) {
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

            char content[1400];
            if (nostr_extract_content(msg, content, sizeof(content)) != 0) continue;

            uint8_t payload[PAYLOAD_MAX];
            int plen = nostr_decrypt_payload(&c->id, content, payload, sizeof(payload));
            if (plen < (int)(TAG_LEN + 1)) continue;   /* not for us */

            /* Relays echo our own events back to us. */
            if (memcmp(payload, c->self_tag, TAG_LEN) == 0) continue;

            int count = payload[TAG_LEN];
            if (count <= 0 || count > SIG_MAX_CANDIDATES) continue;
            if (plen != (int)(TAG_LEN + 1 + (size_t)count * NETADDR_WIRE_LEN)) continue;

            memset(peer_out, 0, sizeof(*peer_out));
            size_t off = TAG_LEN + 1;
            for (int j = 0; j < count; j++) {
                if (netaddr_decode(&peer_out->addr[peer_out->n], payload + off) == 0)
                    peer_out->n++;
                off += NETADDR_WIRE_LEN;
            }
            if (peer_out->n > 0) return 0;
        }

        if (!alive) {
            log_v(c, "[nostr] all relays disconnected\n");
            return -1;
        }
    }
}

static int ns_supports_relay(void *ctx) {
    (void)ctx;
    /* Signalling only. Event size limits, rate limits, and basic courtesy
     * toward public infrastructure all rule out using relays as a byte
     * pipe. */
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
    nostr_identity_wipe(&c->id);
    nt_wipe(c, sizeof(*c));
    free(c);
}

int signaling_nostr_create(signaling_backend_t *out,
                           const char **relay_urls, int nrelays,
                           const nt_keys_t *keys, int verbose) {
    if (nrelays < 1) return -1;
    if (nrelays > MAX_RELAYS) nrelays = MAX_RELAYS;

    nostr_ctx_t *c = calloc(1, sizeof(nostr_ctx_t));
    if (!c) return -1;
    c->verbose = verbose;

    if (nostr_identity_from_keys(keys, &c->id) != 0) {
        free(c);
        return -1;
    }

    nt_random(c->self_tag, sizeof(c->self_tag));

    uint8_t sub[8];
    nt_random(sub, sizeof(sub));
    for (int i = 0; i < 8; i++) snprintf(c->subid + i * 2, 3, "%02x", sub[i]);

    /* Ask for slightly older events as well. Ephemeral events are not
     * stored so this is mostly a no-op, but some relays are lenient. */
    c->since = (int64_t)time(NULL) - 60;

    char req[512];
    if (nostr_build_req(&c->id, NOSTR_KIND_SIGNAL, c->subid,
                        c->since, req, sizeof(req)) != 0) {
        ns_close(c);
        return -1;
    }

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
        ns_close(c);
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
