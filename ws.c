#define _POSIX_C_SOURCE 200809L

#include "ws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define WS_RXBUF 65536

struct ws_conn {
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int use_tls;

    /* Frames can arrive split across reads, so buffer the stream. */
    uint8_t rx[WS_RXBUF];
    size_t rx_len;
};

/* ------------------------- low level I/O ------------------------- */

static int io_read(ws_conn_t *c, void *buf, size_t len) {
    if (c->use_tls) {
        int n = SSL_read(c->ssl, buf, (int)len);
        if (n <= 0) {
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
            return -1;
        }
        return n;
    }
    ssize_t n = recv(c->fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    if (n == 0) return -1; /* peer closed */
    return (int)n;
}

static int io_write_all(ws_conn_t *c, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (c->use_tls) {
            n = SSL_write(c->ssl, p + sent, (int)(len - sent));
            if (n <= 0) return -1;
        } else {
            ssize_t s = send(c->fd, p + sent, len - sent, MSG_NOSIGNAL);
            if (s <= 0) return -1;
            n = (int)s;
        }
        sent += (size_t)n;
    }
    return 0;
}

static void set_timeout(ws_conn_t *c, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* --------------------------- URL parsing -------------------------- */

static int parse_ws_url(const char *url, int *use_tls, char *host, size_t hostlen,
                         uint16_t *port, char *path, size_t pathlen) {
    const char *p;
    if (strncmp(url, "wss://", 6) == 0) { *use_tls = 1; *port = 443; p = url + 6; }
    else if (strncmp(url, "ws://", 5) == 0) { *use_tls = 0; *port = 80; p = url + 5; }
    else return -1;

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    if (colon && slash && colon > slash) colon = NULL;

    size_t hlen;
    if (colon) {
        hlen = (size_t)(colon - p);
        *port = (uint16_t)atoi(colon + 1);
    } else {
        hlen = slash ? (size_t)(slash - p) : strlen(p);
    }
    if (hlen == 0 || hlen >= hostlen) return -1;
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    if (slash) {
        if (strlen(slash) >= pathlen) return -1;
        strcpy(path, slash);
    } else {
        if (pathlen < 2) return -1;
        strcpy(path, "/");
    }
    return 0;
}

/* ----------------------------- base64 ----------------------------- */

static void b64_encode(const uint8_t *in, size_t len, char *out, size_t outlen) {
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)len);
    if (n < 0 || (size_t)n >= outlen) out[0] = '\0';
}

/* --------------------------- handshake ---------------------------- */

static int do_handshake(ws_conn_t *c, const char *host, uint16_t port, const char *path) {
    uint8_t key_raw[16];
    if (RAND_bytes(key_raw, sizeof(key_raw)) != 1) return -1;

    char key_b64[32];
    b64_encode(key_raw, sizeof(key_raw), key_b64, sizeof(key_b64));

    char req[1024];
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n", path, host, port, key_b64);
    if (n < 0 || (size_t)n >= sizeof(req)) return -1;

    if (io_write_all(c, req, (size_t)n) != 0) return -1;

    /* read response headers up to the blank line */
    char resp[2048];
    size_t total = 0;
    while (total < sizeof(resp) - 1) {
        int r = io_read(c, resp + total, sizeof(resp) - 1 - total);
        if (r < 0) return -1;
        if (r == 0) continue;
        total += (size_t)r;
        resp[total] = '\0';
        if (strstr(resp, "\r\n\r\n")) break;
    }
    resp[total] = '\0';

    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) return -1;

    /* Verify Sec-WebSocket-Accept = base64(SHA1(key + GUID)). */
    static const char *GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char concat[128];
    snprintf(concat, sizeof(concat), "%s%s", key_b64, GUID);

    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)concat, strlen(concat), digest);
    char expect[64];
    b64_encode(digest, sizeof(digest), expect, sizeof(expect));

    const char *acc = strcasestr(resp, "Sec-WebSocket-Accept:");
    if (!acc) return -1;
    acc += strlen("Sec-WebSocket-Accept:");
    while (*acc == ' ') acc++;
    if (strncmp(acc, expect, strlen(expect)) != 0) return -1;

    /* the server may have pipelined frames right after the headers */
    char *body = strstr(resp, "\r\n\r\n") + 4;
    size_t leftover = total - (size_t)(body - resp);
    if (leftover > 0 && leftover <= sizeof(c->rx)) {
        memcpy(c->rx, body, leftover);
        c->rx_len = leftover;
    }
    return 0;
}

/* ---------------------------- connect ----------------------------- */

ws_conn_t *ws_connect(const char *url, int timeout_ms) {
    int use_tls;
    char host[256], path[512];
    uint16_t port;
    if (parse_ws_url(url, &use_tls, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return NULL;

    struct addrinfo hints, *res = NULL;
    char portstr[8];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return NULL;

    ws_conn_t *c = calloc(1, sizeof(ws_conn_t));
    if (!c) { freeaddrinfo(res); return NULL; }

    c->fd = socket(res->ai_family, res->ai_socktype, 0);
    if (c->fd < 0) { freeaddrinfo(res); free(c); return NULL; }

    struct timeval tv = { .tv_sec = timeout_ms / 1000,
                          .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (connect(c->fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(c->fd);
        free(c);
        return NULL;
    }
    freeaddrinfo(res);

    c->use_tls = use_tls;
    if (use_tls) {
        c->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!c->ssl_ctx) { close(c->fd); free(c); return NULL; }

        /* Relays are public services reached over the open internet, so
         * certificate verification is not optional. */
        SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(c->ssl_ctx) != 1) {
            SSL_CTX_free(c->ssl_ctx);
            close(c->fd);
            free(c);
            return NULL;
        }

        c->ssl = SSL_new(c->ssl_ctx);
        SSL_set_fd(c->ssl, c->fd);
        SSL_set_tlsext_host_name(c->ssl, host);   /* SNI */
        SSL_set1_host(c->ssl, host);              /* hostname verification */

        if (SSL_connect(c->ssl) != 1) {
            SSL_free(c->ssl);
            SSL_CTX_free(c->ssl_ctx);
            close(c->fd);
            free(c);
            return NULL;
        }
    }

    if (do_handshake(c, host, port, path) != 0) {
        ws_close(c);
        return NULL;
    }
    return c;
}

/* ------------------------- sending frames ------------------------- */

static int ws_send_frame(ws_conn_t *c, uint8_t opcode, const void *payload, size_t len) {
    uint8_t hdr[14];
    size_t hlen = 0;

    hdr[hlen++] = 0x80 | opcode;  /* FIN=1 */

    /* RFC 6455 requires clients to mask every frame */
    if (len < 126) {
        hdr[hlen++] = 0x80 | (uint8_t)len;
    } else if (len <= 0xFFFF) {
        hdr[hlen++] = 0x80 | 126;
        hdr[hlen++] = (uint8_t)(len >> 8);
        hdr[hlen++] = (uint8_t)(len & 0xFF);
    } else {
        hdr[hlen++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) hdr[hlen++] = (uint8_t)((uint64_t)len >> (i * 8));
    }

    uint8_t mask[4];
    if (RAND_bytes(mask, 4) != 1) return -1;
    memcpy(hdr + hlen, mask, 4);
    hlen += 4;

    if (io_write_all(c, hdr, hlen) != 0) return -1;

    if (len > 0) {
        uint8_t *masked = malloc(len);
        if (!masked) return -1;
        const uint8_t *src = payload;
        for (size_t i = 0; i < len; i++) masked[i] = src[i] ^ mask[i & 3];
        int rc = io_write_all(c, masked, len);
        free(masked);
        if (rc != 0) return -1;
    }
    return 0;
}

int ws_send_text(ws_conn_t *c, const char *text, size_t len) {
    return ws_send_frame(c, 0x1, text, len);
}

/* ------------------------ receiving frames ------------------------ */

/* Pull one complete frame out of the buffer.
 * Returns 1 if a frame was extracted, 0 if more data is needed,
 * -1 on protocol violation. */
static int try_parse_frame(ws_conn_t *c, uint8_t *opcode, int *fin,
                            uint8_t **payload, size_t *paylen, size_t *consumed) {
    if (c->rx_len < 2) return 0;

    uint8_t b0 = c->rx[0], b1 = c->rx[1];
    *fin = (b0 & 0x80) ? 1 : 0;
    *opcode = b0 & 0x0F;
    int masked = (b1 & 0x80) ? 1 : 0;
    uint64_t len = b1 & 0x7F;
    size_t pos = 2;

    if (len == 126) {
        if (c->rx_len < pos + 2) return 0;
        len = ((uint64_t)c->rx[pos] << 8) | c->rx[pos + 1];
        pos += 2;
    } else if (len == 127) {
        if (c->rx_len < pos + 8) return 0;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | c->rx[pos + i];
        pos += 8;
    }

    /* servers must not mask, but handle it anyway */
    uint8_t mask[4] = {0};
    if (masked) {
        if (c->rx_len < pos + 4) return 0;
        memcpy(mask, c->rx + pos, 4);
        pos += 4;
    }

    if (len > WS_RXBUF) return -1;  /* would not fit in our buffer */
    if (c->rx_len < pos + len) return 0;

    if (masked) {
        for (uint64_t i = 0; i < len; i++)
            c->rx[pos + i] ^= mask[i & 3];
    }

    *payload = c->rx + pos;
    *paylen = (size_t)len;
    *consumed = pos + (size_t)len;
    return 1;
}

int ws_recv_text(ws_conn_t *c, char *buf, size_t maxlen, int timeout_ms) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    size_t assembled = 0;  /* for reassembling continuation frames */

    for (;;) {
        uint8_t opcode;
        int fin;
        uint8_t *payload;
        size_t paylen, consumed;

        int r = try_parse_frame(c, &opcode, &fin, &payload, &paylen, &consumed);
        if (r < 0) return -1;

        if (r == 1) {
            if (opcode == 0x9) {
                /* ping: answer with a pong */
                uint8_t tmp[128];
                size_t n = paylen > sizeof(tmp) ? sizeof(tmp) : paylen;
                memcpy(tmp, payload, n);
                memmove(c->rx, c->rx + consumed, c->rx_len - consumed);
                c->rx_len -= consumed;
                if (ws_send_frame(c, 0xA, tmp, n) != 0) return -1;
                continue;
            }
            if (opcode == 0x8) return -1;  /* close */
            if (opcode == 0xA) {           /* pong: discard */
                memmove(c->rx, c->rx + consumed, c->rx_len - consumed);
                c->rx_len -= consumed;
                continue;
            }

            if (opcode == 0x1 || opcode == 0x0) {
                size_t copy = paylen;
                if (assembled + copy > maxlen - 1) copy = maxlen - 1 - assembled;
                memcpy(buf + assembled, payload, copy);
                assembled += copy;

                memmove(c->rx, c->rx + consumed, c->rx_len - consumed);
                c->rx_len -= consumed;

                if (fin) {
                    buf[assembled] = '\0';
                    return (int)assembled;
                }
                continue;  /* wait for the rest */
            }

            /* drop opcodes we do not handle */
            memmove(c->rx, c->rx + consumed, c->rx_len - consumed);
            c->rx_len -= consumed;
            continue;
        }

        /* incomplete frame: read more */
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                       (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= timeout_ms) return 0;

        int remain = timeout_ms - (int)elapsed;
        set_timeout(c, remain > 100 ? 100 : remain);

        if (c->rx_len >= sizeof(c->rx)) return -1;  /* overflow */
        int n = io_read(c, c->rx + c->rx_len, sizeof(c->rx) - c->rx_len);
        if (n < 0) return -1;
        c->rx_len += (size_t)n;
    }
}

int ws_fd(ws_conn_t *c) { return c ? c->fd : -1; }

void ws_close(ws_conn_t *c) {
    if (!c) return;
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->ssl_ctx) SSL_CTX_free(c->ssl_ctx);
    if (c->fd >= 0) close(c->fd);
    free(c);
}
