#ifndef WS_H
#define WS_H

#include <stddef.h>

/*
 * Minimal WebSocket client (RFC 6455), ws:// and wss:// (TLS via OpenSSL).
 *
 * Implements only what is needed to talk to a Nostr relay:
 *   - HTTP Upgrade handshake
 *   - text frames (clients must mask their payloads)
 *   - automatic pong replies
 *   - reassembly of continuation frames
 *
 * Not supported: compression extensions (permessage-deflate), binary frames.
 */

typedef struct ws_conn ws_conn_t;

/* url: "wss://relay.damus.io" or "ws://127.0.0.1:7447".
 * timeout_ms bounds both the TCP connect and the handshake. */
ws_conn_t *ws_connect(const char *url, int timeout_ms);

/* Send a text frame. Returns 0 on success, -1 on failure. */
int ws_send_text(ws_conn_t *c, const char *text, size_t len);

/* Receive one text frame.
 * Returns >0 (bytes), 0 on timeout, -1 on close or error.
 * Ping and close frames are handled internally. */
int ws_recv_text(ws_conn_t *c, char *buf, size_t maxlen, int timeout_ms);

void ws_close(ws_conn_t *c);

/* Underlying socket, in case the caller wants to select() on it. */
int ws_fd(ws_conn_t *c);

#endif
