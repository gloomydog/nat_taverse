#ifndef RELAY_CLIENT_H
#define RELAY_CLIENT_H

#include <stdint.h>
#include <netinet/in.h>
#include "relay_proto.h"

/*
 * Client side of the rendezvous / relay server.
 *
 * One constraint drives the whole design: the socket used to talk to the
 * server must be the *same* one used to punch.  NAT mappings are
 * per-socket, so an address observed on a different socket would be
 * useless.  As a consequence, inbound datagrams are a mix of server
 * traffic and peer traffic, and the receive path has to demultiplex them.
 */

typedef struct {
    int sockfd;                    /* caller's bound socket */
    struct sockaddr_in server;     /* the server */
    uint8_t id[RELAY_ID_LEN];      /* meeting point */

    struct sockaddr_in observed;   /* our address as the server sees it */
    int have_observed;

    struct sockaddr_in peer;       /* the peer's address */
    int have_peer;
    uint16_t punch_delay_ms;

    int relay_mode;                /* 1 while falling back to relayed data */
} relay_client_t;

/* sockfd must already be bound.  server_host may be a name or an IP. */
int relay_client_init(relay_client_t *c, int sockfd,
                       const char *server_host, uint16_t server_port,
                       const char *shared_secret);

/* Register and wait for the peer.  On success c->peer is filled in.
 * Returns -1 if nobody showed up within timeout_ms.
 *
 * Call holepunch_run() immediately afterwards: the server sends PEER_INFO
 * to both sides back to back, so acting at once keeps them in step and
 * leaves no time for a carrier NAT to reallocate the mapping. */
int relay_rendezvous(relay_client_t *c, int timeout_ms);

/* Send via the relay (fallback when punching failed).  The payload is
 * expected to be already encrypted; the server never looks at it. */
int relay_send(relay_client_t *c, const void *payload, size_t len);

/* Receive via the relay.  Returns >0 (bytes), 0 on timeout, -1 on error.
 * Datagrams that arrived directly from the peer are ignored here. */
int relay_recv(relay_client_t *c, void *payload, size_t maxlen, int timeout_ms);

/* Refresh our registration.  Call periodically while relaying; the
 * server expires idle peers after 120 s. */
int relay_keepalive(relay_client_t *c);

/* Unregister. */
void relay_bye(relay_client_t *c);

#endif
