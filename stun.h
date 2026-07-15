#ifndef STUN_H
#define STUN_H

#include <stdint.h>
#include <netinet/in.h>

/*
 * Minimal STUN client (RFC 5389), Binding Request only.
 *
 * Purpose: ask a public server "what source address do you see me coming
 * from?".  The answer is the address our NAT allocated for the mapping
 * towards that particular server.
 *
 * Important caveat: the reply describes the mapping towards *the STUN
 * server*, not towards an arbitrary peer.  On a NAT with
 * endpoint-dependent mapping (see README, "NAT behaviour"), the address a
 * peer sees will be different.  This is not a limitation of this code but
 * of STUN itself.
 *
 * No dependencies beyond POSIX sockets.
 */

typedef struct {
    struct sockaddr_in mapped_addr;  /* our address as seen from outside */
    int ok;
} stun_result_t;

/* Query a STUN server for our externally visible address.
 *
 * sockfd must already be bound.  Use the *same* socket you intend to use
 * for the peer-to-peer traffic: NAT mappings are per-socket, so querying
 * from a different socket would return an address that is useless for
 * hole punching.
 *
 * Returns 0 on success, -1 on timeout or protocol error.
 */
int stun_get_mapped_address(int sockfd, const char *stun_host, uint16_t stun_port,
                            int timeout_ms, stun_result_t *out);

/* Compare the mappings observed by two different STUN servers.
 *
 * If both servers report the same external port, the NAT is *probably*
 * doing endpoint-independent mapping (EIM).  If they differ, it is doing
 * endpoint-dependent mapping (EDM) and hole punching is unlikely to work.
 *
 * This only probes the mapping axis.  It says nothing about filtering
 * behaviour, and it can be fooled: two servers run by the same operator
 * may be reached over the same path and yield a consistent answer even
 * on an EDM NAT.  Treat a "0" result as weak evidence, not proof.
 *
 * Returns 0 for EIM-like, 1 for EDM-like, -1 if the probe failed.
 */
int stun_detect_mapping_behaviour(int sockfd,
                                  const char *host1, uint16_t port1,
                                  const char *host2, uint16_t port2,
                                  int timeout_ms);

#endif
