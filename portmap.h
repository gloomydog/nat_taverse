#ifndef PORTMAP_H
#define PORTMAP_H

#include <stdint.h>
#include <netinet/in.h>

/*
 * Ask the router to install an explicit port mapping.
 *
 * Where STUN only *observes* what the NAT happens to be doing, these
 * protocols *instruct* it: "forward anything arriving on this external
 * port to me".  When one succeeds, that NAT layer effectively disappears
 * and hole punching becomes trivial (or unnecessary).
 *
 * Three protocols are tried, all widely deployed on consumer routers:
 *
 *   NAT-PMP (RFC 6886)  simple binary over UDP 5351
 *   PCP     (RFC 6887)  its successor, same port
 *   UPnP IGD            most common, but needs SSDP discovery + SOAP
 *
 * Two important caveats:
 *
 *   - These only affect the *first* NAT hop.  Behind carrier-grade NAT
 *     the home router may happily install a mapping while the carrier's
 *     NAT upstream remains untouched, so the mapping is useless.  Check
 *     the returned external IP with portmap_is_global_ip(); if it is
 *     private or in the CGNAT range, you are behind a second NAT.
 *   - Many routers ship with UPnP disabled (it has a poor security
 *     history).  Failure is normal; always fall back to hole punching.
 *
 * No dependencies beyond POSIX sockets.
 */

typedef enum {
    PORTMAP_METHOD_NONE = 0,
    PORTMAP_METHOD_NATPMP,
    PORTMAP_METHOD_PCP,
    PORTMAP_METHOD_UPNP,
} portmap_method_t;

typedef struct {
    portmap_method_t method;
    struct in_addr external_ip;   /* as reported by the router */
    uint16_t external_port;       /* may differ from what we asked for */
    uint16_t internal_port;
    uint32_t lifetime_sec;        /* 0 means indefinite */

    /* UPnP needs these to refresh or remove the mapping later. */
    char upnp_control_url[512];
    char upnp_service_type[128];
    char internal_client_ip[INET_ADDRSTRLEN];
} portmap_result_t;

int portmap_get_gateway(struct in_addr *out);
int portmap_get_local_ip(struct in_addr gateway, struct in_addr *out);

/* Try PCP, then NAT-PMP, then UPnP.  Pass 0 for desired_external_port to
 * let the router choose.  Returns 0 if any method succeeded. */
int portmap_try_all(uint16_t internal_port, uint16_t desired_external_port,
                    uint32_t lifetime_sec, portmap_result_t *out);

int portmap_natpmp(struct in_addr gateway, uint16_t internal_port,
                   uint16_t desired_external_port, uint32_t lifetime_sec,
                   portmap_result_t *out);
int portmap_pcp(struct in_addr gateway, uint16_t internal_port,
                uint16_t desired_external_port, uint32_t lifetime_sec,
                portmap_result_t *out);
int portmap_upnp(uint16_t internal_port, uint16_t desired_external_port,
                 uint32_t lifetime_sec, portmap_result_t *out);

/* Re-request the mapping before its lifetime expires. */
int portmap_refresh(const portmap_result_t *m);

/* Remove the mapping.  Always do this on exit: leaked mappings clog the
 * router's table and can block other applications. */
int portmap_delete(const portmap_result_t *m);

/* 1 if the address is globally routable, 0 if it is private (10/8,
 * 172.16/12, 192.168/16), link-local, loopback, or CGNAT (100.64/10).
 * A non-global external IP means there is another NAT upstream. */
int portmap_is_global_ip(struct in_addr ip);

#endif
