#define _POSIX_C_SOURCE 200809L

#include "portmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#define PORTMAP_GATEWAY_PORT 5351   /* shared by NAT-PMP and PCP */
#define SSDP_ADDR "239.255.255.250"
#define SSDP_PORT 1900

/* ------------------------------------------------------------------ */
/* common helpers                                                     */
/* ------------------------------------------------------------------ */

int portmap_get_gateway(struct in_addr *out) {
    /* /proc/net/route layout:
     *   Iface Destination Gateway Flags RefCnt Use Metric Mask ...
     *   wlp1s0 00000000 0100A8C0 0003 0 0 600 00000000 ...
     * The row whose Destination is 00000000 is the default route.
     * Gateway is hex, little-endian. */
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;

    char line[256];
    /* skip the header line */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }

    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        unsigned long dest, gw;
        int n = sscanf(line, "%63s %lx %lx", iface, &dest, &gw);
        if (n != 3) continue;
        if (dest != 0) continue;      /* default route only */
        if (gw == 0) continue;        /* on-link, no gateway */
        out->s_addr = (in_addr_t)gw;  /* already in network byte order */
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

int portmap_get_local_ip(struct in_addr gateway, struct in_addr *out) {
    /* connect() on a UDP socket sends nothing, but it makes the kernel
     * pick a route and bind a source address, which we can then read. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr = gateway;
    to.sin_port = htons(PORTMAP_GATEWAY_PORT);

    if (connect(s, (struct sockaddr *)&to, sizeof(to)) < 0) {
        close(s);
        return -1;
    }

    struct sockaddr_in me;
    socklen_t melen = sizeof(me);
    if (getsockname(s, (struct sockaddr *)&me, &melen) < 0) {
        close(s);
        return -1;
    }
    close(s);
    *out = me.sin_addr;
    return 0;
}

int portmap_is_global_ip(struct in_addr ip) {
    uint32_t a = ntohl(ip.s_addr);
    uint8_t b1 = (a >> 24) & 0xFF;
    uint8_t b2 = (a >> 16) & 0xFF;

    if (b1 == 10) return 0;                              /* 10/8 */
    if (b1 == 127) return 0;                             /* loopback */
    if (b1 == 172 && b2 >= 16 && b2 <= 31) return 0;     /* 172.16/12 */
    if (b1 == 192 && b2 == 168) return 0;                /* 192.168/16 */
    if (b1 == 169 && b2 == 254) return 0;                /* link-local */
    if (b1 == 100 && b2 >= 64 && b2 <= 127) return 0;    /* 100.64/10 CGNAT */
    if (b1 == 0) return 0;
    return 1;
}

/* send a UDP request to the gateway and wait for the reply */
static int gw_request(struct in_addr gateway, const void *req, size_t reqlen,
                       void *resp, size_t resplen, int timeout_ms) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr = gateway;
    to.sin_port = htons(PORTMAP_GATEWAY_PORT);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sendto(s, req, reqlen, 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        close(s);
        return -1;
    }

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(s, resp, resplen, 0, (struct sockaddr *)&from, &fromlen);
    close(s);

    if (n < 0) return -1;
    /* ignore replies from anyone but the gateway */
    if (from.sin_addr.s_addr != gateway.s_addr) return -1;
    return (int)n;
}

/* ------------------------------------------------------------------ */
/* NAT-PMP (RFC 6886)                                                  */
/* ------------------------------------------------------------------ */

/* External address request:
 *   req : version(1)=0, opcode(1)=0
 *   resp: version(1), opcode(1)=128, result(2), epoch(4), extip(4) = 12 bytes
 *
 * Mapping request:
 *   req : version(1)=0, opcode(1)=1(UDP), reserved(2), internal(2),
 *         suggested_external(2), lifetime(4) = 12 bytes
 *   resp: version(1), opcode(1)=129, result(2), epoch(4),
 *         internal(2), external(2), lifetime(4) = 16 bytes
 */

static int natpmp_external_address(struct in_addr gateway, struct in_addr *out) {
    uint8_t req[2] = { 0, 0 };
    uint8_t resp[16];

    int n = gw_request(gateway, req, sizeof(req), resp, sizeof(resp), 1000);
    if (n < 12) return -1;
    if (resp[0] != 0 || resp[1] != 128) return -1;

    uint16_t result;
    memcpy(&result, resp + 2, 2);
    if (ntohs(result) != 0) return -1;

    memcpy(&out->s_addr, resp + 8, 4);
    return 0;
}

int portmap_natpmp(struct in_addr gateway, uint16_t internal_port,
                    uint16_t desired_external_port, uint32_t lifetime_sec,
                    portmap_result_t *out) {
    struct in_addr extip;
    if (natpmp_external_address(gateway, &extip) != 0) return -1;

    uint8_t req[12];
    memset(req, 0, sizeof(req));
    req[0] = 0;  /* version */
    req[1] = 1;  /* opcode: 1 = map UDP */
    /* req[2..3] reserved = 0 */
    uint16_t iport = htons(internal_port);
    uint16_t eport = htons(desired_external_port);
    uint32_t lt = htonl(lifetime_sec);
    memcpy(req + 4, &iport, 2);
    memcpy(req + 6, &eport, 2);
    memcpy(req + 8, &lt, 4);

    uint8_t resp[16];
    int n = gw_request(gateway, req, sizeof(req), resp, sizeof(resp), 1000);
    if (n < 16) return -1;
    if (resp[0] != 0 || resp[1] != 129) return -1;

    uint16_t result;
    memcpy(&result, resp + 2, 2);
    if (ntohs(result) != 0) return -1;

    uint16_t mapped_ext;
    uint32_t granted_lt;
    memcpy(&mapped_ext, resp + 10, 2);
    memcpy(&granted_lt, resp + 12, 4);

    memset(out, 0, sizeof(*out));
    out->method = PORTMAP_METHOD_NATPMP;
    out->external_ip = extip;
    out->external_port = ntohs(mapped_ext);
    out->internal_port = internal_port;
    out->lifetime_sec = ntohl(granted_lt);
    return 0;
}

/* ------------------------------------------------------------------ */
/* PCP (RFC 6887)                                                      */
/* ------------------------------------------------------------------ */

/* Request = common header (24) + MAP opcode data (36) = 60 bytes
 *
 * Header:
 *   version(1)=2, R|opcode(1)=0x01, reserved(2), lifetime(4),
 *   client_ip(16, IPv4-mapped IPv6 for v4)
 * MAP data:
 *   nonce(12), protocol(1)=17(UDP), reserved(3),
 *   internal_port(2), suggested_external_port(2), suggested_external_ip(16)
 *
 * Response = header (24) + MAP data (36) = 60 bytes
 * Header: version(1), R|opcode(1)=0x81, reserved(1), result(1),
 *         lifetime(4), epoch(4), reserved(12)
 */

static void ipv4_to_mapped_v6(struct in_addr v4, uint8_t out[16]) {
    memset(out, 0, 10);
    out[10] = 0xFF;
    out[11] = 0xFF;
    memcpy(out + 12, &v4.s_addr, 4);
}

static int mapped_v6_to_ipv4(const uint8_t in[16], struct in_addr *out) {
    static const uint8_t prefix[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
    if (memcmp(in, prefix, 12) != 0) return -1;
    memcpy(&out->s_addr, in + 12, 4);
    return 0;
}

int portmap_pcp(struct in_addr gateway, uint16_t internal_port,
                 uint16_t desired_external_port, uint32_t lifetime_sec,
                 portmap_result_t *out) {
    struct in_addr local_ip;
    if (portmap_get_local_ip(gateway, &local_ip) != 0) return -1;

    uint8_t req[60];
    memset(req, 0, sizeof(req));

    /* --- header --- */
    req[0] = 2;     /* version = 2 (PCP) */
    req[1] = 0x01;  /* R=0(request), opcode=1(MAP) */
    /* req[2..3] reserved */
    uint32_t lt = htonl(lifetime_sec);
    memcpy(req + 4, &lt, 4);
    ipv4_to_mapped_v6(local_ip, req + 8);   /* client IP (16 bytes) */

    /* --- MAP data --- */
    uint8_t *map = req + 24;
    /* nonce: normally random; used to match the response */
    static const uint8_t nonce[12] = {
        0x5A, 0x3C, 0x11, 0x9E, 0x74, 0x28, 0xB0, 0x6D, 0xF1, 0x02, 0xC7, 0x45
    };
    memcpy(map, nonce, 12);
    map[12] = 17;   /* protocol: UDP */
    /* map[13..15] reserved */
    uint16_t iport = htons(internal_port);
    uint16_t eport = htons(desired_external_port);
    memcpy(map + 16, &iport, 2);
    memcpy(map + 18, &eport, 2);
    /* suggested external IP: all-zero means "you decide" */
    struct in_addr any;
    any.s_addr = 0;
    ipv4_to_mapped_v6(any, map + 20);

    uint8_t resp[64];
    int n = gw_request(gateway, req, sizeof(req), resp, sizeof(resp), 1000);
    if (n < 60) return -1;

    if (resp[0] != 2) return -1;
    if (resp[1] != 0x81) return -1;   /* R=1 (response), opcode=1 */
    if (resp[3] != 0) return -1;      /* result code 0 = SUCCESS */

    uint32_t granted_lt;
    memcpy(&granted_lt, resp + 4, 4);

    const uint8_t *rmap = resp + 24;
    if (memcmp(rmap, nonce, 12) != 0) return -1;  /* verify nonce */

    uint16_t assigned_ext;
    memcpy(&assigned_ext, rmap + 18, 2);

    struct in_addr extip;
    if (mapped_v6_to_ipv4(rmap + 20, &extip) != 0) return -1;

    memset(out, 0, sizeof(*out));
    out->method = PORTMAP_METHOD_PCP;
    out->external_ip = extip;
    out->external_port = ntohs(assigned_ext);
    out->internal_port = internal_port;
    out->lifetime_sec = ntohl(granted_lt);
    return 0;
}

/* ------------------------------------------------------------------ */
/* UPnP IGD                                                            */
/* ------------------------------------------------------------------ */

/* split a URL into host / port / path */
static int parse_url(const char *url, char *host, size_t hostlen,
                      uint16_t *port, char *path, size_t pathlen) {
    const char *p = url;
    if (strncmp(p, "http://", 7) != 0) return -1;
    p += 7;

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    if (colon && slash && colon > slash) colon = NULL;

    size_t hlen;
    if (colon) {
        hlen = (size_t)(colon - p);
        *port = (uint16_t)atoi(colon + 1);
    } else {
        hlen = slash ? (size_t)(slash - p) : strlen(p);
        *port = 80;
    }
    if (hlen >= hostlen) return -1;
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

/* issue a plain HTTP request and collect the response */
static int http_request(const char *host, uint16_t port, const char *request,
                         char *resp, size_t resplen) {
    struct addrinfo hints, *res = NULL;
    char portstr[8];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;

    int s = socket(res->ai_family, res->ai_socktype, 0);
    if (s < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        close(s);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    size_t len = strlen(request);
    if (send(s, request, len, 0) < 0) { close(s); return -1; }

    size_t total = 0;
    while (total < resplen - 1) {
        ssize_t n = recv(s, resp + total, resplen - 1 - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    resp[total] = '\0';
    close(s);
    return (int)total;
}

/* Pull <tag>value</tag> out of an XML document.  Naive on purpose: this
 * is not a general parser, only enough for the few fields we need. */
static int xml_extract(const char *xml, const char *tag, char *out, size_t outlen) {
    char open_tag[128];
    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    const char *start = strstr(xml, open_tag);
    if (!start) return -1;
    start += strlen(open_tag);

    char close_tag[128];
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    const char *end = strstr(start, close_tag);
    if (!end) return -1;

    size_t len = (size_t)(end - start);
    if (len >= outlen) return -1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

/* Locate an InternetGatewayDevice via SSDP and return its description URL */
static int ssdp_discover(char *location, size_t locationlen) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(SSDP_PORT);
    inet_pton(AF_INET, SSDP_ADDR, &to.sin_addr);

    static const char *STS[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "upnp:rootdevice",
    };

    for (size_t i = 0; i < sizeof(STS) / sizeof(STS[0]); i++) {
        char req[512];
        snprintf(req, sizeof(req),
                 "M-SEARCH * HTTP/1.1\r\n"
                 "HOST: %s:%d\r\n"
                 "MAN: \"ssdp:discover\"\r\n"
                 "MX: 2\r\n"
                 "ST: %s\r\n"
                 "\r\n", SSDP_ADDR, SSDP_PORT, STS[i]);

        if (sendto(s, req, strlen(req), 0, (struct sockaddr *)&to, sizeof(to)) < 0)
            continue;

        /* several devices may answer, so read a few replies */
        for (int attempt = 0; attempt < 4; attempt++) {
            char buf[2048];
            ssize_t n = recvfrom(s, buf, sizeof(buf) - 1, 0, NULL, NULL);
            if (n <= 0) break;
            buf[n] = '\0';

            /* find the LOCATION header (case-insensitive) */
            const char *p = buf;
            while (*p) {
                if (strncasecmp(p, "LOCATION:", 9) == 0) {
                    p += 9;
                    while (*p == ' ') p++;
                    const char *eol = strpbrk(p, "\r\n");
                    size_t len = eol ? (size_t)(eol - p) : strlen(p);
                    if (len < locationlen) {
                        memcpy(location, p, len);
                        location[len] = '\0';
                        close(s);
                        return 0;
                    }
                }
                const char *nl = strchr(p, '\n');
                if (!nl) break;
                p = nl + 1;
            }
        }
    }
    close(s);
    return -1;
}

/* Extract the controlURL and serviceType of the WANIPConnection or
 * WANPPPConnection service from the device description */
static int find_wan_service(const char *xml, const char *base_url,
                             char *control_url, size_t curl_len,
                             char *service_type, size_t stype_len) {
    static const char *WANTED[] = {
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
    };

    for (size_t i = 0; i < sizeof(WANTED) / sizeof(WANTED[0]); i++) {
        const char *pos = strstr(xml, WANTED[i]);
        if (!pos) continue;

        /* take the first <controlURL> that follows this serviceType */
        const char *cu = strstr(pos, "<controlURL>");
        if (!cu) continue;
        cu += strlen("<controlURL>");
        const char *cu_end = strstr(cu, "</controlURL>");
        if (!cu_end) continue;

        size_t len = (size_t)(cu_end - cu);
        char raw[512];
        if (len >= sizeof(raw)) continue;
        memcpy(raw, cu, len);
        raw[len] = '\0';

        if (strlen(WANTED[i]) >= stype_len) continue;
        strcpy(service_type, WANTED[i]);

        /* controlURL is usually relative; make it absolute */
        if (strncmp(raw, "http://", 7) == 0) {
            if (strlen(raw) >= curl_len) continue;
            strcpy(control_url, raw);
        } else {
            /* reuse scheme://host:port from base_url */
            char host[256];
            uint16_t port;
            char path[512];
            if (parse_url(base_url, host, sizeof(host), &port, path, sizeof(path)) != 0)
                continue;
            int wrote = snprintf(control_url, curl_len, "http://%s:%u%s%s",
                                 host, port, raw[0] == '/' ? "" : "/", raw);
            if (wrote < 0 || (size_t)wrote >= curl_len) continue;
        }
        return 0;
    }
    return -1;
}

/* perform a SOAP action */
static int soap_call(const char *control_url, const char *service_type,
                      const char *action, const char *body_args,
                      char *resp, size_t resplen) {
    char host[256], path[512];
    uint16_t port;
    if (parse_url(control_url, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return -1;

    char body[2048];
    int blen = snprintf(body, sizeof(body),
        "<?xml version=\"1.0\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body><u:%s xmlns:u=\"%s\">%s</u:%s></s:Body></s:Envelope>\r\n",
        action, service_type, body_args ? body_args : "", action);
    if (blen < 0 || (size_t)blen >= sizeof(body)) return -1;

    char req[4096];
    int rlen = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "HOST: %s:%u\r\n"
        "CONTENT-LENGTH: %d\r\n"
        "CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n"
        "SOAPACTION: \"%s#%s\"\r\n"
        "CONNECTION: close\r\n"
        "\r\n%s",
        path, host, port, blen, service_type, action, body);
    if (rlen < 0 || (size_t)rlen >= sizeof(req)) return -1;

    int n = http_request(host, port, req, resp, resplen);
    if (n <= 0) return -1;

    /* check the status line */
    if (strstr(resp, " 200 ") == NULL) return -1;
    return 0;
}

static int upnp_get_external_ip(const char *control_url, const char *service_type,
                                 struct in_addr *out) {
    char resp[8192];
    if (soap_call(control_url, service_type, "GetExternalIPAddress", NULL,
                  resp, sizeof(resp)) != 0)
        return -1;

    char ipstr[INET_ADDRSTRLEN];
    if (xml_extract(resp, "NewExternalIPAddress", ipstr, sizeof(ipstr)) != 0)
        return -1;
    if (inet_pton(AF_INET, ipstr, out) != 1) return -1;
    return 0;
}

int portmap_upnp(uint16_t internal_port, uint16_t desired_external_port,
                  uint32_t lifetime_sec, portmap_result_t *out) {
    char location[512];
    if (ssdp_discover(location, sizeof(location)) != 0) return -1;

    /* fetch the device description */
    char host[256], path[512];
    uint16_t port;
    if (parse_url(location, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return -1;

    char req[1024];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHOST: %s:%u\r\nCONNECTION: close\r\n\r\n",
             path, host, port);

    char xml[16384];
    if (http_request(host, port, req, xml, sizeof(xml)) <= 0) return -1;

    char control_url[512], service_type[128];
    if (find_wan_service(xml, location, control_url, sizeof(control_url),
                         service_type, sizeof(service_type)) != 0)
        return -1;

    /* our LAN address, needed for NewInternalClient */
    struct in_addr gw, local_ip;
    if (portmap_get_gateway(&gw) != 0) return -1;
    if (portmap_get_local_ip(gw, &local_ip) != 0) return -1;
    char local_ip_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &local_ip, local_ip_str, sizeof(local_ip_str)))
        return -1;

    uint16_t ext = desired_external_port ? desired_external_port : internal_port;

    char args[1024];
    snprintf(args, sizeof(args),
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%u</NewExternalPort>"
        "<NewProtocol>UDP</NewProtocol>"
        "<NewInternalPort>%u</NewInternalPort>"
        "<NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>nat_traverse</NewPortMappingDescription>"
        "<NewLeaseDuration>%u</NewLeaseDuration>",
        ext, internal_port, local_ip_str, lifetime_sec);

    char resp[8192];
    if (soap_call(control_url, service_type, "AddPortMapping", args,
                  resp, sizeof(resp)) != 0) {
        /* some routers reject a finite lease; retry with 0 (indefinite) */
        snprintf(args, sizeof(args),
            "<NewRemoteHost></NewRemoteHost>"
            "<NewExternalPort>%u</NewExternalPort>"
            "<NewProtocol>UDP</NewProtocol>"
            "<NewInternalPort>%u</NewInternalPort>"
            "<NewInternalClient>%s</NewInternalClient>"
            "<NewEnabled>1</NewEnabled>"
            "<NewPortMappingDescription>nat_traverse</NewPortMappingDescription>"
            "<NewLeaseDuration>0</NewLeaseDuration>",
            ext, internal_port, local_ip_str);
        if (soap_call(control_url, service_type, "AddPortMapping", args,
                      resp, sizeof(resp)) != 0)
            return -1;
        lifetime_sec = 0;
    }

    struct in_addr extip;
    if (upnp_get_external_ip(control_url, service_type, &extip) != 0) {
        /* The mapping itself succeeded even if we cannot read the
         * external IP.  Report 0.0.0.0 and let the caller fill it in
         * from STUN. */
        extip.s_addr = 0;
    }

    memset(out, 0, sizeof(*out));
    out->method = PORTMAP_METHOD_UPNP;
    out->external_ip = extip;
    out->external_port = ext;
    out->internal_port = internal_port;
    out->lifetime_sec = lifetime_sec;
    snprintf(out->upnp_control_url, sizeof(out->upnp_control_url), "%s", control_url);
    snprintf(out->upnp_service_type, sizeof(out->upnp_service_type), "%s", service_type);
    snprintf(out->internal_client_ip, sizeof(out->internal_client_ip), "%s", local_ip_str);
    return 0;
}

/* ------------------------------------------------------------------ */
/* public entry points                                                */
/* ------------------------------------------------------------------ */

int portmap_try_all(uint16_t internal_port, uint16_t desired_external_port,
                     uint32_t lifetime_sec, portmap_result_t *out) {
    struct in_addr gw;
    if (portmap_get_gateway(&gw) == 0) {
        /* Both live on UDP 5351.  Try the newer PCP first and fall back
         * to NAT-PMP: PCP-capable routers usually accept NAT-PMP too, but
         * not the other way round. */
        if (portmap_pcp(gw, internal_port, desired_external_port,
                        lifetime_sec, out) == 0)
            return 0;
        if (portmap_natpmp(gw, internal_port, desired_external_port,
                           lifetime_sec, out) == 0)
            return 0;
    }
    /* UPnP finds the device by SSDP multicast, so it works without a known gateway */
    if (portmap_upnp(internal_port, desired_external_port, lifetime_sec, out) == 0)
        return 0;

    memset(out, 0, sizeof(*out));
    out->method = PORTMAP_METHOD_NONE;
    return -1;
}

int portmap_refresh(const portmap_result_t *m) {
    portmap_result_t tmp;
    struct in_addr gw;

    switch (m->method) {
    case PORTMAP_METHOD_NATPMP:
        if (portmap_get_gateway(&gw) != 0) return -1;
        return portmap_natpmp(gw, m->internal_port, m->external_port,
                              m->lifetime_sec, &tmp);
    case PORTMAP_METHOD_PCP:
        if (portmap_get_gateway(&gw) != 0) return -1;
        return portmap_pcp(gw, m->internal_port, m->external_port,
                           m->lifetime_sec, &tmp);
    case PORTMAP_METHOD_UPNP:
        return portmap_upnp(m->internal_port, m->external_port,
                            m->lifetime_sec, &tmp);
    default:
        return -1;
    }
}

int portmap_delete(const portmap_result_t *m) {
    struct in_addr gw;

    switch (m->method) {
    case PORTMAP_METHOD_NATPMP: {
        /* lifetime 0 with suggested external 0 means "remove" */
        if (portmap_get_gateway(&gw) != 0) return -1;
        uint8_t req[12];
        memset(req, 0, sizeof(req));
        req[1] = 1; /* UDP */
        uint16_t iport = htons(m->internal_port);
        memcpy(req + 4, &iport, 2);
        /* leave external=0, lifetime=0 */
        uint8_t resp[16];
        int n = gw_request(gw, req, sizeof(req), resp, sizeof(resp), 1000);
        return (n >= 16 && resp[1] == 129) ? 0 : -1;
    }
    case PORTMAP_METHOD_PCP: {
        /* lifetime 0 removes the mapping */
        if (portmap_get_gateway(&gw) != 0) return -1;
        portmap_result_t tmp;
        return portmap_pcp(gw, m->internal_port, m->external_port, 0, &tmp);
    }
    case PORTMAP_METHOD_UPNP: {
        char args[512];
        snprintf(args, sizeof(args),
            "<NewRemoteHost></NewRemoteHost>"
            "<NewExternalPort>%u</NewExternalPort>"
            "<NewProtocol>UDP</NewProtocol>",
            m->external_port);
        char resp[4096];
        return soap_call(m->upnp_control_url, m->upnp_service_type,
                         "DeletePortMapping", args, resp, sizeof(resp));
    }
    default:
        return -1;
    }
}
