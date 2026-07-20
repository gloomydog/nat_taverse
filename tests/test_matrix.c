#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>

#include "holepunch.h"
#include "netaddr.h"

/*
 * The address-family and NAT-type matrix, over loopback.
 *
 * Loopback cannot reproduce a NAT, so the NAT-type half of the matrix is
 * exercised by *simulating* what each NAT type does to the candidate a
 * peer advertises:
 *
 *   cone       the advertised address is the one packets arrive from, so
 *              the peer's advertised candidate is correct.
 *   symmetric  the NAT allocates a different mapping per destination, so
 *              the advertised candidate is WRONG -- packets arrive from a
 *              port the peer never announced. This is simulated by handing
 *              one side a deliberately wrong port for the other.
 *
 * That second case is the whole reason confirmation is done on the
 * observed source address rather than the advertised candidate, so it is
 * worth testing directly: a "cone vs symmetric" pair must still connect
 * even though one side was told the wrong port.
 */

static int failures = 0;
static int skipped  = 0;

static void ok(const char *what, int cond) {
    printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) failures++;
}

static void skip(const char *what, const char *why) {
    printf("  skip %s (%s)\n", what, why);
    skipped++;
}

/* family: 4 = AF_INET, 6 = AF_INET6 with V6ONLY, 0 = dual stack.
 *
 * Fills addr[] with the candidates this host would advertise, and returns
 * how many. A dual-stack host advertises *both* families -- that is what
 * gather() does with a real socket, and it is the whole reason a dual peer
 * can talk to an IPv4-only one. Handing the test a single candidate would
 * make dual-vs-IPv4 fail for a reason the real code does not have. */
static int open_sock(int family, netaddr_t *addr, int *naddr) {
    int fd;
    uint16_t port = 0;

    if (family == 4) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in s;
        memset(&s, 0, sizeof(s));
        s.sin_family = AF_INET;
        s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd, (struct sockaddr *)&s, sizeof(s)) != 0) { close(fd); return -1; }
        socklen_t sl = sizeof(s);
        getsockname(fd, (struct sockaddr *)&s, &sl);
        netaddr_from_string(&addr[0], "127.0.0.1", ntohs(s.sin_port));
        *naddr = 1;
        return fd;
    }

    if (family == 6) {
        fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
        int on = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        struct sockaddr_in6 s;
        memset(&s, 0, sizeof(s));
        s.sin6_family = AF_INET6;
        s.sin6_addr = in6addr_loopback;
        if (bind(fd, (struct sockaddr *)&s, sizeof(s)) != 0) { close(fd); return -1; }
        socklen_t sl = sizeof(s);
        getsockname(fd, (struct sockaddr *)&s, &sl);
        netaddr_from_string(&addr[0], "::1", ntohs(s.sin6_port));
        *naddr = 1;
        return fd;
    }

    fd = netaddr_open_dualstack_udp(&port);
    if (fd < 0) return -1;
    /* Reachable on both families on the one socket, so both are offered
     * and the punch races them. */
    netaddr_from_string(&addr[0], "::1", port);
    netaddr_from_string(&addr[1], "127.0.0.1", port);
    *naddr = 2;
    return fd;
}

typedef struct {
    int fd;
    netaddr_t peers[2];
    int npeers;
    uint8_t key[NT_PUNCH_KEY_LEN];
    int timeout_ms;
    holepunch_result_t result;
} arg_t;

static void *punch_thread(void *p) {
    arg_t *a = p;
    holepunch_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sockfd = a->fd;
    cfg.npeers = a->npeers;
    for (int i = 0; i < a->npeers; i++) cfg.peers[i] = a->peers[i];
    cfg.resend_interval_ms = 25;
    cfg.overall_timeout_ms = a->timeout_ms;
    memcpy(cfg.punch_key, a->key, sizeof(cfg.punch_key));
    holepunch_run(&cfg, &a->result);
    return NULL;
}

/* Punch two sockets at each other. wrong_port_for_a, when non-zero,
 * replaces the port A is told to aim at -- simulating a symmetric NAT on
 * B's side, whose advertised candidate does not match where its packets
 * actually come from. Returns 1 if both sides confirmed. */
static int try_pair(int fam_a, int fam_b, int timeout_ms, int break_a_target,
                    int *both_ok) {
    netaddr_t addr_a[2], addr_b[2];
    int na = 0, nb = 0;
    int fd_a = open_sock(fam_a, addr_a, &na);
    int fd_b = open_sock(fam_b, addr_b, &nb);
    if (fd_a < 0 || fd_b < 0) {
        if (fd_a >= 0) close(fd_a);
        if (fd_b >= 0) close(fd_b);
        return -1;   /* family unavailable on this host */
    }

    uint8_t key[NT_PUNCH_KEY_LEN];
    randombytes_buf(key, sizeof(key));

    arg_t pa = { .fd = fd_a, .npeers = nb, .timeout_ms = timeout_ms };
    arg_t pb = { .fd = fd_b, .npeers = na, .timeout_ms = timeout_ms };
    for (int i = 0; i < nb; i++) pa.peers[i] = addr_b[i];
    for (int i = 0; i < na; i++) pb.peers[i] = addr_a[i];

    if (break_a_target) {
        /* A aims at a port B is not listening on: B's "advertised"
         * candidate is a lie, as under symmetric NAT. A can still be
         * reached by B, and must confirm on B's real source address. */
        for (int i = 0; i < pa.npeers; i++) {
            uint16_t p = netaddr_port(&pa.peers[i]);
            netaddr_set_port(&pa.peers[i], (uint16_t)(p ^ 0x1fff));
        }
    }

    memcpy(pa.key, key, sizeof(key));
    memcpy(pb.key, key, sizeof(key));

    pthread_t ta, tb;
    pthread_create(&ta, NULL, punch_thread, &pa);
    pthread_create(&tb, NULL, punch_thread, &pb);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    *both_ok = pa.result.success && pb.result.success;

    close(fd_a);
    close(fd_b);
    return 0;
}

static void expect(const char *label, int fam_a, int fam_b, int want,
                   int break_a) {
    int both = 0;
    int rc = try_pair(fam_a, fam_b, want ? 3000 : 1200, break_a, &both);
    if (rc != 0) { skip(label, "address family unavailable"); return; }
    ok(label, both == want);
}

int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium init failed\n"); return 1; }

    printf("address family matrix (4 = IPv4-only, 6 = IPv6-only, D = dual):\n");
    expect("IPv4   vs IPv4    connects", 4, 4, 1, 0);
    expect("IPv6   vs IPv6    connects", 6, 6, 1, 0);
    expect("dual   vs dual    connects", 0, 0, 1, 0);
    expect("IPv6   vs dual    connects", 6, 0, 1, 0);
    expect("IPv4   vs dual    connects", 4, 0, 1, 0);
    expect("IPv4   vs IPv6    CANNOT",   4, 6, 0, 0);

    printf("\nNAT mapping behaviour (advertised candidate wrong = symmetric):\n");
    expect("cone   vs cone      connects", 0, 0, 1, 0);
    expect("cone   vs symmetric connects", 0, 0, 1, 1);

    printf("\n  note: symmetric vs symmetric is not reproducible on loopback --\n");
    printf("        neither side can learn the other's real port, which is the\n");
    printf("        definition of the failure. It is covered by reasoning, not\n");
    printf("        by this test.\n");

    printf("\n%s (%d skipped)\n", failures ? "FAILED" : "all passed", skipped);
    return failures ? 1 : 0;
}
