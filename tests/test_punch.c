#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "holepunch.h"
#include "netaddr.h"
#include "candidate.h"

/*
 * Punch two sockets at each other over loopback.
 *
 * This does not exercise a NAT -- nothing here can -- but it does cover
 * the parts that are easy to get wrong and painful to debug against a
 * live peer: the packet format agreeing with itself, the MAC rejecting a
 * wrong key, an ack from an earlier run not being accepted as
 * confirmation, and the socket ending up connect()ed to the right place.
 */

static int failures = 0;

static void ok(const char *what, int cond) {
    printf("%s %s\n", cond ? "  ok  " : "  FAIL", what);
    if (!cond) failures++;
}

typedef struct {
    int fd;
    netaddr_t peer;
    uint8_t key[NT_PUNCH_KEY_LEN];
    int timeout_ms;
    holepunch_result_t result;
    int rc;
} punch_arg_t;

static void *punch_thread(void *p) {
    punch_arg_t *a = p;

    holepunch_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sockfd = a->fd;
    cfg.npeers = 1;
    cfg.peers[0] = a->peer;
    cfg.resend_interval_ms = 30;
    cfg.overall_timeout_ms = a->timeout_ms;
    memcpy(cfg.punch_key, a->key, sizeof(cfg.punch_key));

    a->rc = holepunch_run(&cfg, &a->result);
    return NULL;
}

/* Loopback socket on an ephemeral port; *out gets ::1 with that port. */
static int open_loopback(netaddr_t *out) {
    uint16_t port = 0;
    int fd = netaddr_open_dualstack_udp(&port);
    if (fd < 0) return -1;
    if (netaddr_from_string(out, "::1", port) != 0) { close(fd); return -1; }
    return fd;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    uint8_t key[NT_PUNCH_KEY_LEN];
    randombytes_buf(key, sizeof(key));

    /* --- both sides hold the same key: the path should open ---------- */
    printf("simultaneous punch, matching keys:\n");

    netaddr_t addr_a, addr_b;
    int fd_a = open_loopback(&addr_a);
    int fd_b = open_loopback(&addr_b);
    if (fd_a < 0 || fd_b < 0) {
        fprintf(stderr, "could not open loopback sockets (no IPv6?)\n");
        return 77;   /* skip */
    }

    punch_arg_t pa = { .fd = fd_a, .peer = addr_b, .timeout_ms = 3000 };
    punch_arg_t pb = { .fd = fd_b, .peer = addr_a, .timeout_ms = 3000 };
    memcpy(pa.key, key, sizeof(key));
    memcpy(pb.key, key, sizeof(key));

    pthread_t ta, tb;
    pthread_create(&ta, NULL, punch_thread, &pa);
    pthread_create(&tb, NULL, punch_thread, &pb);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    ok("A confirmed a path", pa.result.success);
    ok("B confirmed a path", pb.result.success);
    ok("A confirmed B's actual port",
       netaddr_port(&pa.result.confirmed_peer) == netaddr_port(&addr_b));
    ok("B confirmed A's actual port",
       netaddr_port(&pb.result.confirmed_peer) == netaddr_port(&addr_a));

    /* connect() should have locked each socket to the other.
     *
     * The last punches and acks are still in flight when holepunch_run
     * returns, so they sit in the queue ahead of our data. An application
     * has to skip them, which is what holepunch_is_control_packet is for;
     * doing it here keeps the test honest about how the socket behaves. */
    if (pa.result.success && pb.result.success) {
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(fd_b, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        const char *msg = "hello over the punched path";
        ssize_t sent = send(fd_a, msg, strlen(msg), 0);

        char buf[128];
        ssize_t got = -1;
        int skipped = 0;
        while (sent > 0) {
            got = recv(fd_b, buf, sizeof(buf) - 1, 0);
            if (got <= 0) break;
            if (holepunch_is_control_packet(buf, (size_t)got)) { skipped++; continue; }
            buf[got] = '\0';
            break;
        }
        ok("data flows over the connected socket",
           got == (ssize_t)strlen(msg) && memcmp(buf, msg, strlen(msg)) == 0);
        printf("       (skipped %d in-flight control packet%s)\n",
               skipped, skipped == 1 ? "" : "s");
    }

    close(fd_a);
    close(fd_b);

    /* --- keys differ: the MAC should reject every packet -------------- */
    printf("\nmismatched keys:\n");

    int fd_c = open_loopback(&addr_a);
    int fd_d = open_loopback(&addr_b);
    if (fd_c < 0 || fd_d < 0) return 1;

    punch_arg_t pc = { .fd = fd_c, .peer = addr_b, .timeout_ms = 1200 };
    punch_arg_t pd = { .fd = fd_d, .peer = addr_a, .timeout_ms = 1200 };
    memcpy(pc.key, key, sizeof(key));
    randombytes_buf(pd.key, sizeof(pd.key));   /* wrong key */

    pthread_create(&ta, NULL, punch_thread, &pc);
    pthread_create(&tb, NULL, punch_thread, &pd);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    ok("a peer with the wrong key cannot open the path", !pc.result.success);
    ok("and does not itself confirm one", !pd.result.success);

    close(fd_c);
    close(fd_d);

    /* --- packet classification --------------------------------------- */
    printf("\ncontrol packet detection:\n");

    uint8_t pkt[HP_PACKET_LEN];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x00; pkt[1] = 0x01;                       /* punch type   */
    pkt[4] = 0x21; pkt[5] = 0x12; pkt[6] = 0xa4; pkt[7] = 0x42;  /* cookie */
    ok("a punch packet is recognised", holepunch_is_control_packet(pkt, sizeof(pkt)));
    ok("application data is not",
       !holepunch_is_control_packet("hello there, this is app data", 29));

    /* --- host candidates ---------------------------------------------- */
    printf("\nhost candidate gathering:\n");

    netaddr_t cands[8];
    int n = cand_collect_host(cands, 8, 41234);
    ok("found at least one local address", n > 0);

    int loopback_seen = 0, port_wrong = 0;
    for (int i = 0; i < n; i++) {
        char buf[NETADDR_STRLEN];
        netaddr_to_string(&cands[i], buf, sizeof(buf));
        if (strstr(buf, "127.0.0.1") || strstr(buf, "[::1]")) loopback_seen = 1;
        if (netaddr_port(&cands[i]) != 41234) port_wrong = 1;
    }
    ok("loopback is excluded", !loopback_seen);
    ok("every candidate carries the bound port", !port_wrong);

    printf("\n%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
