#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include "portmap.h"
#include "holepunch.h"
#include "relay_client.h"

/*
 * Establish a P2P path using your own rendezvous server.
 *
 *   ./p2p_connect <local_port> <relay_host> <relay_port> <shared_secret>
 *
 * Compared with p2p_nostr.c this needs a host of your own, and gains two
 * things for it:
 *
 *   - No STUN.  The server sees our UDP source address directly, and can
 *     report it in the same round trip that carries the signalling.
 *   - A data fallback.  When no direct path exists -- both peers behind
 *     carrier-grade NAT being the usual reason -- the server forwards
 *     payloads.  Nostr cannot do this.
 *
 * Order of preference:
 *   1. port mapping (removes a NAT layer outright)
 *   2. direct path via hole punching
 *   3. relayed, only if 2 fails
 *
 * Step 3 is not P2P: traffic goes through the server and consumes its
 * bandwidth.  The payload is opaque to it, but it is still in the path.
 */

static portmap_result_t g_mapping;
static int g_mapping_active = 0;
static relay_client_t g_relay;
static int g_relay_active = 0;
static volatile sig_atomic_t g_running = 1;

static void cleanup(void) {
    if (g_relay_active) {
        relay_bye(&g_relay);
        g_relay_active = 0;
    }
    if (g_mapping_active) {
        fprintf(stderr, "\n[portmap] removing mapping\n");
        portmap_delete(&g_mapping);
        g_mapping_active = 0;
    }
}

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    cleanup();
    _exit(0);
}

static const char *method_name(portmap_method_t m) {
    switch (m) {
    case PORTMAP_METHOD_NATPMP: return "NAT-PMP";
    case PORTMAP_METHOD_PCP:    return "PCP";
    case PORTMAP_METHOD_UPNP:   return "UPnP IGD";
    default:                    return "none";
    }
}

/* See the note on derive_token() in p2p_nostr.c: mixing, not a KDF. */
static void derive_token(const char *secret, uint8_t out[12]) {
    size_t len = strlen(secret);
    for (int i = 0; i < 12; i++) out[i] = (uint8_t)(i * 31 + 7);
    for (size_t i = 0; i < len; i++) {
        out[i % 12] ^= (uint8_t)secret[i];
        out[(i * 7 + 3) % 12] += (uint8_t)secret[i];
    }
}

static void sleep_ms(int ms) {
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull;
}

/* Works the same whether the path is direct or relayed. */
static void chat_loop(int sockfd, int direct, struct sockaddr_in peer) {
    printf("\n--- connected (%s) ---\n", direct ? "direct" : "relayed");
    printf("type a line and press enter; Ctrl+C to quit\n\n");

    uint64_t last_ka = 0;

    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
        FD_SET(sockfd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(0, &rfds)) {
            char line[512];
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t len = strlen(line);
            if (len && line[len - 1] == '\n') line[--len] = '\0';
            if (len == 0) continue;

            if (direct)
                sendto(sockfd, line, len, 0, (struct sockaddr *)&peer, sizeof(peer));
            else
                relay_send(&g_relay, line, len);
        }

        if (FD_ISSET(sockfd, &rfds)) {
            uint8_t buf[2048];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&from, &fromlen);
            if (n <= 0) continue;

            if (direct) {
                if (holepunch_is_control_packet(buf, (size_t)n)) continue;
                buf[n] = '\0';
                printf("peer> %s\n", buf);
            } else {
                if (!relay_validate_header(buf, (size_t)n)) continue;
                relay_header_t *h = (relay_header_t *)buf;
                if (h->type != RELAY_DATA) continue;
                size_t plen = (size_t)n - sizeof(relay_header_t);
                if (plen >= sizeof(buf) - sizeof(relay_header_t)) continue;
                uint8_t *p = buf + sizeof(relay_header_t);
                p[plen] = '\0';
                printf("peer(relayed)> %s\n", p);
            }
        }

        /* The server drops peers it has not heard from in 120 s. */
        if (!direct && now_ms() - last_ka >= 20000) {
            relay_keepalive(&g_relay);
            last_ka = now_ms();
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
            "usage: %s <local_port> <relay_host> <relay_port> <shared_secret>\n"
            "\n"
            "  local_port     UDP port to bind; 0 picks a free one (recommended)\n"
            "  relay_host     host running relay_server\n"
            "  relay_port     its port (3478 by default)\n"
            "  shared_secret  must match exactly on both peers\n"
            "\n"
            "example:\n"
            "  %s 0 relay.example.com 3478 correct-horse-battery-staple\n",
            argv[0], argv[0]);
        return 1;
    }

    uint16_t local_port = (uint16_t)atoi(argv[1]);
    const char *relay_host = argv[2];
    uint16_t relay_port = (uint16_t)atoi(argv[3]);
    const char *shared_secret = argv[4];

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    setvbuf(stdout, NULL, _IOLBF, 0);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(local_port);
    if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        return 1;
    }
    socklen_t llen = sizeof(local);
    getsockname(sockfd, (struct sockaddr *)&local, &llen);
    local_port = ntohs(local.sin_port);
    printf("[local] bound UDP %u\n", local_port);

    /* 1. Port mapping. */
    printf("[portmap] asking the router (NAT-PMP / PCP / UPnP)\n");
    if (portmap_try_all(local_port, local_port, 3600, &g_mapping) == 0) {
        g_mapping_active = 1;
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_mapping.external_ip, ipbuf, sizeof(ipbuf));
        printf("[portmap] mapped via %s: %s:%u\n",
               method_name(g_mapping.method), ipbuf, g_mapping.external_port);
        if (g_mapping.external_ip.s_addr != 0 &&
            !portmap_is_global_ip(g_mapping.external_ip))
            printf("[portmap] note: external IP is private/CGNAT, so there is "
                   "another NAT upstream and this mapping does not help\n");
    } else {
        printf("[portmap] unavailable (unsupported or disabled)\n");
    }

    /* 2. Rendezvous.  No STUN needed: the server reports what it sees. */
    if (relay_client_init(&g_relay, sockfd, relay_host, relay_port,
                          shared_secret) != 0) {
        fprintf(stderr, "[relay] cannot resolve %s\n", relay_host);
        cleanup();
        return 1;
    }
    g_relay_active = 1;

    printf("[relay] registered with %s:%u, waiting for peer (up to 120 s)\n",
           relay_host, relay_port);

    if (relay_rendezvous(&g_relay, 120000) != 0) {
        fprintf(stderr, "[relay] peer never appeared -- is the secret identical "
                        "on both sides?\n");
        cleanup();
        return 1;
    }

    if (g_relay.have_observed) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_relay.observed.sin_addr, ip, sizeof(ip));
        printf("[relay] server sees us as %s:%u\n",
               ip, ntohs(g_relay.observed.sin_port));
    }
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_relay.peer.sin_addr, ip, sizeof(ip));
        printf("[relay] found peer at %s:%u\n", ip, ntohs(g_relay.peer.sin_port));
    }

    /* 3. Punch.  The server sent PEER_INFO to both of us back to back;
     *    waiting the same relative delay lines us up without needing
     *    synchronised clocks. */
    printf("[punch] starting in %u ms\n", g_relay.punch_delay_ms);
    sleep_ms(g_relay.punch_delay_ms);

    uint8_t token[12];
    derive_token(shared_secret, token);

    holepunch_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sockfd = sockfd;
    cfg.peer = g_relay.peer;
    memcpy(cfg.session_token, token, 12);
    cfg.burst_interval_ms = 200;
    cfg.overall_timeout_ms = 10000;  /* rendezvous already lined us up */
    cfg.start_at_epoch_ms = 0;

    holepunch_result_t hp;
    holepunch_run(&cfg, &hp);

    if (hp.success) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hp.confirmed_peer.sin_addr, ip, sizeof(ip));
        printf("[punch] connected to %s:%u\n",
               ip, ntohs(hp.confirmed_peer.sin_port));

        /* Direct path is up; the server is no longer needed. */
        relay_bye(&g_relay);
        g_relay_active = 0;

        holepunch_start_keepalive(sockfd, hp.confirmed_peer, token, 15000);
        chat_loop(sockfd, 1, hp.confirmed_peer);
        holepunch_stop_keepalive();
    } else {
        /* 4. Fall back to relaying. */
        printf("[punch] failed, falling back to the relay\n");
        printf("[relay] note: this is no longer peer to peer -- traffic goes\n");
        printf("        through the server (which cannot read it)\n");
        g_relay.relay_mode = 1;
        chat_loop(sockfd, 0, g_relay.peer);
    }

    cleanup();
    close(sockfd);
    return 0;
}
