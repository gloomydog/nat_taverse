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

#include "stun.h"
#include "portmap.h"
#include "holepunch.h"
#include "signaling_nostr.h"

/*
 * Establish a direct P2P path using public Nostr relays for rendezvous.
 * No server of your own.
 *
 *   ./p2p_nostr <local_port> <shared_secret> [relay_url ...]
 *
 * Sequence:
 *   1. ask the router for a port mapping (removes one NAT layer if it works)
 *   2. ask STUN what our public address is
 *   3. publish it, encrypted, on Nostr; wait for the peer to do the same
 *   4. punch
 *
 * If step 4 fails there is nothing left to try: Nostr cannot relay data.
 * That is the expected outcome when both peers sit behind carrier-grade
 * NAT.  Use relay_server + p2p_connect for that case.
 *
 * Compare p2p_connect.c, which needs a host of your own but can fall back
 * to relaying.
 */

static portmap_result_t g_mapping;
static int g_mapping_active = 0;
static volatile sig_atomic_t g_running = 1;

static void cleanup(void) {
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

/* Derive the punch token from the shared secret.
 *
 * Simple mixing, not a KDF.  The token only has to be unguessable enough
 * that an unrelated datagram is not mistaken for the peer; it is not a
 * security boundary.  See README, "Security". */
static void derive_token(const char *secret, uint8_t out[12]) {
    size_t len = strlen(secret);
    for (int i = 0; i < 12; i++) out[i] = (uint8_t)(i * 31 + 7);
    for (size_t i = 0; i < len; i++) {
        out[i % 12] ^= (uint8_t)secret[i];
        out[(i * 7 + 3) % 12] += (uint8_t)secret[i];
    }
}

/* Trivial chat, just to show the path carries traffic.  In a real
 * application this is where you would run your key exchange and then your
 * own protocol. */
static void chat_loop(int sockfd, struct sockaddr_in peer) {
    printf("\n--- connected (direct) ---\n");
    printf("type a line and press enter; Ctrl+C to quit\n\n");

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
            sendto(sockfd, line, len, 0, (struct sockaddr *)&peer, sizeof(peer));
        }

        if (FD_ISSET(sockfd, &rfds)) {
            uint8_t buf[2048];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&from, &fromlen);
            if (n <= 0) continue;
            /* keepalives share this socket */
            if (holepunch_is_control_packet(buf, (size_t)n)) continue;
            buf[n] = '\0';
            printf("peer> %s\n", buf);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <local_port> <shared_secret> [relay_url ...]\n"
            "\n"
            "  local_port     UDP port to bind; 0 picks a free one (recommended)\n"
            "  shared_secret  must match exactly on both peers\n"
            "  relay_url      Nostr relays; defaults to a few public ones\n"
            "\n"
            "examples:\n"
            "  %s 0 correct-horse-battery-staple\n"
            "  %s 0 my-secret wss://relay.damus.io wss://nos.lol\n"
            "\n"
            "environment:\n"
            "  NAT_TRAVERSE_STUN_HOST / NAT_TRAVERSE_STUN_PORT\n"
            "      override the default STUN server\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    uint16_t local_port = (uint16_t)atoi(argv[1]);
    const char *shared_secret = argv[2];

    static const char *default_relays[] = {
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.nostr.band",
    };
    const char **relays;
    int nrelays;
    if (argc > 3) {
        relays = (const char **)&argv[3];
        nrelays = argc - 3;
    } else {
        relays = default_relays;
        nrelays = (int)(sizeof(default_relays) / sizeof(default_relays[0]));
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* Keep stdout in step with stderr when redirected to a file. */
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

    /* 2. STUN.  Nostr rides TCP and cannot see our UDP mapping, so unlike
     *    the relay_server backend we have to ask a STUN server ourselves. */
    const char *stun_host = getenv("NAT_TRAVERSE_STUN_HOST");
    uint16_t stun_port = 19302;
    if (stun_host) {
        const char *ps = getenv("NAT_TRAVERSE_STUN_PORT");
        stun_port = ps ? (uint16_t)atoi(ps) : 3478;
    } else {
        stun_host = "stun.l.google.com";
    }

    stun_result_t sr;
    if (stun_get_mapped_address(sockfd, stun_host, stun_port, 2000, &sr) != 0) {
        fprintf(stderr, "[stun] no answer from %s:%u\n", stun_host, stun_port);
        cleanup();
        return 1;
    }
    printf("[stun] public address %s:%u (via %s)\n",
           inet_ntoa(sr.mapped_addr.sin_addr), ntohs(sr.mapped_addr.sin_port),
           stun_host);

    /* 3. Rendezvous over Nostr. */
    signaling_backend_t sig;
    if (signaling_nostr_create(&sig, relays, nrelays, shared_secret, 1) != 0) {
        fprintf(stderr, "[nostr] no relay reachable\n");
        cleanup();
        return 1;
    }

    printf("[nostr] waiting for peer (up to 120 s)\n");
    struct sockaddr_in peer;
    int found = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* Ephemeral events are not stored, so a peer that subscribes later
     * will never see an announcement we made earlier.  Keep re-publishing. */
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long elapsed = (t1.tv_sec - t0.tv_sec) * 1000 +
                       (t1.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed >= 120000) break;

        if (sig.publish(sig.ctx, &sr.mapped_addr) != 0) {
            fprintf(stderr, "[nostr] publish failed\n");
            break;
        }
        if (sig.wait_peer(sig.ctx, &peer, 3000) == 0) { found = 1; break; }
    }

    if (!found) {
        fprintf(stderr, "[nostr] peer never appeared -- is the secret identical "
                        "on both sides?\n");
        sig.close(sig.ctx);
        cleanup();
        return 1;
    }

    printf("[nostr] found peer at %s:%u\n",
           inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

    /* Seeing the peer does not mean the peer has seen us.  If our earlier
     * announcements went out before they subscribed, and we stop now, they
     * will wait forever -- ephemeral events leave nothing behind to catch
     * up on.  A few more publishes cost nothing and make discovery
     * symmetric. */
    for (int i = 0; i < 4; i++) {
        sig.publish(sig.ctx, &sr.mapped_addr);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 400 * 1000000L };
        nanosleep(&ts, NULL);
    }
    sig.close(sig.ctx);

    /* 4. Punch.  Both sides start as soon as they see the other; the skew
     *    is just the difference in relay latency, which the retry loop in
     *    holepunch_run() absorbs. */
    uint8_t token[12];
    derive_token(shared_secret, token);

    holepunch_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sockfd = sockfd;
    cfg.peer = peer;
    memcpy(cfg.session_token, token, 12);
    cfg.burst_interval_ms = 200;
    cfg.overall_timeout_ms = 20000;
    cfg.start_at_epoch_ms = 0;

    printf("[punch] trying to open a direct path\n");
    holepunch_result_t hp;
    holepunch_run(&cfg, &hp);

    if (hp.success) {
        printf("[punch] connected to %s:%u\n",
               inet_ntoa(hp.confirmed_peer.sin_addr),
               ntohs(hp.confirmed_peer.sin_port));
        holepunch_start_keepalive(sockfd, hp.confirmed_peer, token, 15000);
        chat_loop(sockfd, hp.confirmed_peer);
        holepunch_stop_keepalive();
    } else {
        printf("[punch] failed. Nostr cannot relay data, so this is the end "
               "of the line.\n");
        printf("        likely causes:\n");
        printf("          - both peers behind carrier-grade NAT; a direct path\n");
        printf("            is essentially impossible, use relay_server +\n");
        printf("            p2p_connect instead\n");
        printf("          - UPnP / NAT-PMP disabled on the router\n");
        printf("          - the peer's mapping changed; retrying may work\n");
    }

    cleanup();
    close(sockfd);
    return 0;
}
