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

#include "netaddr.h"
#include "crypto.h"
#include "stun.h"
#include "portmap.h"
#include "holepunch.h"
#include "channel.h"
#include "signaling_nostr.h"

/*
 * Open an authenticated, encrypted, direct P2P path using public Nostr
 * relays for rendezvous. No server of your own.
 *
 *   ./p2p_nostr <local_port> <shared_secret> [relay_url ...]
 *   ./p2p_nostr --gen-secret
 *
 * Sequence:
 *   1. stretch the passphrase into key material (Argon2id)
 *   2. ask the router for a port mapping, which removes one NAT layer
 *      when it works
 *   3. gather candidates: our public IPv4 and IPv6 addresses, via STUN
 *   4. publish them encrypted on Nostr, wait for the peer's
 *   5. punch every candidate at once, keep whichever answers
 *   6. run the handshake over that path, then talk encrypted
 *
 * Step 6 is not optional. Punching only produces a path; it says nothing
 * about who is on the far end and protects nothing. Without the handshake
 * anyone who reaches the port can talk to you and anyone on the path can
 * read and rewrite what you send.
 *
 * If step 5 fails there is nothing left to try, because Nostr cannot
 * relay data. That is the expected outcome when both peers sit behind
 * carrier-grade NAT: there is simply no direct path to find, and someone
 * has to forward the bytes. Every serious implementation carries a relay
 * for this reason. Adding one behind the signaling.h interface would be
 * the way to cover it.
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

/* Ask STUN over each family in turn. A host may have IPv4 only, IPv6
 * only, or both; whatever answers becomes a candidate. */
static void gather_candidates(int sockfd, const char *stun_host,
                              uint16_t stun_port, sig_candidates_t *out) {
    memset(out, 0, sizeof(*out));

    struct { int family; const char *label; } probes[] = {
        { AF_INET,  "IPv4" },
        { AF_INET6, "IPv6" },
    };

    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        if (out->n >= SIG_MAX_CANDIDATES) break;

        netaddr_t a;
        if (stun_query(sockfd, stun_host, stun_port, probes[i].family,
                       2000, &a) != 0) {
            printf("[stun] no %s answer from %s\n", probes[i].label, stun_host);
            continue;
        }

        char buf[NETADDR_STRLEN];
        printf("[stun] %s candidate %s%s\n", probes[i].label,
               netaddr_to_string(&a, buf, sizeof(buf)),
               netaddr_is_global(&a) ? "" : "  (not globally routable)");

        /* Skip duplicates: on a dual stack socket an IPv4 answer may come
         * back v4-mapped and match one we already have. */
        int dup = 0;
        for (int j = 0; j < out->n; j++)
            if (netaddr_equal(&out->addr[j], &a)) dup = 1;
        if (!dup) out->addr[out->n++] = a;
    }
}

static void print_candidates(const char *label, const sig_candidates_t *c) {
    for (int i = 0; i < c->n; i++) {
        char buf[NETADDR_STRLEN];
        printf("%s %s\n", label, netaddr_to_string(&c->addr[i], buf, sizeof(buf)));
    }
}

/* Encrypted chat, to show the path carries traffic. In a real
 * application this is where your own protocol would go. */
static void chat_loop(int sockfd, const netaddr_t *peer, hs_session_t *sess) {
    printf("\n--- connected, authenticated, encrypted ---\n");
    printf("type a line and press enter; Ctrl+C to quit\n\n");

    netaddr_t dst = *peer;
    {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(sockfd, (struct sockaddr *)&ss, &sl) == 0 &&
            ss.ss_family == AF_INET6)
            netaddr_to_v4mapped(&dst);
    }

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
            channel_send(sockfd, &dst, sess, line, len);
            nt_wipe(line, sizeof(line));
        }

        if (FD_ISSET(sockfd, &rfds)) {
            char msg[CH_MAX_PLAINTEXT + 1];
            int n = channel_recv(sockfd, sess, msg, sizeof(msg) - 1, 0);
            if (n > 0) {
                msg[n] = '\0';
                printf("peer> %s\n", msg);
                nt_wipe(msg, sizeof(msg));
            }
        }
    }
}

int main(int argc, char **argv) {
    if (nt_crypto_init() != 0) {
        fprintf(stderr, "libsodium failed to initialise\n");
        return 1;
    }

    if (argc == 2 && strcmp(argv[1], "--gen-secret") == 0) {
        char secret[256];
        nt_generate_secret(secret, sizeof(secret));
        printf("%s\n", secret);
        fprintf(stderr,
            "\n128 bits of entropy. Give this to the other side over a channel\n"
            "you already trust, and treat it like an SSH private key.\n"
            "\n"
            "Do not invent your own passphrase. An observer who captures the\n"
            "handshake can test guesses offline, and a memorable phrase will\n"
            "not survive that.\n");
        nt_wipe(secret, sizeof(secret));
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <local_port> <shared_secret> [relay_url ...]\n"
            "       %s --gen-secret\n"
            "\n"
            "  local_port     UDP port to bind; 0 picks a free one (recommended)\n"
            "  shared_secret  must match exactly on both peers\n"
            "  relay_url      Nostr relays; defaults to a few public ones\n"
            "\n"
            "examples:\n"
            "  %s --gen-secret\n"
            "  %s 0 river-quartz-lantern-moss-...\n"
            "  %s 0 <secret> wss://relay.damus.io wss://nos.lol\n"
            "\n"
            "environment:\n"
            "  NAT_TRAVERSE_STUN_HOST / NAT_TRAVERSE_STUN_PORT\n"
            "      override the default STUN server\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
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
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Deliberately slow, so say something first. */
    printf("[keys] stretching the passphrase (Argon2id)\n");
    nt_keys_t keys;
    if (nt_derive_keys(shared_secret, &keys) != 0) {
        fprintf(stderr, "[keys] derivation failed (out of memory?)\n");
        return 1;
    }

    uint16_t bound = local_port;
    int sockfd = netaddr_open_dualstack_udp(&bound);
    if (sockfd < 0) {
        perror("socket");
        nt_keys_wipe(&keys);
        return 1;
    }
    local_port = bound;
    printf("[local] bound UDP %u\n", local_port);

    /* 1. Port mapping. IPv4 only: NAT-PMP has no IPv6 form, and IPv6
     *    generally needs a firewall pinhole rather than a mapping, which
     *    punching already produces. */
    printf("[portmap] asking the router (NAT-PMP / PCP / UPnP)\n");
    if (portmap_try_all(local_port, local_port, 3600, &g_mapping) == 0) {
        g_mapping_active = 1;
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_mapping.external_ip, ipbuf, sizeof(ipbuf));
        printf("[portmap] mapped via %s: %s:%u\n",
               method_name(g_mapping.method), ipbuf, g_mapping.external_port);
        if (g_mapping.external_ip.s_addr != 0 &&
            !portmap_is_global_ip(g_mapping.external_ip))
            printf("[portmap] note: external IP is private or CGNAT, so there "
                   "is another NAT upstream and this mapping does not help\n");
    } else {
        printf("[portmap] unavailable (unsupported or disabled)\n");
    }

    /* 2. Candidates. Nostr rides TCP and so cannot observe our UDP
     *    mapping; we have to ask STUN ourselves. */
    const char *stun_host = getenv("NAT_TRAVERSE_STUN_HOST");
    uint16_t stun_port = 19302;
    if (stun_host) {
        const char *ps = getenv("NAT_TRAVERSE_STUN_PORT");
        stun_port = ps ? (uint16_t)atoi(ps) : 3478;
    } else {
        stun_host = "stun.l.google.com";
    }

    sig_candidates_t mine;
    gather_candidates(sockfd, stun_host, stun_port, &mine);
    if (mine.n == 0) {
        fprintf(stderr, "[stun] no candidates; cannot continue\n");
        nt_keys_wipe(&keys);
        cleanup();
        return 1;
    }

    /* 3. Rendezvous. */
    signaling_backend_t sig;
    if (signaling_nostr_create(&sig, relays, nrelays, &keys, 1) != 0) {
        fprintf(stderr, "[nostr] no relay reachable\n");
        nt_keys_wipe(&keys);
        cleanup();
        return 1;
    }

    printf("[nostr] waiting for peer (up to 120 s)\n");
    sig_candidates_t theirs;
    int found = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* Ephemeral events are not stored, so a peer that subscribes later
     * will never see an announcement made earlier. Keep republishing. */
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long elapsed = (t1.tv_sec - t0.tv_sec) * 1000 +
                       (t1.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed >= 120000) break;

        if (sig.publish(sig.ctx, &mine) != 0) {
            fprintf(stderr, "[nostr] publish failed\n");
            break;
        }
        if (sig.wait_peer(sig.ctx, &theirs, 3000) == 0) { found = 1; break; }
    }

    if (!found) {
        fprintf(stderr, "[nostr] peer never appeared. Is the secret identical "
                        "on both sides?\n");
        sig.close(sig.ctx);
        nt_keys_wipe(&keys);
        cleanup();
        return 1;
    }

    print_candidates("[nostr] peer candidate", &theirs);

    /* Seeing the peer does not mean the peer has seen us. If our earlier
     * announcements went out before they subscribed and we stop now, they
     * wait forever: ephemeral events leave nothing to catch up on. A few
     * more publishes cost nothing and make discovery symmetric. */
    for (int i = 0; i < 4; i++) {
        sig.publish(sig.ctx, &mine);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 400 * 1000000L };
        nanosleep(&ts, NULL);
    }
    sig.close(sig.ctx);

    /* 4. Punch every candidate at once and keep whichever answers. Both
     *    sides start as soon as they see the other; the skew is only the
     *    difference in relay latency, which the retry loop absorbs. */
    holepunch_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sockfd = sockfd;
    cfg.npeers = theirs.n;
    for (int i = 0; i < theirs.n; i++) cfg.peers[i] = theirs.addr[i];
    memcpy(cfg.session_token, keys.token, NT_TOKEN_LEN);
    cfg.burst_interval_ms = 200;
    cfg.overall_timeout_ms = 20000;

    printf("[punch] trying %d candidate%s\n", theirs.n, theirs.n == 1 ? "" : "s");
    holepunch_result_t hp;
    holepunch_run(&cfg, &hp);
    nt_wipe(&cfg, sizeof(cfg));

    if (!hp.success) {
        printf("[punch] failed. Nostr cannot relay data, so this is the end "
               "of the line.\n");
        printf("        likely causes:\n");
        printf("          - both peers behind carrier-grade NAT, where a "
               "direct path is\n");
        printf("            essentially impossible and only a relay would "
               "help\n");
        printf("          - UPnP / NAT-PMP disabled on the router\n");
        printf("          - the peer's mapping changed; retrying may work\n");
        nt_keys_wipe(&keys);
        cleanup();
        close(sockfd);
        return 1;
    }

    {
        char buf[NETADDR_STRLEN];
        printf("[punch] path open to %s\n",
               netaddr_to_string(&hp.confirmed_peer, buf, sizeof(buf)));
    }

    /* 5. Authenticate. Until this succeeds we know nothing about who is
     *    on the far end. */
    printf("[handshake] authenticating\n");
    hs_session_t sess;
    if (channel_handshake(sockfd, &hp.confirmed_peer, keys.psk, 10000, &sess) != 0) {
        fprintf(stderr,
            "[handshake] failed. The path is open, but whoever is on it did "
            "not prove\n"
            "            they hold the passphrase. Not proceeding.\n");
        nt_keys_wipe(&keys);
        cleanup();
        close(sockfd);
        return 1;
    }
    printf("[handshake] peer authenticated, session keys established\n");

    holepunch_start_keepalive(sockfd, &hp.confirmed_peer, keys.token, 15000);

    /* The punch token is no longer needed for anything but keepalive, and
     * the psk has done its job. */
    nt_keys_wipe(&keys);

    chat_loop(sockfd, &hp.confirmed_peer, &sess);

    holepunch_stop_keepalive();
    hs_session_wipe(&sess);
    cleanup();
    close(sockfd);
    return 0;
}
