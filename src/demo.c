#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>

#include "traverse.h"
#include "holepunch.h"
#include "signaling_nostr.h"

/*
 * Demo: open a direct UDP path between two machines behind NATs, using
 * public Nostr relays to introduce them. No server of your own.
 *
 *   ./nat_demo <local_port> <shared_secret> [relay_url ...]
 *   ./nat_demo --gen-secret
 *
 * The library does the work; this file only wires it up:
 *
 *   1. stretch the passphrase into key material          crypto.c
 *   2. open a Nostr signalling backend                   signaling_nostr.c
 *   3. hand both to nt_connect()                         traverse.c
 *   4. talk over the socket it hands back
 *
 * The chat loop at the end sends and receives *plain text*. That is the
 * point of the demo -- it shows the path carries traffic -- but it is not
 * a protocol and it is not private. This library deliberately stops at
 * the open path: it authenticates the punch, so only a peer holding the
 * shared secret can open the path to you, and it connect()s the socket,
 * so the kernel drops packets from anyone else. Neither of those encrypts
 * or authenticates what you then send. Anyone on the wire can read and
 * rewrite it. A real application runs its own encrypted, authenticated
 * protocol over this socket.
 */

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/* The keepalive keeps punch packets flowing on this same socket to hold
 * the NAT mapping open, so anything that reads from it has to drop them
 * rather than hand them to the application. */
static void chat_loop(int sockfd) {
    printf("\n--- connected (plain text, not encrypted) ---\n");
    printf("type a line and press enter; Ctrl+C to quit\n\n");

    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(sockfd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            char line[512];
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t len = strlen(line);
            if (len && line[len - 1] == '\n') line[--len] = '\0';
            if (len == 0) continue;
            send(sockfd, line, len, 0);
        }

        if (FD_ISSET(sockfd, &rfds)) {
            char msg[1024];
            ssize_t n = recv(sockfd, msg, sizeof(msg) - 1, 0);
            if (n <= 0) continue;
            if (holepunch_is_control_packet(msg, (size_t)n)) continue;
            msg[n] = '\0';
            printf("peer> %s\n", msg);
        }
    }
}

static int gen_secret(void) {
    char secret[256];
    nt_generate_secret(secret, sizeof(secret));
    printf("%s\n", secret);
    fprintf(stderr,
        "\n128 bits of entropy. Give this to the other side over a channel\n"
        "you already trust, and treat it like an SSH private key.\n"
        "\n"
        "Do not invent your own passphrase. It is what both peers meet\n"
        "under on the relay and what authenticates the punch, and it is\n"
        "guessable offline.\n");
    nt_wipe(secret, sizeof(secret));
    return 0;
}

static void usage(const char *argv0) {
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
        "  NAT_TRAVERSE_STUN_SERVERS   comma-separated host[:port] list\n",
        argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (nt_crypto_init() != 0) {
        fprintf(stderr, "libsodium failed to initialise\n");
        return 1;
    }

    if (argc == 2 && strcmp(argv[1], "--gen-secret") == 0) return gen_secret();
    if (argc < 3) { usage(argv[0]); return 1; }

    uint16_t local_port = (uint16_t)atoi(argv[1]);
    const char *shared_secret = argv[2];

    static const char *default_relays[] = {
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.nostr.band",
    };
    const char **relays = default_relays;
    int nrelays = (int)(sizeof(default_relays) / sizeof(default_relays[0]));
    if (argc > 3) {
        relays = (const char **)&argv[3];
        nrelays = argc - 3;
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

    signaling_backend_t sig;
    if (signaling_nostr_create(&sig, relays, nrelays, &keys, 1) != 0) {
        fprintf(stderr, "[nostr] no relay reachable\n");
        nt_keys_wipe(&keys);
        return 1;
    }

    nt_config_t cfg;
    nt_config_default(&cfg);
    cfg.local_port = local_port;
    cfg.verbose    = 1;
    memcpy(cfg.punch_key, keys.punch_key, NT_PUNCH_KEY_LEN);

    /* The signalling backend still needs its own keys, so wipe only our
     * copy of the derived material. */
    nt_keys_wipe(&keys);

    nt_session_t s;
    int rc = nt_connect(&cfg, &sig, &s);
    nt_wipe(&cfg, sizeof(cfg));
    sig.close(sig.ctx);

    if (rc != 0) {
        fprintf(stderr,
            "\nno direct path. Nostr cannot relay data, so this is the end of\n"
            "the line. Likely causes:\n"
            "  - both peers behind carrier-grade NAT, where a direct path is\n"
            "    essentially impossible and only a relay would help\n"
            "  - UDP blocked outright on one of the networks\n"
            "  - the peer never started, or is using a different secret\n");
        return 1;
    }

    chat_loop(s.sockfd);

    nt_close(&s);
    return 0;
}
