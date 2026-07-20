#include "traverse.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include "candidate.h"
#include "holepunch.h"

#define MAX_CANDS SIG_MAX_CANDIDATES

static void vlog(const nt_config_t *cfg, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void vlog(const nt_config_t *cfg, const char *fmt, ...) {
    if (!cfg->verbose) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

void nt_config_default(nt_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->local_port           = 0;
    cfg->punch_attempts       = 5;
    cfg->punch_timeout_ms     = 10000;
    cfg->rebind_on_retry      = 1;
    cfg->stun_timeout_ms      = 2000;
    cfg->sync_timeout_ms      = 5000;
    cfg->discovery_timeout_ms = 120000;
    cfg->keepalive_ms         = 15000;
    cfg->verbose              = 0;
}

/* How often to re-announce while waiting at the barrier. Ephemeral relay
 * events are not stored, so a single announcement is only seen by a peer
 * that happens to already be listening. */
#define BARRIER_REPUB_MS 1500

/* ---------------------------- candidate gathering ----------------------- */

/* Where the reflexive candidates ended up in the list.
 *
 * The reflexive entries are the only ones that go stale while the socket
 * stays bound, so they are the ones re-measured before each attempt. That
 * refresh has to *overwrite* the slot rather than append a second entry:
 * appending leaves the dead mapping in the list for the peer to waste
 * punches on, and -- because the list is capped -- silently drops the
 * fresh address entirely once the cap is reached, which is the case on any
 * host with a few interfaces (VPN, container bridge, IPv6 privacy
 * addresses). The refresh then does nothing at all, without saying so. */
typedef struct { int v4, v6; } srflx_slots_t;

/* Add if new, and report the slot either way. -1 when the list is full. */
static int cand_slot(sig_candidates_t *c, const netaddr_t *a) {
    for (int i = 0; i < c->n; i++)
        if (netaddr_equal(&c->addr[i], a)) return i;
    if (c->n >= MAX_CANDS) return -1;
    c->addr[c->n] = *a;
    return c->n++;
}

/* The reflexive addresses STUN reports, then whatever host addresses fit.
 *
 * Order matters, and it is the reverse of what feels natural. Host
 * addresses are free to gather, so collecting them first is tempting --
 * but there can be a lot of them (several interfaces, a VPN or two,
 * container bridges, plus a rotating set of IPv6 privacy addresses), and
 * the list is capped. Fill it with host addresses first and the reflexive
 * candidate gets silently crowded out, which is precisely the one that
 * carries an ordinary IPv4-behind-NAT peer. So the measured addresses go
 * in first and host addresses take the remaining slots.
 *
 * Host addresses still earn their place: they are the only thing that
 * works when both peers sit behind the *same* NAT, where both reflexive
 * candidates point at the router's external address and hairpinning may
 * not be supported.
 *
 * *nat receives the mapping verdict when it was measured (attempt 1 only;
 * later rounds skip it, since it is diagnostic and costs two round trips).
 */
static int gather(const nt_config_t *cfg, int sockfd, uint16_t port,
                  sig_candidates_t *out, nat_type_t *nat, srflx_slots_t *slots) {
    memset(out, 0, sizeof(*out));
    slots->v4 = slots->v6 = -1;

    netaddr_t srflx;
    int have_srflx = 0;

    if (nat) {
        /* One pass gets both the verdict and a candidate. */
        *nat = stun_nat_type(sockfd, cfg->stun_timeout_ms, &srflx);
        have_srflx = (*nat != NAT_UNKNOWN);
        /* NAT_UNKNOWN means fewer than two servers answered -- but one
         * may well have, and that mapping is a perfectly good candidate.
         * stun_nat_type fills srflx whenever anything answered, so only
         * re-query when nothing did. */
        if (!have_srflx)
            have_srflx = (stun_srflx(sockfd, cfg->stun_timeout_ms, &srflx) == 0);
    } else {
        have_srflx = (stun_srflx(sockfd, cfg->stun_timeout_ms, &srflx) == 0);
    }

    if (have_srflx) slots->v4 = cand_slot(out, &srflx);

    /* The v6 reflexive address is not redundant with the host v6
     * addresses: it is the one the kernel actually sources from. See
     * stun.h. Quietly skipped when there is no IPv6 path. */
    netaddr_t srflx6;
    if (stun_srflx6(sockfd, cfg->stun_timeout_ms, &srflx6) == 0)
        slots->v6 = cand_slot(out, &srflx6);

    netaddr_t host[MAX_CANDS];
    int nhost = cand_collect_host(host, MAX_CANDS, port);
    for (int i = 0; i < nhost; i++)
        cand_add_unique(out->addr, &out->n, MAX_CANDS, &host[i]);

    return out->n;
}

static void log_candidates(const nt_config_t *cfg, const char *label,
                           const sig_candidates_t *c) {
    if (!cfg->verbose) return;
    for (int i = 0; i < c->n; i++) {
        char buf[NETADDR_STRLEN];
        fprintf(stderr, "%s %s\n", label,
                netaddr_to_string(&c->addr[i], buf, sizeof(buf)));
    }
}

/* ------------------------------- rebind --------------------------------- */

/* Close the socket and open a fresh one on an ephemeral port, then
 * re-gather. See the rationale in traverse.h.
 *
 * Returns the new fd, or -1 with the old socket left untouched so the
 * caller can carry on with it. */
static int rebind(const nt_config_t *cfg, int old_fd, sig_candidates_t *mine,
                  netaddr_t *local, srflx_slots_t *slots) {
    uint16_t port = 0;   /* deliberately not cfg->local_port: reusing it
                          * risks being handed back the same CGNAT or VPN
                          * mapping we are trying to get away from */
    int fd = netaddr_open_dualstack_udp(&port);
    if (fd < 0) return -1;

    close(old_fd);

    /* Everything measured through the old socket is now meaningless: host
     * candidates carried the old port, and the reflexive ones described a
     * mapping that no longer exists. */
    gather(cfg, fd, port, mine, NULL, slots);

    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0)
        netaddr_from_sockaddr(local, (struct sockaddr *)&ss, sl);

    vlog(cfg, "[punch] rebound to UDP %u for a fresh mapping\n", port);
    return fd;
}

/* ------------------------------ the barrier ----------------------------- */

/* Re-measure and re-swap candidates, tagged with this attempt number.
 *
 * Two jobs at once. The reflexive port may have drifted since it was last
 * measured, so the peer could be aiming at an address that is already
 * wrong. And the exchange is a barrier both sides pass through together,
 * so their next punch windows overlap instead of drifting apart.
 *
 * We announce repeatedly for the whole wait rather than once at the top.
 * The two sides do not arrive here together -- the STUN probes above alone
 * can stagger them by seconds, and each side's punch window is twice this
 * barrier's timeout -- and on an ephemeral-event backend nothing is
 * stored, so a single announcement is seen only by a peer that was already
 * listening when it went out. Announcing once is how one side ends up
 * punching an address the other never received.
 *
 * *attempt is raised if the peer turns out to be on a later round: it has
 * moved on and will not repeat the round we asked for, so following it is
 * the only way back into step. See signaling.h.
 *
 * A timeout here is not fatal and not even unusual: if the peer has
 * already confirmed and moved on, it is no longer answering. We punch
 * anyway with the candidates we have and confirm on its keepalives. */
static void barrier(const nt_config_t *cfg, signaling_backend_t *sig,
                    int sockfd, int *attempt, const srflx_slots_t *slots,
                    sig_candidates_t *mine, sig_candidates_t *theirs) {
    /* Refresh only the reflexive entries; the host ones cannot drift while
     * the socket stays bound. Overwrite in place -- see srflx_slots_t. */
    netaddr_t srflx;
    if (slots->v4 >= 0 && stun_srflx(sockfd, cfg->stun_timeout_ms, &srflx) == 0)
        mine->addr[slots->v4] = srflx;
    netaddr_t srflx6;
    if (slots->v6 >= 0 && stun_srflx6(sockfd, cfg->stun_timeout_ms, &srflx6) == 0)
        mine->addr[slots->v6] = srflx6;

    mine->round = (uint8_t)*attempt;
    if (sig->publish(sig->ctx, mine) != 0) return;

    long deadline = now_ms() + cfg->sync_timeout_ms;
    while (now_ms() < deadline) {
        long slice = deadline - now_ms();
        if (slice > BARRIER_REPUB_MS) slice = BARRIER_REPUB_MS;

        sig_candidates_t fresh;
        memset(&fresh, 0, sizeof(fresh));
        fresh.round = (uint8_t)*attempt;
        if (sig->wait_peer(sig->ctx, &fresh, (int)slice) == 0 && fresh.n > 0) {
            *theirs = fresh;
            if (fresh.round > (uint8_t)*attempt) {
                vlog(cfg, "[sync] peer is on round %u; catching up\n", fresh.round);
                *attempt = fresh.round;
                /* Our announcement went out under the round we *were* on,
                 * which the peer now discards as stale -- so it is still
                 * holding whatever address it had for us. Re-announce under
                 * the round it is actually listening for. */
                mine->round = fresh.round;
                sig->publish(sig->ctx, mine);
            }
            log_candidates(cfg, "[sync] peer candidate", theirs);
            return;
        }
        if (now_ms() < deadline) sig->publish(sig->ctx, mine);
    }
    vlog(cfg, "[sync] no answer for round %d; punching with what we have\n",
         *attempt);
}

/* -------------------------------- connect ------------------------------- */

/* Publish until the peer shows up.
 *
 * Republishing is not optional with an ephemeral-event backend: a peer
 * that subscribes later never sees an announcement made earlier, so a
 * single publish makes discovery depend on who started first.
 *
 * Re-running STUN while waiting is also deliberate. A long wait is a long
 * time for the NAT to rotate the punch socket's mapping, and traffic on
 * that socket is what keeps it alive -- which is exactly what a STUN probe
 * produces. */
static int discover(const nt_config_t *cfg, signaling_backend_t *sig,
                    int sockfd, sig_candidates_t *mine,
                    sig_candidates_t *theirs) {
    const int warm_ms  = 10000;
    const int repub_ms = 3000;

    long deadline = now_ms() + cfg->discovery_timeout_ms;
    long warm_at  = now_ms() + warm_ms;

    mine->round = 0;

    while (now_ms() < deadline) {
        if (sig->publish(sig->ctx, mine) != 0) {
            vlog(cfg, "[sync] publish failed\n");
            return -1;
        }

        memset(theirs, 0, sizeof(*theirs));
        theirs->round = 0;
        if (sig->wait_peer(sig->ctx, theirs, repub_ms) == 0 && theirs->n > 0)
            return 0;

        if (now_ms() >= warm_at) {
            netaddr_t tmp;
            stun_srflx(sockfd, cfg->stun_timeout_ms, &tmp);
            warm_at = now_ms() + warm_ms;
        }
    }
    return -1;
}

int nt_connect(const nt_config_t *cfg, signaling_backend_t *sig,
               nt_session_t *out) {
    memset(out, 0, sizeof(*out));
    out->sockfd = -1;

    uint16_t port = cfg->local_port;
    int fd = netaddr_open_dualstack_udp(&port);
    if (fd < 0) {
        vlog(cfg, "[local] could not open a UDP socket\n");
        return -1;
    }
    vlog(cfg, "[local] bound UDP %u\n", port);

    sig_candidates_t mine, theirs;
    srflx_slots_t slots;
    if (gather(cfg, fd, port, &mine, &out->nat, &slots) == 0) {
        vlog(cfg, "[stun] no candidates at all; cannot continue\n");
        goto fail;
    }
    vlog(cfg, "[stun] NAT mapping looks %s\n", nat_type_str(out->nat));
    log_candidates(cfg, "[stun] our candidate", &mine);

    if (discover(cfg, sig, fd, &mine, &theirs) != 0) {
        vlog(cfg, "[sync] peer never appeared\n");
        goto fail;
    }
    log_candidates(cfg, "[sync] peer candidate", &theirs);

    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0)
        netaddr_from_sockaddr(&out->local, (struct sockaddr *)&ss, sl);

    int attempts = cfg->punch_attempts > 0 ? cfg->punch_attempts : 1;
    holepunch_result_t hp;
    memset(&hp, 0, sizeof(hp));

    /* Discovery ends the moment we see the peer, which says nothing about
     * whether it has seen us. If it announced from a later round it is
     * already retrying, so start where it is rather than at 1: it will not
     * announce round 1 again for us to answer. */
    int first = theirs.round > 0 ? theirs.round : 1;

    for (int attempt = first; attempt <= attempts; attempt++) {
        if (attempt > first && cfg->rebind_on_retry) {
            int nfd = rebind(cfg, fd, &mine, &out->local, &slots);
            if (nfd >= 0) fd = nfd;
        }

        /* Before every attempt, including the first: the reflexive address
         * gathered before the discovery wait may already be stale by the
         * time the peer answers, and attempt 1 must not punch from it.
         * May raise `attempt` if the peer is further along. */
        barrier(cfg, sig, fd, &attempt, &slots, &mine, &theirs);

        holepunch_config_t hc;
        memset(&hc, 0, sizeof(hc));
        hc.sockfd = fd;
        hc.npeers = theirs.n > HP_MAX_CANDIDATES ? HP_MAX_CANDIDATES : theirs.n;
        for (int i = 0; i < hc.npeers; i++) hc.peers[i] = theirs.addr[i];
        hc.resend_interval_ms = 60;
        hc.overall_timeout_ms = cfg->punch_timeout_ms;
        memcpy(hc.punch_key, cfg->punch_key, NT_PUNCH_KEY_LEN);

        vlog(cfg, "[punch] attempt %d/%d, %d candidate%s, up to %ds\n",
             attempt, attempts, hc.npeers, hc.npeers == 1 ? "" : "s",
             cfg->punch_timeout_ms / 1000);

        int prc = holepunch_run(&hc, &hp);
        nt_wipe(&hc, sizeof(hc));

        out->attempts_used = attempt;
        if (hp.success) break;

        /* -1 means not one candidate was even reachable from this socket,
         * which on a dual-stack socket cannot happen and on a single-stack
         * one means the peer offered nothing in our address family: an
         * IPv4-only host facing an IPv6-only peer, or the reverse. No
         * amount of retrying invents a shared family, and re-exchanging
         * only re-delivers the same unreachable list, so stop now rather
         * than burn the whole retry budget discovering it five times. */
        if (prc < 0) {
            vlog(cfg, "[punch] no candidate reachable from this socket -- the "
                      "peer offered no address in our family (IPv4 vs IPv6); "
                      "a direct path is impossible\n");
            break;
        }

        if (attempt < attempts) vlog(cfg, "[punch] no path yet; retrying\n");
    }

    if (!hp.success) {
        vlog(cfg, "[punch] failed after %d attempt%s\n",
             out->attempts_used, out->attempts_used == 1 ? "" : "s");
        goto fail;
    }

    out->sockfd = fd;
    out->peer   = hp.confirmed_peer;

    {
        char buf[NETADDR_STRLEN];
        vlog(cfg, "[punch] direct path to %s (%s)\n",
             netaddr_to_string(&out->peer, buf, sizeof(buf)),
             netaddr_family(&out->peer) == AF_INET6 ? "IPv6" : "IPv4");
    }

    if (cfg->keepalive_ms > 0 &&
        holepunch_start_keepalive(fd, cfg->punch_key, cfg->keepalive_ms) == 0)
        out->keepalive_running = 1;

    return 0;

fail:
    close(fd);
    out->sockfd = -1;
    return -1;
}

void nt_close(nt_session_t *s) {
    if (!s) return;

    if (s->keepalive_running) {
        holepunch_stop_keepalive();
        s->keepalive_running = 0;
    }
    if (s->sockfd >= 0) {
        close(s->sockfd);
        s->sockfd = -1;
    }
}
