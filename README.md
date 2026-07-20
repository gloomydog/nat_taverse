# nat_traverse: UDP hole punching for P2P connections

- Direct peer-to-peer UDP across NAT.
- Written in C.
- with no server of your own required. 

This library does **NAT traversal only**. It opens the path and stops
there. It does not encrypt your traffic, authenticate your peer beyond the
punch itself, or provide reliability or ordering — run your own protocol
(or DTLS, Noise, WireGuard) over the socket it returns. See
[Scope](#scope).

```c
nt_config_t cfg;
nt_config_default(&cfg);
memcpy(cfg.punch_key, my_shared_key, NT_PUNCH_KEY_LEN);

nt_session_t s;
if (nt_connect(&cfg, &my_signaling_backend, &s) == 0) {
    send(s.sockfd, "hello", 5, 0);   /* connect()ed to the peer */
    nt_close(&s);
}
```

## What it does

```
bind a dual-stack UDP socket
    │
    ├─ gather host candidates                   LAN IPv4, global IPv6
    ├─ STUN over IPv4  ──▶ reflexive candidate + mapping behaviour
    ├─ STUN over IPv6  ──▶ reflexive candidate  (skipped without IPv6)
    │
exchange candidates with the peer               your signalling backend
    │
┌─▶ punch all candidates at once, MAC-authenticated, STUN-shaped
│       │   confirm on the peer's ACTUAL source address
│       │
│       ├─ a path confirms ─▶ connect() ─▶ keepalive ─▶ done
│       └─ window expires
│             │
└── rebind to a fresh port + re-STUN + re-exchange ── retry
```

A few of these choices are less obvious than they look:

- **All candidates are punched in parallel**, so the fastest working path
  wins on its own. A same-LAN or IPv6 path confirms almost instantly; a
  NATed IPv4 path costs a round trip through the public internet.

- **The path is confirmed on the address packets actually arrived from**,
  never on the candidate the peer advertised. A peer's NAT may map a
  different port toward you than the one it announced — common on carrier
  NAT — and the observed source is the only address that works.

- **IPv6 needs STUN too.** "No NAT, so just advertise the global address"
  fails in the common case: a modern host has several global v6 addresses
  and the kernel sources outbound flows from a rotating privacy address,
  so the peer aims at an address this host never sends from and a stateful
  firewall drops everything. STUN over IPv6 reports the address really in
  use. See [BACKGROUND.md](BACKGROUND.md).

- **Retries rebind to a fresh port.** On CGNAT and VPN paths the external
  port is luck that re-STUNning cannot change, so retrying on the same
  socket re-runs a lost bet. A new socket draws new dice — which is why
  restarting by hand often connects when a retry loop does not.

- **Punch packets are shaped like STUN Binding Requests.** Some carrier
  networks treat unrecognised small UDP payloads differently from STUN
  traffic, and looking like STUN measurably improves reachability. A real
  STUN server that receives one ignores it.

## What connects

Rendezvous happens over the signalling channel; the direct path is UDP.
Whether that path can exist at all is decided by two independent things —
whether the peers share an address family, and how their NATs allocate
mappings.

**Address family.** A direct path needs a family both ends can speak.

| | IPv4-only | dual-stack | IPv6-only |
|---|---|---|---|
| **IPv4-only** | ✅ | ✅ | ❌ |
| **dual-stack** | ✅ | ✅ | ✅ |
| **IPv6-only** | ❌ | ✅ | ✅ |

IPv4-only against IPv6-only is the one impossible pair: there is no
common family, and nothing in a NAT-traversal library can create one
(that is what NAT64/DNS64 or a relay is for). This is detected rather
than waited out — the punch reports that no candidate was reachable and
`nt_connect` gives up immediately instead of spending the retry budget.

**NAT mapping behaviour.** See [BACKGROUND.md](BACKGROUND.md) §2.1.

| | cone | symmetric |
|---|---|---|
| **cone** | ✅ | ✅ |
| **symmetric** | ✅ | ❌ |

Cone against symmetric works, which is worth stating because it is not
obvious: the symmetric side's advertised candidate is wrong by
construction, but confirmation is done on the address packets *actually
arrived from*, so the cone side learns the real mapping on the first
punch it receives.

Symmetric against symmetric cannot work. Neither side can predict the
per-destination port the other's NAT will allocate, so both advertised
candidates are wrong and there is nothing to correct them against. This
is the CGNAT-vs-CGNAT case, and the only remedy is a relay, which this
library does not provide — **when no path is found the connection simply
fails.** There is no fallback.

## Layout

    src/     library and demo sources
    tests/   loopback punch tests  (make test)
    build/   objects and test binaries, disposable

The traversal core needs only libsodium. Everything else is the demo and
one signalling backend.

| file | what it does | |
|---|---|---|
| `src/traverse.c` | the whole thing in one call: bind, gather, exchange, punch, retry | core |
| `src/holepunch.c` | simultaneous transmission, multi-candidate, keepalive | core |
| `src/stun.c` | STUN client (RFC 5389), IPv4 + IPv6, mapping behaviour | core |
| `src/candidate.c` | local interface address gathering | core |
| `src/netaddr.c` | address handling, dual-stack sockets, wire encoding | core |
| `src/crypto.c` | Argon2id key derivation (optional; see below) | core |
| `src/signaling.h` | rendezvous backend interface — **implement this** | |
| `src/signaling_nostr.c` | rendezvous over public Nostr relays | backend |
| `src/nostr.c` | NIP-01: events, ids, Schnorr signatures | backend |
| `src/ws.c` | WebSocket client (RFC 6455) with TLS | backend |
| `src/demo.c` | example client tying it together | demo |

## Using it in another project

Two things are yours to provide.

**1. A punch key.** 32 bytes, identical on both peers, secret, and
established *before* punching. It MACs every punch packet, so only a peer
holding it can open a path to you, and forged or replayed packets are
dropped.

If you already have a shared secret — from your own key exchange, a PAKE,
a TLS exporter — derive the punch key from that and ignore `crypto.c`
entirely. `nt_derive_keys()` is there for the case where all you have is a
passphrase.

**2. A signalling backend.** Two peers cannot punch until they have
swapped candidate addresses, and that has to travel over something already
reachable. The choice is orthogonal to punching, so it sits behind
`signaling.h`: implement `publish` and `wait_peer` over whatever you
have — an existing messaging channel, a DHT, your own rendezvous server —
and the rest works unchanged.

`signaling_nostr.c` is one implementation, riding public Nostr relays so
there is nothing to deploy. Drop it and `libsecp256k1` and `OpenSSL` go
with it; the core keeps only libsodium.

One requirement worth reading: `wait_peer` must honour the `round` field.
Candidates are re-exchanged before every punch attempt, so several rounds
cross the same channel, and a leftover message from an earlier round names
a mapping already known not to work.

## Build

```sh
make          # nat_demo
make test     # punch tests over loopback
```

```sh
# Arch
sudo pacman -S libsodium libsecp256k1 openssl
# Debian / Ubuntu
sudo apt install libsodium-dev libsecp256k1-dev libssl-dev
# macOS
brew install libsodium secp256k1 openssl
```

`make libnat_traverse.a` builds the traversal core alone, which needs only
libsodium.

## Demo

Generate a secret and give it to the other side over something you already
trust:

```sh
./nat_demo --gen-secret
```

Then run this on both machines with that secret:

```sh
./nat_demo 0 <shared_secret> [relay_url ...]
```

```console
$ ./nat_demo 0 syrup-jasmine-orchid-seagull-prairie-fathom-fiber-birch-...
[keys] stretching the passphrase (Argon2id)
[nostr] subscribed on wss://relay.damus.io
[local] bound UDP 39689
[stun] NAT mapping looks cone (endpoint-independent, punchable)
[stun] our candidate 192.168.1.20:39689
[stun] our candidate 203.0.113.44:39689
[sync] peer candidate 198.51.100.7:53934
[punch] attempt 1/5, 1 candidate, up to 10s
[punch] direct path to 198.51.100.7:53934 (IPv4)

--- connected (plain text, not encrypted) ---
```

It does not matter who starts first; whoever does waits up to 120 seconds
for the other.

The chat loop sends plain text on purpose — it demonstrates that the path
carries traffic. It is not a protocol and it is not private.

## Configuration

| variable | effect |
|---|---|
| `NAT_TRAVERSE_STUN_SERVERS` | comma- or space-separated `host[:port]`; port defaults to 3478. Bracket IPv6 literals to carry a port |

The default server list deliberately spans several operators. Two probes
to one provider share that provider's outage and its blocking, which is
exactly what the mapping-behaviour test is least able to notice.

Everything else lives in `nt_config_t`: attempts, timeouts, whether to
rebind on retry, keepalive interval. See
`traverse.h`.

## Scope

**What the punch key gives you.** Only a peer holding it can open a path
to you; stray, forged, and replayed punch packets are dropped. After a
path confirms the socket is `connect()`ed, so the kernel drops packets
from any other source.

**What it does not give you.** Nothing here encrypts application data,
authenticates individual datagrams, or detects replay or reordering of
your traffic. Anyone on the wire can read and rewrite what you send.
Traversal and transport security are separate concerns, and this library
implements the first one.

If you use `nt_derive_keys()`, use `--gen-secret` and treat the result
like an SSH private key. The passphrase is what both peers meet under on
the relay and what authenticates the punch, and it is guessable offline;
Argon2id makes each guess cost real time and memory but does not change
the shape of the attack.

## Limitations

**No relay fallback.** When no direct path exists — symmetric vs
symmetric, IPv4-only vs IPv6-only, or UDP blocked outright — the
connection fails. Every serious implementation carries a relay for these
cases (TURN, Tailscale's DERP); this one does not, by design. See
[What connects](#what-connects).

**UDP only.** Where UDP is blocked outright nothing here works, which is
why DERP runs over HTTPS on TCP 443 instead.

**No port-mapping protocols.** There is no NAT-PMP, PCP or UPnP here: the
library never asks the router to install a mapping, it only punches. Port
mapping is worth something in one narrow case — a first-hop NAT with
endpoint-dependent mapping and no CGNAT above it, where punching fails but
an explicit mapping would work — and costs a protocol zoo to reach it.
UPnP in particular is SSDP discovery plus HTTP, XML and SOAP, which is not
really NAT code; NAT-PMP and PCP are compact but less widely deployed than
UPnP, so implementing only those buys the smaller half of an already small
win. If you need it, it layers cleanly on top: install the mapping
yourself and the traversal below is unchanged.

**Firewalls are usually not the problem.** Most host firewalls (`ufw`,
`firewalld`, Windows Defender) are stateful and already accept
`RELATED,ESTABLISHED`, which is exactly what an outbound-first punch
creates. An explicit rule only matters on a stateless firewall — and note
it can only name the first attempt's port, since retries rebind.

## References

- RFC 4787, [NAT Behavioral Requirements for Unicast UDP](https://www.rfc-editor.org/rfc/rfc4787),
  the mapping and filtering vocabulary
- RFC 5389, [Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc5389)
- RFC 6455, [The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)
- RFC 9106, [Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- NIP-01, [Nostr basic protocol flow](https://github.com/nostr-protocol/nips/blob/master/01.md)
- Ford, Srisuresh, Kegel, [Peer-to-Peer Communication Across Network Address Translators](https://bford.info/pub/net/p2pnat/),
  the original treatment
- Tailscale, [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works),
  probably the best practical writeup out there
