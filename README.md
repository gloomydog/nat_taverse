# nat_traverse: NAT hole punching and P2P rendezvous

Direct peer-to-peer UDP connections across NAT, in C, with no server of
your own.

Rendezvous happens over public [Nostr](https://nostr.com) relays, so there
is nothing to deploy: both peers run the same command with the same
passphrase and a direct path opens between them.

```console
$ ./p2p_nostr 0 correct-horse-battery-staple
[local] bound UDP 39689
[portmap] asking the router (NAT-PMP / PCP / UPnP)
[portmap] unavailable (unsupported or disabled)
[stun] public address 203.0.113.44:39689 (via stun.l.google.com)
[nostr] subscribed on wss://relay.damus.io
[nostr] subscribed on wss://nos.lol
[nostr] waiting for peer (up to 120 s)
[nostr] found peer at 198.51.100.7:53934
[punch] trying to open a direct path
[punch] connected to 198.51.100.7:53934

--- connected (direct) ---
```

A conventional rendezvous server is also included for the cases where a
direct path is impossible and traffic has to be relayed.

Dependencies: POSIX sockets and pthreads for everything, plus
libsecp256k1 and OpenSSL for the Nostr client. No other libraries.

---

## Table of contents

- [Build](#build)
- [Usage](#usage)
- [Which one should I use?](#which-one-should-i-use)
- [Background: why this is hard](#background-why-this-is-hard)
  - [What NAT breaks](#what-nat-breaks)
  - [Mapping behaviour](#mapping-behaviour)
  - [Filtering behaviour](#filtering-behaviour)
  - [Why "cone" and "symmetric" are misleading](#why-cone-and-symmetric-are-misleading)
  - [Hole punching](#hole-punching)
  - [Your firewall is not the problem](#your-firewall-is-not-the-problem)
  - [Port mapping protocols](#port-mapping-protocols)
  - [Carrier-grade NAT](#carrier-grade-nat)
  - [Rendezvous, and why latency matters](#rendezvous-and-why-latency-matters)
  - [Why relays exist](#why-relays-exist)
- [Design](#design)
- [Security](#security)
- [Notes from testing](#notes-from-testing)
- [Limitations](#limitations)
- [References](#references)

---

## Build

```sh
make            # everything
make nolibs     # skip p2p_nostr, no external libraries needed
```

The Nostr client needs two libraries:

| library | why |
|---|---|
| libsecp256k1 | BIP-340 Schnorr signatures for Nostr events |
| OpenSSL | TLS for `wss://`, SHA-256, ChaCha20-Poly1305 |

```sh
# Arch
sudo pacman -S openssl libsecp256k1
# Debian / Ubuntu
sudo apt install libssl-dev libsecp256k1-dev
# macOS
brew install openssl secp256k1
```

## Usage

### Without a server

Run this on both machines, with the same passphrase:

```sh
./p2p_nostr 0 <shared_secret> [relay_url ...]
```

```sh
./p2p_nostr 0 correct-horse-battery-staple
./p2p_nostr 0 my-secret wss://relay.damus.io wss://nos.lol
```

Order does not matter; whoever starts first waits up to 120 seconds.

Pass `0` as the port unless you have a reason not to.

To use a different STUN server:

```sh
NAT_TRAVERSE_STUN_HOST=stun.example.com NAT_TRAVERSE_STUN_PORT=3478 \
    ./p2p_nostr 0 my-secret
```

### With your own server

On a host with a public address:

```sh
./relay_server 3478 -v
sudo ufw allow 3478/udp     # if you run a firewall
```

On both peers:

```sh
./p2p_connect 0 <server_host> 3478 <shared_secret>
```

## Which one should I use?

|  | `p2p_nostr` | `p2p_connect` |
|---|---|---|
| server of your own | not needed | required |
| rendezvous | public Nostr relays | `relay_server` |
| STUN | required | not needed |
| when punching fails | connection fails | falls back to relaying |
| external libraries | libsecp256k1, OpenSSL | none |

**`p2p_nostr` is the default choice.** Most home routers use
endpoint-independent mapping and support UPnP or NAT-PMP, so a direct path
usually opens.

**`p2p_connect` is for the tail.** When both peers are behind
carrier-grade NAT — two phones on mobile data, say — no amount of
cleverness will produce a direct path, and something has to relay the
bytes. 

---

## Background: why this is hard

### What NAT breaks

A host behind NAT has no address the outside world can reach. The router
holds a table of *mappings*: when an inside host sends a packet out, the
router allocates an external `IP:port` and rewrites the packet to appear
to come from it. Replies to that external address get rewritten back and
delivered inside.

The consequences for peer-to-peer traffic:

1. **You don't know your own address.** The address peers must use is the
   one the router picked, and nothing tells you what it is.
2. **Mappings are created by outbound traffic.** An inbound packet
   arriving before any outbound packet has no mapping to match, and is
   dropped.

STUN (RFC 5389) answers the first problem: a server on the public internet
reports the source address it observed. The second problem is what hole
punching is for.

### Mapping behaviour

The critical question is: **does the router reuse the same external port
for different destinations?**

RFC 4787 names three behaviours:

| behaviour | meaning |
|---|---|
| **Endpoint-Independent Mapping (EIM)** | one external port per internal port, regardless of destination |
| **Address-Dependent Mapping (ADM)** | a new mapping per destination address |
| **Address and Port-Dependent Mapping (APDM)** | a new mapping per destination address *and* port |

With EIM, the address STUN reports is the same one your peer will see, so
you can tell them about it and it will work.

With ADM or APDM — collectively **endpoint-dependent mapping (EDM)**, the
thing people usually mean by "symmetric NAT" — the mapping towards the
STUN server is *not* the mapping towards your peer. The address you
learned is useless for connecting to anyone else, and hole punching
essentially cannot work.

Most consumer routers do EIM. Mobile carriers usually do not.

### Filtering behaviour

Orthogonal to mapping is: **once a mapping exists, whose packets are let
in?**

| behaviour | meaning |
|---|---|
| **Endpoint-Independent Filtering (EIF)** | anyone may send to the mapping |
| **Address-Dependent Filtering (ADF)** | only hosts you have sent to |
| **Address and Port-Dependent Filtering (APDF)** | only the exact `IP:port` you have sent to |

These are independent of mapping behaviour. A router can be EIM+APDF,
which is common, and is what the old term "port-restricted cone" meant.

Filtering is a much smaller obstacle than mapping. Under APDF the peer's
first packet is dropped — but sending it still created the sender's own
permission, so a retransmission a moment later gets through. Under EIM+EDM
no retransmission helps, because the address itself is wrong.

**This code does not detect filtering behaviour at all.** It does not need
to: retransmitting for several seconds handles the strictest case, and
handling the strictest case handles all of them.

### Why "cone" and "symmetric" are misleading

RFC 3489 classified NATs as full cone, restricted cone, port-restricted
cone, and symmetric. RFC 4787 deprecated this, for a good reason: it
collapses two independent axes onto one, so it cannot describe real
devices. "Port-restricted cone" is really "EIM + APDF" — a *mapping*
property and a *filtering* property glued together.

The distinction matters for diagnosis:

- punching fails because of **EDM** → hopeless, use a relay
- punching fails because of **APDF** → a timing problem, retries fix it

The old vocabulary cannot express that difference. This project uses the
RFC 4787 terms.

### Hole punching

Both peers transmit to each other at roughly the same time:

```
   A ──────── punch ────────▶  ✗ dropped by B's filter
                                  (but A's mapping + permission now exist)
   ◀───────── punch ────────  B  ✗ dropped by A's filter
                                  (but B's mapping + permission now exist)

   A ──────── punch ────────▶  ✓ A is now permitted
   ◀───────── ack ──────────  B  ✓ path is open
```

Each outbound packet creates state in the sender's own NAT and firewall.
The first packets are supposed to fail. The retry is the mechanism, not a
workaround for one.

Two details in this implementation matter more than they look:

**Follow the actual source address.** `holepunch_run()` replies to
wherever the packet came from, not to the address signalling advertised.
If the peer's NAT allocated a different mapping than the one they told you
about — routine on carrier NAT — this is the only address that works. It
is also why `holepunch_result_t` reports `confirmed_peer` separately.

**Keep transmitting for the whole window.** Sending a fixed number of
bursts and then only listening leaves a narrow window in which both sides
must be transmitting. Transmitting for the entire timeout costs a few tiny
datagrams and removes an entire class of failure.

### Your firewall is not the problem

A common assumption is that a host firewall must be blocking things. It
almost certainly is not.

`ufw`, `iptables` and `nftables` are *stateful*: they track connections
via conntrack. A default-deny inbound policy still permits packets
matching `ESTABLISHED,RELATED`, and sending a UDP datagram creates a
conntrack entry that makes the reply match.

This is the same property hole punching depends on. If your outbound
packet created the state, the reply comes back — no rule needed. The
relevant timeouts:

```sh
sysctl net.netfilter.nf_conntrack_udp_timeout          # 30 s, unconfirmed
sysctl net.netfilter.nf_conntrack_udp_timeout_stream   # 120 s, once bidirectional
```

Once both sides have been seen the flow is marked ASSURED and gets the
longer timeout. Keepalives at 15 s stay comfortably inside both. You can
watch the transition happen:

```sh
sudo conntrack -E -p udp
```

Explicit `deny` or rate-limiting rules on the port are of course another
matter. But opening a port "to make P2P work" is treating a symptom that
usually is not there.

### Port mapping protocols

Rather than *observing* what the NAT does, you can *instruct* it:

| protocol | notes |
|---|---|
| **NAT-PMP** (RFC 6886) | simple binary over UDP 5351 |
| **PCP** (RFC 6887) | its successor, same port |
| **UPnP IGD** | most widely deployed; SSDP discovery + SOAP |

When one succeeds, that NAT layer stops mattering: the router forwards the
external port unconditionally and the peer can simply connect.

Two caveats:

- **They only affect the first NAT hop.** Behind carrier-grade NAT the
  home router will happily install a mapping while the carrier's NAT
  upstream remains untouched. The mapping is real and useless. Check the
  external IP the router reports: if it is private or in `100.64/10`, there
  is another NAT above it. `portmap_is_global_ip()` does this, and both
  clients warn about it.
- **Many routers disable UPnP by default**, given its security history.
  Failure is normal. Always fall back to punching.

### Carrier-grade NAT

Mobile networks and some ISPs put subscribers behind CGNAT: thousands of
customers share a pool of public addresses. This is where NAT traversal
goes to die:

- **Endpoint-dependent mapping.** Sharing addresses efficiently means
  allocating per destination. STUN's answer does not apply to your peer.
- **Short mapping lifetimes**, to recycle scarce ports.
- **No port mapping protocols.** You cannot control the carrier's NAT, and
  neither can your router.
- **Deep packet inspection** in some networks, treating unrecognised UDP
  differently from known protocols.

One peer behind CGNAT is often survivable, particularly if the other is on
a well-behaved home connection. Both peers behind CGNAT is not: there is
no direct path to find, and a relay is the only answer. This is not a
limitation of this code — Tailscale, WebRTC and Iroh all carry relays for
exactly this case.

### Rendezvous, and why latency matters

Peers must exchange addresses somehow. That channel is called signalling
or rendezvous, and its *speed* is not a detail.

An address learned from STUN describes a mapping that exists *now*. On
CGNAT it may not exist in thirty seconds. Any scheme where a human copies
an address from one terminal to another is racing a clock it cannot see,
and losing often.

Doing the exchange programmatically collapses that window to milliseconds.
In testing, this single change is what turned an unreliable connection
into a routine one — not any change to the punching itself.

A rendezvous channel can also **trigger both sides at once**, which is what
"simultaneous transmission" wants. `relay_server` does this by sending both
peers their `PEER_INFO` back to back, with a *relative* delay (no clock
synchronisation needed). Nostr has no such primitive, so each peer starts
when it sees the other's event; the residual skew is just relay latency,
which the retry loop absorbs.

### Why relays exist

Every serious NAT traversal implementation has a relay. Tailscale has
DERP, WebRTC has TURN, Iroh has its own. This is not an admission of
defeat; it is the recognition that a fraction of network pairs have no
direct path, and something must carry those bytes.

This project keeps that fraction small — port mapping, fast rendezvous,
follow-the-source-address, generous retries — and provides `relay_server`
for the remainder.

**Note that this is deliberately not TURN.** TURN (RFC 8656) is a large
specification layered on STUN, with allocations, permissions and channel
bindings. If your application already encrypts end to end, the relay can be
a dumb pipe that forwards opaque bytes — a few hundred lines instead of a
few thousand. That is the DERP approach, and it is what `relay_server` is.

---

## Design

```
        p2p_nostr                       p2p_connect
            │                                │
    ┌───────┴────────┐              ┌────────┴────────┐
    │ signaling_nostr│              │  relay_client   │
    │   nostr + ws   │              │   relay_proto   │
    └───────┬────────┘              └────────┬────────┘
            │      (signaling.h interface)   │
            └───────────────┬────────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
           portmap       holepunch      stun
        NAT-PMP/PCP/    punch + ka    RFC 5389
           UPnP
```

`signaling.h` is the seam. Both backends implement it, so swapping
rendezvous transports does not touch the punching code. A BitTorrent DHT
or an existing messaging channel would drop into the same interface.

### How the Nostr backend works

```
1. derive from the shared secret (PBKDF2-HMAC-SHA256):
     - a secp256k1 signing key   ── both peers derive the SAME key
     - a ChaCha20-Poly1305 key   ── independent salt
2. ask STUN for our public address
3. publish it, encrypted, as an ephemeral event (kind 20117)
4. subscribe with authors = our shared pubkey, decrypt the peer's event
5. punch
```

Both peers signing with the same key is what makes the rendezvous work: to
a relay they look like one identity posting twice, and each side finds the
other with an `authors` filter. The meeting point *is* the pubkey.

Kinds 20000–29999 are ephemeral: relays forward them but do not store
them. Signalling data is worthless seconds later, so this is the right
range — and it leaves nothing behind on public infrastructure.

Addresses are always encrypted. Anything in an event's `content` is
world-readable.

| file | what it does |
|---|---|
| `p2p_nostr.c` | client: portmap → STUN → Nostr rendezvous → punch |
| `p2p_connect.c` | client: portmap → server rendezvous → punch → relay |
| `relay_server.c` | rendezvous + relay server |
| `signaling.h` | backend interface |
| `signaling_nostr.c` | Nostr backend |
| `nostr.c` | NIP-01: events, ids, Schnorr signatures, payload encryption |
| `ws.c` | WebSocket client (RFC 6455) with TLS |
| `relay_client.c`, `relay_proto.c` | client and wire format for `relay_server` |
| `holepunch.c` | simultaneous transmission, keepalive, token check |
| `portmap.c` | NAT-PMP, PCP, UPnP IGD |
| `stun.c` | STUN client (RFC 5389) |

---

## Security

**Read this before using the code for anything real.**

The tokens and meeting ids here are lightweight filters, not
authentication:

- **`derive_token()` in the clients and `relay_derive_id()` are not KDFs.**
  They are simple mixing functions. Replace them with Argon2id — or
  whatever your application already uses — before depending on them.
- **The punch token travels in clear text.** Its only job is to stop an
  unrelated datagram from being mistaken for the peer.
- **Both peers share the Nostr signing key.** This proves knowledge of the
  secret and nothing else. Anyone with the secret can join the rendezvous.
- **Therefore: authenticate the peer cryptographically in your own
  handshake, once the path is open.** Do not treat a successful punch as
  identification.

What the code does get right:

- Addresses published to Nostr are encrypted with ChaCha20-Poly1305 under
  a key derived independently of the signing key. AEAD means tampering is
  detected.
- `wss://` connections verify certificates and hostnames.
- `relay_server` only forwards between registered peers, so it cannot be
  used as an open reflector.
- The relay never sees plaintext — it forwards opaque bytes.

If you run `relay_server` publicly, add rate and bandwidth limits.

---

## Limitations

- **UDP only.** Where UDP is blocked outright, nothing here works. This is
  why DERP runs over HTTPS on TCP 443. A TCP transport would be a
  reasonable addition.
- **IPv4 only.** IPv6 mostly removes the need for any of this, which is a
  pleasant thought but not an implementation.
- **Both peers behind CGNAT will not get a direct path.** Use
  `p2p_connect` with your own `relay_server`.
- **UPnP discovery is slow** — SSDP probing can take tens of seconds
  before giving up on a router that does not support it.
- **`p2p_nostr` has no data fallback.** By design; Nostr relays are not a
  byte pipe.
- The chat loop in both clients is a demonstration that the path carries
  traffic. It is not a protocol.

---

## References

- RFC 4787 — [NAT Behavioral Requirements for Unicast UDP](https://www.rfc-editor.org/rfc/rfc4787)
  (the mapping/filtering vocabulary)
- RFC 5389 — [Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc5389)
- RFC 5780 — [NAT Behavior Discovery Using STUN](https://www.rfc-editor.org/rfc/rfc5780)
  (not implemented here; would require `CHANGE-REQUEST` support)
- RFC 6886 — [NAT Port Mapping Protocol (NAT-PMP)](https://www.rfc-editor.org/rfc/rfc6886)
- RFC 6887 — [Port Control Protocol (PCP)](https://www.rfc-editor.org/rfc/rfc6887)
- RFC 6455 — [The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)
- BIP-340 — [Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- NIP-01 — [Nostr basic protocol flow](https://github.com/nostr-protocol/nips/blob/master/01.md)
- Ford, Srisuresh, Kegel — [Peer-to-Peer Communication Across Network Address Translators](https://bford.info/pub/net/p2pnat/)
  (the original treatment)
- Tailscale — [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)
  (the best practical write-up of the problem)

---

