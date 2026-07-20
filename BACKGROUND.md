# Background: the NAT theory behind `nat_traverse`

This document explains the networking theory this library is built on.
It is not a walkthrough of the code; it is the *why* underneath it — what
NAT is, why two ordinary machines cannot simply send each other packets,
and the set of techniques that make a direct path possible anyway. The
code (`stun.c`, `holepunch.c`, `traverse.c`, `signaling_nostr.c`) is one
concrete implementation of the ideas below.

## 1. The problem: there is no route from A to B

Two hosts on the public Internet can address each other by IP and
exchange packets. Almost no consumer machine is on the public Internet.
It sits behind a **NAT** (Network Address Translation) device — a home
router, a corporate gateway, a mobile carrier's core — that lets many
private hosts share one public IP address.

A host behind NAT has a **private address** (e.g. `192.168.1.20:39689`)
drawn from a range (RFC 1918: `10/8`, `172.16/12`, `192.168/16`) that is
not routable on the public Internet. Its packets only reach the outside
world because the NAT rewrites them on the way out, and rewrites the
replies on the way back in.

The consequence that matters here: **a host does not know its own public
address, and nothing outside can initiate a connection to it.** From the
outside there is no name for "the machine at `192.168.1.20`" — only the
router's single public IP, shared by everyone behind it. This is the wall
that all NAT traversal exists to get over.

```
   private side                NAT                 public Internet
 192.168.1.20:39689  <--->  203.0.113.44  <--->  the rest of the world
   (host knows this)      (host does NOT know       (only ever sees
                           this until it asks)       203.0.113.44:XXXXX)
```

## 2. How NAT actually behaves: mappings and filtering

A NAT's behaviour splits into two independent questions. RFC 4787 gives
them precise names, and the whole strategy of NAT traversal depends on
this distinction.

### 2.1 Mapping behaviour — *what public address do I get?*

When an internal host sends a UDP packet out, the NAT allocates a
**mapping**: a public `(IP, port)` tuple that stands in for the internal
`(IP, port)`. Return traffic to that public tuple is translated back. The
question is *when the NAT reuses the same mapping*:

- **Endpoint-Independent Mapping (EIM).** The same internal
  `(IP, port)` always gets the *same* public port, no matter which remote
  host it is talking to. Send to server X and to peer Y from the same
  local socket, and both see you at the same public address. This is the
  friendly case.

- **Endpoint-Dependent Mapping (address- or address-and-port-dependent).**
  The public port the NAT hands out *depends on the destination*. Talk to
  server X and you get one public port; talk to peer Y and you get a
  different one. This is what "**symmetric NAT**" means in the older
  vocabulary, and it is the case that defeats hole punching (see §5).

The reason mapping behaviour is decisive: NAT traversal works by learning
your public address from one party (a STUN server) and then handing it to
a *different* party (your peer) to send to. That only works if the
address you learned is the address your peer will actually reach — i.e.
if the mapping is endpoint-independent.

### 2.2 Filtering behaviour — *who is allowed to send to me?*

Once a mapping exists, a second, separate policy decides which inbound
packets are permitted through it:

- **Endpoint-Independent Filtering (EIF).** Once you have sent *any*
  packet out and opened the mapping, *anyone* may send to that public
  port. Permissive.

- **Address-Dependent Filtering.** Only hosts you have already sent a
  packet *to* may send back — matched by their IP.

- **Address-and-Port-Dependent Filtering.** Only the exact
  `(IP, port)` you sent to may send back. Strictest.

Filtering is why the outbound packet has to go first: sending out is what
creates the state (in the NAT and in any stateful firewall) that lets the
reply back in. And it is why the *first* packet in a hole punch is
usually dropped — the peer's filter has not yet seen your side open —
while opening the path so a later retransmission succeeds.

The key insight this library relies on: **you never need to detect the
filtering type.** However strict the filter is, sending outbound first
plus retrying covers it. The code (`holepunch.c`) does exactly this and
deliberately does no filtering-behaviour probing.

## 3. Discovering your public address: STUN

If a host cannot know its own public mapping, it has to *ask*. **STUN**
(Session Traversal Utilities for NAT, RFC 5389) is the mechanism: the
host sends a Binding Request from the very socket it intends to use, and a
public STUN server replies with the source address it *observed* — that
is, the public `(IP, port)` the NAT assigned to that socket.

Two details from `stun.c` are worth calling out because they are
consequences of the NAT theory, not incidental:

- **The reply carries the address XOR'd with a magic cookie**
  (XOR-MAPPED-ADDRESS). Some NATs inspect packet payloads and rewrite
  anything that looks like an internal IP address. Obscuring the address
  behind a fixed XOR keeps a meddling NAT from silently corrupting the one
  field that matters.

- **You must STUN from the same socket you will punch from.** The mapping
  is tied to a specific internal `(IP, port)`. Learn your public address
  on one socket and punch from another and — under endpoint-dependent
  mapping especially — the address you learned is meaningless.

It STUNs over both IPv4 and IPv6, collecting whatever answers as
a **candidate**. A host may have one, the other, or both.

> Note: because rendezvous here rides a *separate* TCP connection (Nostr
> over WebSocket), the rendezvous channel cannot observe the UDP source
> address the way a purpose-built UDP rendezvous server could. That is
> precisely why STUN is mandatory in this design — the app has to discover
> its own mapping itself.

## 4. Opening the path: UDP hole punching

Now both peers know their own public candidate addresses. They exchange
them (that is what rendezvous, §7, is for). Then they **hole punch**:

1. Both peers begin sending UDP packets *to each other's* public
   candidate at roughly the same time.
2. Each outbound packet installs mapping-and-filter state in the sender's
   own NAT/firewall: "I am talking to that remote endpoint; let its
   replies in."
3. The first packets to arrive are typically dropped by the *other*
   side's filter, which has not yet seen its own host open the path — but
   they have already done their job of opening the *sender's* side.
4. A moment later, once both sides have punched outward, retransmissions
   pass through in both directions. The path is open.

This symmetry is the trick: neither side can accept an unsolicited inbound
packet, but if *both* send outbound first, each one's outbound turns the
other's inbound from "unsolicited" into "expected." No server ever
forwards the data; it only helped the two sides learn where to aim.

The sequence, with time running downward:

```
   Peer A                A's NAT              B's NAT               Peer B
     |                     |                     |                     |
     |  (both already know each other's public candidate via §7)      |
     |                     |                     |                     |
     |   PUNCH ->          |                     |                     |
     |-------------------->| opens A's mapping   |                     |
     |                     |  + filter for B     |                     |
     |                     |------ PUNCH ------->X| DROPPED             |
     |                     |                     | (B's filter has     |
     |                     |                     |  not opened yet)    |
     |                     |                     |                     |
     |                     |                     |          PUNCH <----|
     |                     |                     | opens B's mapping   |
     |                     |                     |  + filter for A     |
     |                     |X<----- PUNCH -------|<--------------------|
     |            DROPPED   |                     |                     |
     |  (A's filter open,  |                     |                     |
     |   but this crossed  |                     |                     |
     |   before B opened)  |                     |                     |
     |                     |                     |                     |
     |   PUNCH ->  (retransmit; both sides now open)                   |
     |-------------------->|-------- PUNCH ----->|-------------------->|
     |                     |                     |                     | recv PUNCH
     |                     |                     |                     | -> send ACK
     |                     |<------- ACK --------|<--------------------|
     |<--------------------|<------- ACK --------|                     |
     | recv ACK            |                     |                     |
     |                     |                     |                     |
     |==================== direct path open, both ways ===============|
     |                     |                     |                     |
```

Notice that no single packet had to survive on the first try. Each early
`PUNCH` is dropped by the peer's not-yet-open filter, yet still opens its
*own* side's mapping and filter. Once both sides have sent at least one
outbound packet, the next retransmission crosses cleanly in both
directions — which is why the code transmits continuously across a window
rather than firing a single burst. The `ACK` is a reply to the observed
source address (§4), so it works even if the peer's real public port
differs from the one it advertised.

Two robustness ideas from `holepunch.c` follow directly from the theory:

- **Transmit for the whole window, not a single burst.** The two sides
  are never perfectly synchronised — here the skew is just the difference
  in relay delivery latency. Continuous retransmission absorbs it and
  covers even address-and-port-dependent filtering.

- **Reply to where the packet actually came from,** not to the candidate
  you were told about. Under endpoint-dependent mapping the peer's NAT may
  present a *different* public port to you than the one it advertised via
  STUN. The observed source address is the one that actually works.

Because a host may be reachable several ways, all candidates are punched
at once and whichever answers first wins. **IPv6 usually wins when it is
available**, because there is typically no NAT in the path at all — only a
stateful firewall pinhole to open, which the same outbound-first packet
opens. IPv6 does not abolish the filtering problem; it abolishes the
*mapping* problem.

### 4a. Why IPv6 still needs STUN

"IPv6 has no NAT, so just advertise your global address" is the obvious
move, and it quietly fails in the common case. The reason is worth
understanding, because it looks nothing like a NAT problem.

A modern host has **many** global IPv6 addresses on one interface: a
stable SLAAC address, plus a rotating set of RFC 4941 *privacy*
addresses. Which one the kernel uses as the *source* of an outbound flow
is its own decision, and it is usually a privacy address — not the one
you would pick by reading `ip addr`.

Now recall §4: the punch works because our outbound packet creates
firewall state that lets the peer's packet back in. That state is keyed on
the address we actually *sent from*. So if each side advertises its host
v6 addresses and the peer aims there, the peer's packets arrive at an
address belonging to **no flow this host originated** — and a stateful
host firewall drops every one of them. Both peers have perfect IPv6
connectivity and the punch still fails.

The fix is to treat IPv6 exactly like IPv4 and **ask STUN over IPv6**: the
reply reports the precise global v6 `(IP, port)` the kernel sources from
toward the internet. Advertise *that*, and both sides open a pinhole for,
and aim at, the same address. The punch then lines up and confirms almost
instantly, since there is no NAT round trip.

So STUN's role generalises. It is not "the NAT discovery protocol" — it is
**how a host learns which of its own addresses the outside world actually
sees**, which is a question NAT makes urgent but does not exclusively
own.

## 5. When it cannot work: symmetric NAT on both sides

Hole punching rests on one assumption: **the public address I learn from
STUN is the address my peer can reach me at.** Under endpoint-dependent
(symmetric) mapping that assumption breaks. The port the NAT assigns for
talking to the STUN server is *not* the port it will assign for talking to
the peer, because the mapping depends on the destination. So the candidate
you advertise is stale the moment your peer tries to use it.

If *one* side is symmetric, tricks sometimes help (port prediction,
birthday-paradox port scanning). If **both** sides are symmetric — the
common outcome behind **carrier-grade NAT (CGNAT)**, where the mobile
carrier itself NATs all its subscribers — there is essentially no direct
path to find. Neither side can predict the other's per-destination port.

At that point the only remedy is a **relay**: a third party that both
sides *can* reach outbound, which forwards bytes between them (this is
what TURN, and Tailscale's DERP, provide). This library deliberately does
*not* carry one — and the Nostr backend could not be one anyway, being a
signalling channel rather than a byte pipe — so this case simply fails,
and the code says so plainly. Every production-grade NAT traversal system
carries a relay for exactly this reason.

### 5a. Why retrying is not just hoping

Between "works on the first try" and "impossible" sits a large middle
ground, and it is worth understanding why a second attempt is not
superstition.

A punch fails for one of several reasons, and they want different
remedies:

- **The two windows barely overlapped.** Signalling latency decides when
  each side starts punching, and if one starts as the other gives up, no
  packet ever meets a warm mapping. Remedy: try again, and re-synchronise
  first. The candidate re-exchange before each attempt doubles as a
  **barrier** both peers pass through together, which re-aligns their
  windows instead of letting them drift further apart.

- **The mapping drifted.** The reflexive address was measured, then the
  peer took twenty seconds to appear, and by the time it punches, the NAT
  has rotated the port. Remedy: re-run STUN before punching, so the
  address the peer is aiming at is current.

- **The mapping was never punchable.** Here is the one that looks like
  bad luck and is not. On CGNAT and commercial-VPN paths, the external
  port a socket is granted is endpoint-dependent luck that re-STUNning
  cannot change: measure it again and you get the same unusable answer.
  Retrying on the *same socket* therefore re-runs a lost bet with the
  same dice. This is precisely why quitting and relaunching by hand often
  connects when an in-process retry loop never does — a **new socket
  draws a new mapping**, one the peer has never seen. Remedy: close the
  socket and rebind to a fresh ephemeral port, which is what a hand
  restart accomplishes, minus the human.

Note the tension with binding a known fixed port: a known port is the only
one a static firewall rule can name in advance, but reusing it risks being
handed back the very mapping that just failed. The resolution is to hold
the fixed port for the first attempt and rebind only after it has already
failed — easy NATs keep the benefit, hard ones get fresh dice.

## 6. Removing a NAT layer in advance: port mapping

Hole punching works *around* a NAT. Port-mapping protocols instead ask the
NAT to *cooperate*: "please install a permanent mapping from public port P
to my internal port, and tell me my public IP." When one succeeds, the
first NAT layer effectively stops being an obstacle — an inbound
connection to the mapped port reaches you directly.

Three are widely deployed: **NAT-PMP** (RFC 6886), its successor **PCP**
(RFC 6887), and **UPnP IGD**. The first two are compact binary exchanges
on UDP 5351; UPnP is a different kind of thing entirely, reaching the
router by SSDP multicast and then speaking HTTP, XML and SOAP to it.

**This library implements none of them,** and the reasoning is worth
setting out because it is a good illustration of how narrow the technique
actually is. The theory sets two hard limits:

- **It only affects the *first* NAT hop.** If there is another NAT
  upstream (CGNAT again), a mapping on your home router hands you a
  private or carrier-side external IP that is still unreachable from the
  public Internet. Worse, it *looks* like success, so it has to be checked
  for explicitly.

- **It is IPv4-only in practice.** NAT-PMP has no IPv6 form, and IPv6 does
  not need a *mapping* — it needs a firewall *pinhole*, which the
  outbound-first hole punch already produces. So for IPv6 the punch does
  the whole job.

Put those together with §2 and the window where port mapping is the
deciding factor turns out to be small: the first-hop NAT must have
endpoint-dependent mapping (or punching would have worked anyway), *and*
there must be no CGNAT above it (or the mapping is useless), *and* the
router must have the protocol enabled. Outside that window it is at best
an optimisation and at worst a slow no-op — SSDP probing in particular can
take tens of seconds to give up on a router that does not support it.

There is also a deployment irony worth noticing, since it cuts against the
obvious way to economise. UPnP is the most commonly *available* of the
three, but by far the most expensive to implement and the one with the
worst security history. NAT-PMP and PCP are cheap to implement but less
widely supported. So "implement only the cheap ones" buys the smaller half
of an already small win — which is why this library implements neither and
relies on punching, and why an application that genuinely needs port
mapping is better off installing the mapping itself and leaving the
traversal below unchanged.

## 7. The role of rendezvous (and why it is not traversal)

None of the above can begin until the two peers have exchanged candidate
addresses, and neither can reach the other yet — that is the whole
problem. **Rendezvous** solves the bootstrap: a mutually-reachable meeting
point where each side can *publish* its candidates and *learn* the peer's.

It is important to separate the two jobs:

- **Rendezvous** = discovery. It only needs to move a few addresses, once,
  and both peers can reach it outbound (so no NAT problem for this
  channel). Here it is public Nostr relays; the meeting point is a
  pubkey both peers derive from the same passphrase.
- **Traversal** = the direct path, opened by punching. This is where the
  actual data flows, peer to peer, no third party in the middle.

The rendezvous channel does not, and need not, carry application data. In
this design it *cannot* — which is what makes the symmetric-NAT case
(§5) terminal rather than merely degraded.

One property of *this* rendezvous channel shapes the punch timing: a
purpose-built rendezvous server can signal both peers to start punching at
the same instant. Nostr has no such primitive, so each peer starts the
moment it sees the other's published event. The residual skew is only the
difference in relay delivery latency — which, per §4, the continuous
retransmission window absorbs.

## 8. Punching opens a pipe, not a trust relationship

A final point of theory that is easy to miss. Successful hole punching
proves exactly one thing: **there is now a bidirectional UDP path to some
endpoint.** It says nothing about what may safely travel over that path.

There is a real distinction here that is easy to blur. The punch packets
in `holepunch.c` *are* authenticated: each carries a MAC keyed by a secret
both peers established beforehand over signalling, so only a peer holding
that key can open the path, and forged or replayed packets are dropped.
That is worth having — an unauthenticated punch will confirm a "path" to
whatever happens to answer, and its confirmation means nothing.

But authenticating the *punch* is not authenticating the *session*. Once
the path is open, this library stops. Nothing encrypts your traffic,
nothing authenticates individual datagrams, nothing detects replay or
reordering of application data. An observer on the wire can read and
rewrite everything you send.

So NAT traversal and transport security remain separate concerns, and
this library deliberately implements only the first. Everything after
"the path is open" — deriving session keys, encrypting and authenticating
every datagram, replay windows — is a layer *on top of* traversal. Build
it, or use something that has (DTLS, Noise, WireGuard) over the socket
you get back.

## Summary

| concept | what it is | where it bites |
|---|---|---|
| NAT mapping | public `(IP,port)` a host is seen as | endpoint-dependent ⇒ hole punch fails |
| NAT filtering | who may send inbound through a mapping | strict filtering ⇒ needs outbound-first + retry |
| STUN | asking a server for your own public address | must use the same socket you punch from |
| Hole punching | both sides send outbound to open the path | the actual traversal mechanism |
| Symmetric / CGNAT | per-destination mappings on both sides | no direct path; needs a relay |
| Port mapping | asking the NAT to install a mapping | first hop only; IPv4 only |
| Rendezvous | exchanging candidates via a reachable third party | discovery, not traversal |

## References

- RFC 4787, *NAT Behavioral Requirements for Unicast UDP* — the mapping
  and filtering vocabulary used throughout.
- RFC 5389, *Session Traversal Utilities for NAT (STUN)*.
- RFC 6886 / RFC 6887, *NAT-PMP* / *Port Control Protocol*.
- Ford, Srisuresh, Kegel, *Peer-to-Peer Communication Across Network
  Address Translators* — the original treatment of UDP hole punching.
- Tailscale, *How NAT traversal works* — the best practical write-up.
