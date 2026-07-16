# nat_traverse: NAT hole punching and P2P connections

Authenticated, encrypted, direct peer to peer UDP connections across NAT,
written in C, with no server of your own required.

Rendezvous happens over public [Nostr](https://nostr.com) relays, so there
is nothing to deploy. Both peers run the same command with the same
passphrase and a direct path opens between them.

```console
$ ./p2p_nostr 0 syrup-jasmine-orchid-seagull-prairie-fathom-fiber-birch-...
[keys] stretching the passphrase (Argon2id)
[local] bound UDP 39689
[portmap] asking the router (NAT-PMP / PCP / UPnP)
[portmap] unavailable (unsupported or disabled)
[stun] IPv4 candidate 203.0.113.44:39689
[stun] IPv6 candidate [2001:db8::1]:39689
[nostr] subscribed on wss://relay.damus.io
[nostr] subscribed on wss://nos.lol
[nostr] waiting for peer (up to 120 s)
[nostr] peer candidate 198.51.100.7:53934
[punch] trying 1 candidate
[punch] path open to 198.51.100.7:53934
[handshake] authenticating
[handshake] peer authenticated, session keys established

--- connected, authenticated, encrypted ---
```

IPv4 and IPv6, whichever works. Mutual authentication and forward secrecy
from a single shared passphrase.

## Build

```sh
make
```

Three libraries:

| library | why |
|---|---|
| libsodium | Argon2id, X25519, XChaCha20-Poly1305, constant-time comparison |
| libsecp256k1 | BIP-340 Schnorr signatures for Nostr events |
| OpenSSL | TLS for `wss://`, SHA-256, Nostr payload cipher |

```sh
# Arch
sudo pacman -S libsodium libsecp256k1 openssl
# Debian / Ubuntu
sudo apt install libsodium-dev libsecp256k1-dev libssl-dev
# macOS
brew install libsodium secp256k1 openssl
```

## Usage

Generate a passphrase and give it to the other side over something you
already trust:

```sh
./p2p_nostr --gen-secret
```

Then run this on both machines with that passphrase:

```sh
./p2p_nostr 0 <shared_secret> [relay_url ...]
```

```sh
./p2p_nostr 0 syrup-jasmine-orchid-seagull-prairie-fathom-fiber-birch-...
./p2p_nostr 0 <secret> wss://relay.damus.io wss://nos.lol
```

It does not matter who starts first; whoever does waits up to 120 seconds
for the other.

Pass `0` as the port unless you have a specific reason not to. 
To use a different STUN server:

```sh
NAT_TRAVERSE_STUN_HOST=stun.example.com NAT_TRAVERSE_STUN_PORT=3478 \
    ./p2p_nostr 0 <secret>
```

## How it works

```
1. stretch the passphrase into key material            crypto.c
2. ask the router for a port mapping                   portmap.c
3. gather IPv4 and IPv6 candidates via STUN            stun.c
4. publish them encrypted on Nostr, wait for the peer  signaling_nostr.c
5. punch every candidate at once                       holepunch.c
6. authenticate, then talk encrypted                   handshake.c, channel.c
```

Everything derives from one passphrase. Argon2id stretches it once, then
independent subkeys fall out of that: the punch token, the Nostr signing
key, the Nostr payload key, and the handshake pre-shared key. A leak of
one tells you nothing about the others.

**Rendezvous.** Both peers derive the *same* Nostr signing key, so to a
relay they look like one identity posting twice. Each side subscribes with
an `authors` filter on that pubkey and finds the other. The meeting point
is the pubkey itself. Candidates are published as ephemeral events (kind
20117), which relays forward but do not store, and always encrypted:
anything in an event's `content` is otherwise world readable.

**Punching.** Both peers transmit to each other at roughly the same time.
Each outbound packet creates state in the sender's own NAT and stateful
firewall, which then lets the reply through. The first packets are
*supposed* to be dropped by the peer's filter; they still open the path,
so a retransmission a moment later gets through. Retrying like this covers
the strictest filtering behaviour, which is why the filtering type never
needs to be detected.

A host often has more than one way to be reached, so all candidates get
punched at once and whichever answers first wins. IPv6 usually wins when
available, since there is no NAT in the way, only a firewall to open.

**Authentication.** Punching only produces a path. It says nothing about
who is on the far end and protects nothing; the punch token is a filter
against stray datagrams, not a secret, and it travels in clear. So the
handshake is not optional. It is one symmetric round trip: ephemeral
X25519 for forward secrecy, authenticated with a tag only a passphrase
holder can produce, then a confirmation so a key mismatch fails
immediately rather than confusingly later. After that, XChaCha20-Poly1305
with a separate key per direction and a sliding replay window.

| file | what it does |
|---|---|
| `p2p_nostr.c` | the client, ties the steps together |
| `crypto.c` | Argon2id key derivation, constant-time helpers |
| `handshake.c` | authenticated key exchange, encrypted transport |
| `channel.c` | handshake over UDP with retransmission, framing |
| `holepunch.c` | simultaneous transmission, multi-candidate, keepalive |
| `portmap.c` | NAT-PMP, PCP, UPnP IGD |
| `stun.c` | STUN client (RFC 5389), IPv4 and IPv6 |
| `netaddr.c` | address handling, dual stack sockets, wire encoding |
| `signaling.h` | rendezvous backend interface |
| `signaling_nostr.c` | Nostr backend |
| `nostr.c` | NIP-01: events, ids, Schnorr signatures |
| `ws.c` | WebSocket client (RFC 6455) with TLS |

## Security

**Use `--gen-secret`. Do not invent a passphrase.**

That is not boilerplate. An observer who captures a handshake can test
guesses against it offline, at their leisure, without contacting anyone.
Argon2id makes each guess cost real time and memory, but it does not
change the shape of the attack: a memorable phrase will not survive it. A
password-authenticated key exchange such as CPace closes this properly, at
the cost of a much larger and much easier to misimplement protocol. The
mitigation taken here is to make guessing pointless by generating 128 bits
and treating the result like an SSH private key.

Anyone holding the passphrase can join the rendezvous and complete the
handshake. There is no notion of identity beyond it.

What the code does handle:

- Forward secrecy. Session keys come from ephemeral X25519 keys that are
  discarded afterwards, so a passphrase leaking later does not decrypt
  recorded traffic.
- Mutual authentication before any application data moves.
- Replay protection, both on the handshake and on every datagram after
  it, via a sliding window.
- Constant-time comparison of every secret, so a wrong guess does not leak
  how nearly right it was.
- Key material wiped from memory when done.
- Addresses on Nostr encrypted under a key derived independently of the
  signing key, with an AEAD so tampering is caught.
- `wss://` connections verify certificates and hostnames.

Argon2id runs at libsodium's INTERACTIVE setting, roughly 100 ms and
64 MiB. Both peers must agree, so it is compiled in rather than
negotiated; raise it in `crypto.c` if your threat model warrants it.


## Limitations

**Both peers behind symmetric NAT will not connect.** There is no
direct path to find, and Nostr cannot forward data. Every serious
implementation carries a relay for this case. 

**UDP only.** Where UDP is blocked outright nothing here works, which is
why DERP runs over HTTPS on TCP 443 instead.

**Port mapping is IPv4 only.** NAT-PMP has no IPv6 form, and IPv6
generally wants a firewall pinhole rather than a mapping, which punching
already produces. Port mapping also only affects the first NAT hop, so
behind CGNAT the router will install a mapping that does nothing. The
client checks the external IP and says so when that happens.

**UPnP discovery is slow.** SSDP probing can take tens of seconds before
giving up on a router that does not support it.

The chat loop exists to show the path carries traffic. It is a
demonstration, not a protocol.

## References

- RFC 4787, [NAT Behavioral Requirements for Unicast UDP](https://www.rfc-editor.org/rfc/rfc4787),
  the mapping and filtering vocabulary
- RFC 5389, [Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc5389)
- RFC 6886, [NAT Port Mapping Protocol](https://www.rfc-editor.org/rfc/rfc6886)
- RFC 6887, [Port Control Protocol](https://www.rfc-editor.org/rfc/rfc6887)
- RFC 6455, [The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)
- RFC 9106, [Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- BIP-340, [Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- NIP-01, [Nostr basic protocol flow](https://github.com/nostr-protocol/nips/blob/master/01.md)
- Ford, Srisuresh, Kegel, [Peer-to-Peer Communication Across Network Address Translators](https://bford.info/pub/net/p2pnat/),
  the original treatment
- Tailscale, [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works),
  probably the best practical writeup out there
