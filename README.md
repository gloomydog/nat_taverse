# nat_traverse: NAT hole punching and P2P rendezvous


Direct peer to peer UDP connections across NAT, written in C, with no
server of your own required.
 
Rendezvous happens over public [Nostr](https://nostr.com) relays, so
there's nothing to deploy. Both peers run the same command with the same
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
 
A conventional rendezvous server is also included, for the cases where a
direct path just isn't possible and traffic needs to be relayed.
 
Dependencies: POSIX sockets and pthreads for everything, plus
libsecp256k1 and OpenSSL for the Nostr client. Nothing else.
 
 
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
 
It doesn't matter who starts first, whoever does waits up to 120 seconds
for the other.
 
Pass `0` as the port unless you have a specific reason not to.
 
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
 
`p2p_nostr` is the one to reach for first. Most home routers use
endpoint independent mapping and support UPnP or NAT-PMP, so a direct
path usually opens without much trouble.
 
`p2p_connect` covers the cases `p2p_nostr` can't like the case when both peers sit
symmetric NAT.
 
---
 
## Design
 
```
        p2p_nostr                       p2p_connect
            |                                |
    +----------------+              +-----------------+
    | signaling_nostr|              |  relay_client   |
    |   nostr + ws   |              |   relay_proto   |
    +-------+--------+              +--------+--------+
            |      (signaling.h interface)   |
            +---------------+-----------------+
                            |
              +-------------+-------------+
              |             |             |
           portmap       holepunch      stun
        NAT-PMP/PCP/    punch + ka    RFC 5389
           UPnP
```
 
`signaling.h` is the seam between the two approaches. Both backends
implement it, so swapping the rendezvous transport doesn't touch the
punching code at all. A BitTorrent DHT or an existing messaging channel
would drop into the same interface without much fuss.
 
### How the Nostr backend works
 
1. Derive from the shared secret (PBKDF2-HMAC-SHA256): a secp256k1
   signing key, the same one for both peers, plus a ChaCha20-Poly1305
   key derived with an independent salt.
2. Ask STUN for our public address.
3. Publish it, encrypted, as an ephemeral event (kind 20117).
4. Subscribe with `authors` set to our shared pubkey and decrypt the
   peer's event when it arrives.
5. Punch.
Both peers signing with the same key is what makes the rendezvous work
at all. To a relay they look like one identity posting twice, and each
side finds the other with an `authors` filter. The meeting point really
is the pubkey itself.
 
Kinds 20000 through 29999 are ephemeral: relays forward them but don't
store them. Signalling data is worthless a few seconds later anyway, so
this is the right range to use, and it leaves nothing behind on public
infrastructure.
 
Addresses are always encrypted before publishing. Anything sitting in an
event's `content` field is world readable otherwise.
 
| file | what it does |
|---|---|
| `p2p_nostr.c` | client: portmap, STUN, Nostr rendezvous, punch |
| `p2p_connect.c` | client: portmap, server rendezvous, punch, relay |
| `relay_server.c` | rendezvous and relay server |
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
 
Read this before using the code for anything real.
 
The tokens and meeting ids here are lightweight filters, not
authentication. `derive_token()` in the clients and `relay_derive_id()`
are not KDFs, they're simple mixing functions, and should be replaced
with Argon2id (or whatever your application already uses) before you
depend on them for anything. The punch token itself travels in clear
text; its only job is to stop an unrelated datagram from being mistaken
for the peer. Both peers also share the Nostr signing key, which proves
knowledge of the secret and nothing more. Anyone who has the secret can
join the rendezvous.
 
So authenticate the peer cryptographically in your own handshake once
the path is open. A successful punch is not identification.
 
What the code does handle properly: addresses published to Nostr are
encrypted with ChaCha20-Poly1305 under a key derived independently of the
signing key, and AEAD means any tampering gets caught. `wss://`
connections verify certificates and hostnames. `relay_server` only
forwards between registered peers, so it can't be turned into an open
reflector. The relay itself never sees plaintext, it just forwards
opaque bytes.
 
If you run `relay_server` publicly, add rate and bandwidth limits.
 
---
## Limitations
**UDP only**. Where UDP is blocked outright, nothing here works, which is
why DERP runs over HTTPS on TCP 443 instead. A TCP transport would be a
reasonable thing to add.
 
**IPv4 only**. IPv6 mostly makes this whole problem go away, which is a nice
thought but not something implemented here.
 
Both peers behind CGNAT won't get a direct path, full stop. Use
`p2p_connect` with your own `relay_server` in that case.
 
UPnP discovery is slow. SSDP probing can take tens of seconds before
giving up on a router that doesn't support it.
 
`p2p_nostr` has no data fallback, by design. Nostr relays aren't meant to
be a byte pipe.
 
The chat loop in both clients exists to show the path actually carries
traffic. It's a demonstration, not a protocol.
 

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

