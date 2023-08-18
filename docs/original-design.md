## Objective

Create a simple framework that will allow to securely connect to peers in a P2P
network without relying on DNS.

This project builds upon a lower level project
_Experimental simplified DTLS packet transport interface_
(see https://github.com/ppetr/secure-packet-transport).

## Background

P2P networks are commonly based on a
[distributed hash-table](https://en.wikipedia.org/wiki/Distributed_hash_table),
which allows peers to publish their connection information, linked to their
randomly generated keys.

[SSL](https://en.wikipedia.org/wiki/Transport_Layer_Security) allows to
establish a secure communcation channel among two peers and verify their
mutual identity by verifying their peers' public keys.

## Design ideas

Commonly SSL identifies a server by verifying its DNS name against its public
key, and by checking the chain of certificates up to a known, trusted (root)
certificate. This is unsuitable to a P2P network where peers often do not have
DNS names, and whose network identity and address might change frequently. Also
this requires a complicated process of requesting such a signature from
an established, trusted authority known in advance to all parties.

We propose here an approach that is more suitable to P2P, and at the same time
makes establishing secure connections very simple.

Each peer creates a public/private SSL key pair. The
*[fingerprint](https://en.wikipedia.org/wiki/Public_key_fingerprint)* of the
public key becomes *the identity* of the peer. Then the peer opens a listening server
network connection, and publishes its address under the identity in the DHT.

Peers need to know only the identity, the fingerprint, of others, to establish a
secure connection to them. A peer looks up the network connection to another one
in the DHT using the target's identity. It connects to it and establishes a SSL
connection. Then it requests its public SSL key, and verifies that its
fingerprint matches the identity. (Alternatively it can verify that the peer's
public key is signed by a certificate that matches the identity.)

Since fingerprints are constructed using cryptographically secure hashes, a
malicious peer cannot impersonate another one. It cannot construct a SSL key
whose fingerprint would match the other node's identity.

## Contributions and future plans

Once a skeleton of the project becomes available, contributions will be
welcomed! Please see [Code of Conduct](docs/code-of-conduct.md) and
[Contributing](docs/contributing.md).
