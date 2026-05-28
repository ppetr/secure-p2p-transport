# Secure P2P transport

A simple framework to securely connect to peers in a P2P network without
relying on DNS.

_*Disclaimer:* This is not an officially supported Google product._

## Overview

`secure-p2p-transport` is a Rust framework designed to establish direct, secure
peer-to-peer communication channels that bypass traditional centralized naming
layers.

Instead of DNS infrastructure, the architecture couples
**[Pkarr](https://github.com/n0-computer/pkarr)** for decentralized peer
routing via the Mainline DHT with **[Iroh](https://iroh.computer/)** for secure
endpoint connectivity and reliable byte-level stream transport.

Every transport node is initialized with a
[Ed25519](https://en.wikipedia.org/wiki/Ed25519) private key. The corresponding
**public key becomes its network identifier,** as well as a key in the DHT storing
the node's network address. All connections between nodes are protected by **TLS
using the same key.** This allows clients to **verify the cryptographic identity of
their peers** as part of creating network connections.

## Under-the-Hood: Built on QUIC

Every connection established by `secure-p2p-transport` leverages the **[QUIC
transport protocol](https://datatracker.ietf.org/doc/html/rfc9000)** through
Iroh's underlying networking stack. QUIC provides substantial advantages for
peer-to-peer networking over classic TCP+TLS architectures:

- **Built-in Encryption**: QUIC fully integrates TLS 1.3 cryptographic
  handshakes directly into its transport layer, enforcing zero-trust mutual
  authentication between peer keys without performance overhead.
- **Connection Migration**: Connections are resilient to IP address
  changes—critical for mobile nodes or roaming peers switching networks.
- **Multiplexing with No Head-of-Line Blocking**: Multiple independent data
  streams can run concurrently over a single connection; a dropped packet on
  one stream will not stall data transmission on another.
- **NAT Traversal Friendliness**: Operating over UDP makes robust
  [hole-punching and STUN/DERP
  configurations](https://iroh.computer/docs/layers/net) significantly more
  effective when navigating restrictive firewalls.

## Usage Example

To see how to initialize a network node using discovery options
(`MdnsAddressLookup`, `DhtAddressLookup`), configure peer filtering via
closures, or handle secure incoming connections, check out the implementation
setup in the codebase:
- 📄 **[src/node.rs](src/node.rs)**
- 🔧 **[tests/integration-test.rs](tests/integration-test.rs)**

```rust
let alpn_protocol = b"secure-p2p-transport/integration-test/1.0".to_vec();
// 1. Spin up Bob (the listener)
let bob_secret = SecretKey::generate();  // Or load from disk.
let bob_node = TransportNode::new(bob_secret, alpn_protocol.clone(), &Default::default()).await?;
let bob_pubkey = bob_node.public_key();
let mut bob_incoming = bob_node.listen_any(None);

// 2. Spin up Alice (the connector)
let alice_secret = SecretKey::generate();  // Or load from disk.
let alice_node = TransportNode::new(alice_secret, alpn_protocol, &Default::default()).await?;
let alice_pubkey = alice_node.public_key();

// 3. Alice attempts to establish connection using only Bob's PublicKey
let alice_connection = alice_node.connect(bob_pubkey).await?;

// 4. Accept the incoming connection from Bob's perspective
let bob_connection = bob_incoming
    .recv()
    .await
    .expect("Bob failed to receive connection");
```

## Architecture & Background

For the original protocol design, and the technical specification driving this
project see:

- 💻 **[docs/original-design.md](docs/original-design.md)**

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.
