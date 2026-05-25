# Implementation Plan: Secure P2P Transport (PoC)

## 1. Architectural Goals and Mapping to Iroh
The goal is to create a minimalist transport node (`TransportNode`) that completely abstracts away the complexities of NAT traversal and distributed address resolution.

* **Node Identity (`SecretKey` / `PublicKey`):** We will use Ed25519 cryptographic keys from Iroh. The `PublicKey` (32 bytes) serves directly as a unique global `EndpointId` (referred to as `NodeId` in Iroh's terminology).
* **Human-Readable Format:** To present the ID, we will use Iroh/Pkarr's built-in formatting to encode it into a **z-base32** string (or base32 depending on the exact sub-version), which is safe for URLs and DNS subdomains.
* **Address Resolution (Pkarr & Mainline DHT):** Upon startup, the node registers an `iroh::discovery::pkarr::PkarrPublisher`. This automatically publishes local network endpoints and DERP/Relay information to the public Mainline DHT.
* **Establishing Connections:** When calling `connect(PublicKey)`, Iroh queries Pkarr (DHT) in the background, resolves the counterparty's network endpoints, and performs QUIC hole-punching.

---

## 2. API Design (Interface)

We will create a `TransportNode` struct in `src/lib.rs` with the following asynchronous interface:

```rust
pub struct TransportNode {
    // Internal state (Iroh Endpoint, potentially background tasks)
}

impl TransportNode {
    /// Initializes the endpoint, uses the provided key,
    /// and registers the Pkarr router/publisher for address discovery.
    pub async fn new(secret_key: SecretKey) -> Result<Self>;

    /// Starts a background task that accepts incoming QUIC connections
    /// and forwards them into an asynchronous channel (tokio::sync::mpsc).
    /// Returns a Receiver from which the application will consume iroh::endpoint::Connection.
    pub fn listen(&self) -> mpsc::Receiver<Connection>;

    /// Resolves a node using Pkarr and establishes an encrypted QUIC connection.
    pub async fn connect(&self, peer_id: PublicKey) -> Result<Connection>;
}
```

---

## 3. Step-by-Step Implementation Phase

### Phase 1: Analysis and Dependency Fixation (`Cargo.toml`)
* Verify the current feature flags for `iroh`. In newer versions, features such as `pkarr` and `discovery` must be explicitly enabled.
* Ensure correct versions of companion crates (`tokio` for the async runtime and channels, `anyhow` for error handling, `tracing` for NAT traversal diagnostics).

### Phase 2: Key Management and Formatting
* Create helper functions for key persistence: `save_key_to_disk` and `load_key_from_disk` (working with a raw 32-byte array).
* Implement conversion functions: `PublicKey` <-> `String` (z-base32) to easily hand off IDs to the user.

### Phase 3: Construction of `TransportNode::new`
* Configure `iroh::Endpoint::builder()`.
* Properly wire the Pkarr publisher into the builder. (In modern Iroh, Pkarr is configured using the `Discovery` mechanism, passing a client/publisher that communicates with a Pkarr relay or directly with the DHT).
* Bind to a random local port (supporting both IPv4 and IPv6).

### Phase 4: Implementation of `listen()` and Event Loop
* Because `iroh::Endpoint::accept` is an asynchronous method that must be called in a loop, `listen()` will start a `tokio::spawn` background loop.
* This loop will fetch incoming connections (`endpoint.accept().await`), asynchronously complete the QUIC handshake (`connecting.await`), and send successfully established connections (`Connection`) into a `tokio::sync::mpsc` channel.
* Once the channel is closed by the receiver, the asynchronous QUIC connection is properly cleaned up and closed as well.

### Phase 5: Implementation of `connect()`
* Construct an `iroh::NodeAddr` using only the `PublicKey` (without explicit IP addresses).
* Call `endpoint.connect(node_addr, iroh::protocol::ALPN)`. In the background, Iroh activates Pkarr resolution, discovers the addresses, and attempts to connect.

---

## 4. Testing Strategy

To validate the proof-of-concept, we design two types of tests:

### A. Unit Tests (`src/lib.rs`)
* **Identity Test:** Verify that after initializing a node, we can export the `PublicKey`, convert it to a string, and successfully parse it back.
* **Persistence Test:** Verify that a node started with the same `SecretKey` loaded from disk yields an identical `PublicKey`.

### B. Integration Test (`tests/integration_test.rs`)
* Simulate a complete lifecycle within a single asynchronous test.
* Initialize two nodes: `alice` and `bob`.
* Call `bob.listen()` to start capturing connections.
* Call `alice.connect(bob.public_key())`.
* **Data Transfer Verification:** Once the connection is established, open a QUIC stream (`connection.open_bi()`), through which the nodes exchange a test message (e.g., `"Hello P2P"`), confirming the functionality of the entire stack, including Pkarr discovery.
