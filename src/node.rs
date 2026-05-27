use anyhow::Result;
use iroh::{
    Endpoint,
    EndpointAddr,
    PublicKey,
    SecretKey,
    endpoint::{Connection, presets},
    // Use the explicit address lookup types matching version 0.98.2
    address_lookup::{
        mdns::MdnsAddressLookup,
        pkarr::dht::DhtAddressLookup,
    },
};
use tokio::sync::mpsc;

/// See https://docs.rs/iroh/latest/iroh/endpoint/presets/index.html and
/// https://docs.iroh.computer/concepts/discovery.
#[derive(Default)]
pub enum N0Discovery {
    #[default] Full,  // Use the n0.computer relay.
    DisableRelay,    // Use the n0.computer only for discovery.
    NoN0,             // Rely on mDNS and/or DHT (which must be enabled in NodeExtraConfig).
}


/// Configuration options for initializing a TransportNode.
/// See https://docs.iroh.computer/concepts/discovery.
pub struct NodeExtraConfig {
    pub n0_discovery: N0Discovery,
    pub use_mdns: bool,
    pub use_dht: bool,
}

impl Default for NodeExtraConfig {
    fn default() -> NodeExtraConfig {
        NodeExtraConfig {
            n0_discovery: Default::default(),
            use_mdns: true,
            use_dht: true,
        }
    }
}

/// The primary node for secure P2P transport, abstracting NAT traversal and address resolution.
pub struct TransportNode {
    // The underlying asynchronous iroh endpoint.
    endpoint: Endpoint,
    // Cached ALPN identifier used for initiating connections.
    alpn: Vec<u8>,
}

impl TransportNode {
    /// Initializes the endpoint, applies the identity key, and activates fully decentralized discovery.
    ///
    /// secret_key: The cryptographic identity of the node.
    /// alpn: Application-Layer Protocol Negotiation (ALPN) byte string (e.g.,
    ///   b"secure-p2p-transport/0.1").
    pub async fn new(secret_key: SecretKey, alpn: Vec<u8>, options: &NodeExtraConfig) -> Result<Self> {
        let builder = match options.n0_discovery {
            N0Discovery::Full => iroh::endpoint::Builder::new(presets::N0),
            N0Discovery::DisableRelay => iroh::endpoint::Builder::new(presets::N0DisableRelay),
            N0Discovery::NoN0 => iroh::endpoint::Builder::new(presets::Minimal),
        }.secret_key(secret_key.clone())
         .alpns(vec![alpn.clone()]);
        let builder = if options.use_dht {
            builder.address_lookup(DhtAddressLookup::builder().build()?)
        } else {
            builder
        };
        let builder = if options.use_mdns {
            builder.address_lookup(MdnsAddressLookup::builder().build(secret_key.public())?)
        } else {
            builder
        };

        Ok(Self { endpoint: builder.bind().await?, alpn: alpn })
    }

    /// Exposes the node's unique public identity.
    pub fn public_key(&self) -> PublicKey {
        self.endpoint.secret_key().public()
    }

    /// Extracts the remote peer's public key (Endpoint ID) from an established Iroh connection.
    pub fn get_remote_public_key(connection: &Connection) -> PublicKey {
        connection.remote_id()
    }

    /// Asynchronously establishes a connection to a remote peer using only their public key.
    pub async fn connect(&self, peer_id: PublicKey) -> Result<Connection> {
        let endpoint_addr = EndpointAddr::from(peer_id);
        let connection = self.endpoint.connect(endpoint_addr, &self.alpn).await?;
        Ok(connection)
    }

    /// Gracefully closes the underlying endpoint link.
    pub async fn close(self) {
        self.endpoint.close().await;
    }

    pub fn is_closed(&self) -> bool {
        self.endpoint.is_closed()
    }

    /// Spawns an internal background task accepting incoming connections.
    /// Provides an optional stateless function pointer to filter connections based on the remote peer's public key.
    pub fn listen(&self, filter: Option<fn(PublicKey) -> bool>) -> mpsc::Receiver<Connection> {
        let endpoint = self.endpoint.clone();
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let tx = tx.clone();

                tokio::spawn(async move {
                    match connecting.await {
                        Ok(connection) => {
                            if let Some(f) = filter {
                                let remote_id = connection.remote_id();
                                if !f(remote_id) {
                                    tracing::info!("Connection from peer {} rejected by ALPN filter", remote_id);
                                    let _ = connection.close(0u32.into(), b"Rejected by peer ALPN filter");
                                    return;
                                }
                            }

                            match tx.reserve().await {
                                Ok(permit) => permit.send(connection),
                                Err(e) => {
                                    tracing::debug!("Receiver channel dropped; incoming connection discarded: {}", e);
                                    let _ = connection.close(0u32.into(), b"Not accepting new connections any more");
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!("Error completing QUIC handshake: {:?}", err);
                        }
                    }
                });
            }
            tracing::info!("Endpoint closed; terminating accept loop");
        });

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_and_listen_lifecycle() {
        let secret_key = SecretKey::generate();
        let node = TransportNode::new(secret_key, b"secure-p2p-transport/test/0.1".to_vec(), &NodeExtraConfig {
            n0_discovery: N0Discovery::NoN0,
            use_dht: false,
            use_mdns: true,
          }).await.expect("Failed to create node");
        let connection_rx = node.listen(None);

        assert!(!connection_rx.is_closed());
        node.close().await;
    }
}
