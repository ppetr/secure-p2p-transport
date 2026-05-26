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

/// Configuration options for initializing a TransportNode.
pub struct TransportNodeOptions {
    /// The cryptographic identity of the node.
    pub secret_key: SecretKey,
    /// Application-Layer Protocol Negotiation (ALPN) byte string 
    /// (e.g., b"secure-p2p-transport/0.1").
    pub alpn: Vec<u8>,
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
    pub async fn new(options: TransportNodeOptions) -> Result<Self> {
        // Instantiate both lookup mechanisms as requested via their respective builders
        let dht_lookup = DhtAddressLookup::builder().build()?;  // TODO: BROKEN
        let mdns_lookup = MdnsAddressLookup::builder().build(options.secret_key.public())?;

        let alpn = options.alpn.clone();
        // Attach both directly to the Endpoint builder configuration pipeline
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(options.secret_key)
            .address_lookup(dht_lookup)
            .address_lookup(mdns_lookup)
            .alpns(vec![alpn.clone()])
            .bind()
            .await?;

        Ok(Self { endpoint, alpn })
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

    /// Gracefully closes the underlying endpoint link.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_and_listen_lifecycle() {
        let secret_key = SecretKey::generate();
        let options = TransportNodeOptions {
            secret_key,
            alpn: b"secure-p2p-transport/test/0.1".to_vec(),
        };

        let node = TransportNode::new(options).await.expect("Failed to create node");
        let connection_rx = node.listen(None);

        assert!(!connection_rx.is_closed());
        node.close().await;
    }
}
