use anyhow::Result;
use iroh::{
    discovery::{
        ConcurrentDiscovery,
        pkarr::dht::DhtDiscovery,
        local_swarm_discovery::LocalSwarmDiscovery,
    },
    endpoint::{Connection, Endpoint},
    key::{PublicKey, SecretKey},
    NodeAddr,
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
        let alpn = options.alpn.clone();

        // Combine both discovery engines into a concurrent tracking router
        let mut combined_discovery = ConcurrentDiscovery::empty();
        combined_discovery.add(DhtDiscovery::builder().build()?);
        combined_discovery.add(LocalSwarmDiscovery::new(options.secret_key.public())?);

        let endpoint = Endpoint::builder()
            .secret_key(options.secret_key)
            .alpns(vec![options.alpn])
            .discovery(Box::new(combined_discovery))
            .bind()
            .await?;

        Ok(Self { endpoint, alpn })
    }

    /// Returns the public key (Node ID) of this transport node.
    pub fn public_key(&self) -> PublicKey {
        self.endpoint.node_id()
    }

    /// Connects to a remote peer using only their public key.
    /// Address resolution via Mainline DHT and mDNS is handled automatically.
    pub async fn connect(&self, peer_id: PublicKey) -> Result<Connection> {
        let node_addr = NodeAddr::from(peer_id);
        let connection = self.endpoint.connect(node_addr, &self.alpn).await?;
        Ok(connection)
    }

    /// Starts a background loop to listen for incoming connections.
    /// Established connections are sent to the returned mpsc receiver channel.
    pub fn listen(&self) -> mpsc::Receiver<Connection> {
        // Create a bounded channel for established connections
        let (tx, rx) = mpsc::channel::<Connection>(32);
        let endpoint = self.endpoint.clone();

        tokio::spawn(async move {
            tracing::info!("Starting TransportNode connection accept loop");

            while !tx.is_closed() {
                match endpoint.accept().await {
                    Some(connecting) => {
                        let tx = tx.clone();
                        
                        tokio::spawn(async move {
                            match connecting.await {
                                Ok(connection) => {
                                    if let Err(_) = tx.send(connection).await {
                                        tracing::debug!("Receiver channel dropped; incoming connection discarded");
                                    }
                                }
                                Err(err) => {
                                    tracing::error!("Error completing QUIC handshake: {:?}", err);
                                }
                            }
                        });
                    }
                    None => {
                        tracing::info!("Endpoint closed; terminating accept loop");
                        break;
                    }
                }
            }
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
        let options = TransportNodeOptions {
            secret_key,
            alpn: b"secure-p2p-transport/test/0.1".to_vec(),
        };

        let node = TransportNode::new(options).await.expect("Failed to create node");
        let connection_rx = node.listen();

        assert!(!connection_rx.is_closed());
    }
}
