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
}

impl TransportNode {
    /// Initializes the endpoint, applies the identity key, and activates fully decentralized discovery.
    pub async fn new(options: TransportNodeOptions) -> Result<Self> {
        let alpn = options.alpn.clone();

        // 3. Combine both engines into a concurrent tracking router
        let mut combined_discovery = ConcurrentDiscovery::empty();
        combined_discovery.add(DhtDiscovery::builder().build()?);
        combined_discovery.add(LocalSwarmDiscovery::new(options.secret_key.public())?);
        let combined_discovery = combined_discovery;

        // 4. Build the endpoint cleanly without the cloud n0 DNS infrastructure
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

    /// Starts a background loop to listen for incoming connections.
    /// Established connections are sent to the returned mpsc receiver channel.
    pub fn listen(&self) -> mpsc::Receiver<Connection> {
        // Create a bounded channel for established connections
        let (tx, rx) = mpsc::channel::<Connection>(32);
        let endpoint = self.endpoint.clone();

        tokio::spawn(async move {
            tracing::info!("Starting TransportNode connection accept loop");

            while !tx.is_closed() {
                // Fetch incoming connection attempts from the endpoint
                match endpoint.accept().await {
                    Some(connecting) => {
                        let tx = tx.clone();
                        
                        // Spawn a separate task for the QUIC handshake to avoid blocking 
                        // the main accept loop for other incoming connections
                        tokio::spawn(async move {
                            match connecting.await {
                                Ok(connection) => {
                                    // Successfully established connection; send to receiver channel
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

        // The channel should be open and waiting for connections
        assert!(!connection_rx.is_closed());
    }
}
