use anyhow::Result;
use iroh::{endpoint::Endpoint, key::SecretKey};

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
    /// Initializes the endpoint, applies the identity key, and activates Pkarr discovery.
    pub async fn new(options: TransportNodeOptions) -> Result<Self> {
        let endpoint = Endpoint::builder()
            // 1. Assign the secret key for cryptographic identity
            .secret_key(options.secret_key)
            // 2. Configure the ALPN protocol identifier
            .alpns(vec![options.alpn])
            // 3. Enable standard discovery (registers Pkarr publisher/resolver + Mainline DHT)
            .discovery_n0()
            // 4. Bind to [::]:0 and 0.0.0.0:0 (random local ports)
            .bind()
            .await?;

        Ok(Self { endpoint })
    }

    /// Returns the public key (Node ID) of this transport node.
    pub fn public_key(&self) -> iroh::key::PublicKey {
        self.endpoint.node_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_node() {
        let secret = SecretKey::generate();
        let _node = TransportNode::new(TransportNodeOptions{secret_key: secret, alpn: vec![]}).await;
    }
}
