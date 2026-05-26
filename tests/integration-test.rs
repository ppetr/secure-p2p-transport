use anyhow::Result;
use iroh::key::SecretKey;
use secure_p2p_transport::{TransportNode, TransportNodeOptions};

#[tokio::test]
async fn test_end_to_end_node_transport() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let alpn_protocol = b"secure-p2p-transport/integration-test/1.0".to_vec();

    // 1. Spin up Bob (the listener)
    let bob_secret = SecretKey::generate();
    let bob_options = TransportNodeOptions {
        secret_key: bob_secret,
        alpn: alpn_protocol.clone(),
    };
    let bob_node = TransportNode::new(bob_options).await?;
    let bob_pubkey = bob_node.public_key();
    let mut bob_incoming = bob_node.listen();

    // 2. Spin up Alice (the connector)
    let alice_secret = SecretKey::generate();
    let alice_options = TransportNodeOptions {
        secret_key: alice_secret,
        alpn: alpn_protocol,
    };
    let alice_node = TransportNode::new(alice_options).await?;

    // 3. Alice attempts to establish connection using only Bob's PublicKey
    let alice_connection = alice_node.connect(bob_pubkey).await?;

    // 4. Accept the incoming connection from Bob's perspective
    let bob_connection = bob_incoming
        .recv()
        .await
        .expect("Bob failed to receive Alice's incoming connection");

    // TODO: Figure out how to get the peers' identities here.
    // assert_eq!(bob_connection..remote_node_id()?, alice_node.public_key());
    // assert_eq!(alice_connection.remote_node_id()?, bob_pubkey);

    // 5. Open a bidirectional communication stream from Alice to Bob
    let (mut alice_send, mut alice_recv) = alice_connection.open_bi().await?;

    // Alice sends a payload
    let test_message = b"Hello P2P Sourdough and Bees";
    alice_send.write_all(test_message).await?;
    alice_send.finish()?;

    // Bob accepts the incoming bidirectional stream
    let (mut bob_send, mut bob_recv) = bob_connection.accept_bi().await?;

    // Bob reads the payload using a pre-allocated limit-based buffer
    // iroh-quinn's read_to_end takes a max size limit and returns Result<Vec<u8>>
    let bob_read_buffer = bob_recv.read_to_end(1024).await?;
    assert_eq!(bob_read_buffer, test_message);

    // 6. Bob responds back over the same stream
    let response_message = b"Message received securely via local mDNS/DHT discovery";
    bob_send.write_all(response_message).await?;
    bob_send.finish()?;

    // Fix 2: Read Bob's response payload using the proper size-limited signature
    let alice_read_buffer = alice_recv.read_to_end(1024).await?;
    assert_eq!(alice_read_buffer, response_message);

    Ok(())
}
