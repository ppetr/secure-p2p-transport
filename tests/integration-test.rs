use anyhow::Result;
use iroh::SecretKey;
use secure_p2p_transport::connection::*;
use secure_p2p_transport::{N0Discovery, NodeExtraConfig, TransportNode};

#[tokio::test]
async fn test_end_to_end_node_transport() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let alpn_protocol = b"secure-p2p-transport/integration-test/1.0".to_vec();
    let options = NodeExtraConfig {
        n0_discovery: N0Discovery::NoN0,
        use_dht: false,
        use_mdns: true,
    };

    let bob_secret = SecretKey::generate();
    let alice_secret = SecretKey::generate();

    // Spin up the nodes.
    let bob_node = TransportNode::new(bob_secret, alpn_protocol.clone(), &options).await?;
    let bob_pubkey = bob_node.public_key();
    let alice_node = TransportNode::new(alice_secret, alpn_protocol, &options).await?;
    let alice_pubkey = alice_node.public_key();

    // Bob listens on incoming connections.
    let mut bob_incoming = bob_node.listen_filtered(move |key| {
        key == alice_pubkey // Allow only connections from Alice.
    });

    // Alice attempts to establish connection using only Bob's PublicKey
    let alice_connection = alice_node.connect(bob_pubkey).await?;

    // Accept the incoming connection from Bob's perspective
    let bob_connection = bob_incoming
        .recv()
        .await
        .expect("Bob failed to receive connection");

    // In case `N0Discovery::Full` is enabled above, test that eventually after establishing the
    // connection, the channel becomes connected directly without a relay
    // (https://docs.iroh.computer/concepts/nat-traversal).
    wait_for_direct(&bob_connection).await?;

    // Verify the peer identities using the new helper method
    let bobs_view_of_alice = get_remote_public_key(&bob_connection);
    assert_eq!(bobs_view_of_alice, alice_pubkey);

    let alices_view_of_bob = get_remote_public_key(&alice_connection);
    assert_eq!(alices_view_of_bob, bob_pubkey);

    // Open a bidirectional communication stream from Alice to Bob
    let (mut alice_send, mut alice_recv) = alice_connection.open_bi().await?;

    // Alice sends a payload
    let test_message = b"Hello P2P Sourdough and Bees";
    alice_send.write_all(test_message).await?;
    alice_send.finish()?;

    // Bob accepts the incoming bidirectional stream
    let (mut bob_send, mut bob_recv) = bob_connection.accept_bi().await?;

    // Bob reads the payload using a pre-allocated limit-based buffer
    let bob_read_buffer = bob_recv.read_to_end(1024).await?;
    assert_eq!(bob_read_buffer, test_message);

    // 6. Bob responds back over the same stream
    let response_message = b"Message received securely via local mDNS/DHT discovery";
    bob_send.write_all(response_message).await?;
    bob_send.finish()?;

    // Alice reads Bob's response
    let alice_read_buffer = alice_recv.read_to_end(1024).await?;
    assert_eq!(alice_read_buffer, response_message);

    alice_node.close().await;
    bob_node.close().await;

    Ok(())
}
