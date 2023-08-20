// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Adapted from:
// - https://github.com/libp2p/rust-libp2p/tree/cbdbaa836e1159fb4e8b20e76c32f1af5ec66926/examples/chat-example
//   Copyright 2018 Parity Technologies (UK) Ltd.
// - https://github.com/mxinden/libp2p-lookup/blob/615606c79d820b0ad76751b9728d5e97580bdc24/src/main.rs
//   Copyright (c) 2020 Max Inden

#![doc = include_str!("../README.md")]

// TODO: It's neccessary to incorporate the Identify protocol to discover peers.
//
// > Peer Discovery with Identify In other libp2p implementations, the Identify protocol might be
// > seen as a core protocol. Rust-libp2p tries to stay as generic as possible, and does not make
// > this assumption. This means that the Identify protocol must be manually hooked up to Kademlia
// > through calls to Kademlia::add_address. If you choose not to use the Identify protocol, and do
// > not provide an alternative peer discovery mechanism, a Kademlia node will not discover nodes
// > beyond the network’s boot nodes. Without the Identify protocol, existing nodes in the kademlia
// > network cannot obtain the listen addresses of nodes querying them, and thus will not be able to
// > add them to their routing table.
//
// https://docs.rs/libp2p-kad/latest/libp2p_kad/

use async_std::io;
use futures::{prelude::*, select};
use libp2p::{
    core::muxing::StreamMuxerBox,
    core::transport::OrTransport,
    development_transport, gossipsub, identify, identity,
    kad::{
        record::store::MemoryStore, GetProvidersOk, Kademlia, KademliaConfig, KademliaEvent,
        QueryResult, RecordKey,
    },
    swarm::NetworkBehaviour,
    swarm::{SwarmBuilder, SwarmEvent},
    PeerId, Swarm, Transport,
};
use libp2p_quic as quic;
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;

// We create a custom network behaviour that combines Gossipsub and Kademlia.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: Kademlia<MemoryStore>,
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Create a random PeerId
    let local_peer = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_peer.public());
    println!("Local peer id: {local_peer_id}");

    let shared_dht_key =
        RecordKey::new(&"12D3KooWD3mFq2ijumTBcnuG5jQh3qC7ChjLNwf5WaPjh3aAWJr9".as_bytes());

    let quic_transport = quic::async_std::Transport::new(quic::Config::new(&local_peer));
    let transport = OrTransport::new(
        development_transport(local_peer.clone()).await?,
        quic_transport,
    )
    .map(|output, _| match output {
        Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
        Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
    })
    .boxed();

    // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    // Set a custom gossipsub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
        .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
        .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
        .build()
        .expect("Valid config");

    // build a gossipsub network behaviour
    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_peer),
        gossipsub_config,
    )
    .expect("Correct configuration");
    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("test-net");
    // subscribes to our topic
    gossipsub.subscribe(&topic)?;

    // Create a Kademlia behaviour.
    let mut kademlia = Kademlia::with_config(
        local_peer_id,
        MemoryStore::new(local_peer_id),
        KademliaConfig::default(),
    );
    for peer in &BOOTNODES {
        kademlia.add_address(&peer.parse()?, "/dnsaddr/bootstrap.libp2p.io".parse()?);
    }

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let behaviour = MyBehaviour {
            gossipsub,
            kademlia,
        };
        SwarmBuilder::with_async_std_executor(transport, behaviour, local_peer_id).build()
    };

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip6/::0/udp/0/quic-v1".parse()?)?;

    println!("Enter messages via STDIN and they will be sent to connected peers using Gossipsub");

    // Kick it off
    let kademlia = &mut swarm.behaviour_mut().kademlia;
    kademlia.start_providing(shared_dht_key.clone())?;
    kademlia.get_providers(shared_dht_key.clone());
    loop {
        select! {
            line = stdin.select_next_some() => {
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                        .publish(topic.clone(), line.expect("Stdin not to close").as_bytes()) {
                            println!("Publish error: {e:?}");
                            // Let's try to fetch providers again.
                            swarm.behaviour_mut().kademlia.get_providers(shared_dht_key.clone());
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(kademlia_event)) =>
                    match kademlia_event {
                        KademliaEvent::OutboundQueryProgressed {
                            result: QueryResult::Bootstrap(result),
                            ..
                        } => {
                            result?;
                            panic!("Unexpected bootstrap");
                        }
                        KademliaEvent::OutboundQueryProgressed {
                            result: QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders{ providers, .. })),
                            ..
                        } => {
                            for peer_id in providers {
                                if peer_id != local_peer_id && !Swarm::is_connected(&swarm, &peer_id) {
                                    println!("Kademlia discovered a new peer: {peer_id}");
                                    // TODO: Kademlia might not be caching the address of the peer.
                                    Swarm::dial(&mut swarm, peer_id)?;
                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                }
                            }
                        },
                        KademliaEvent::OutboundQueryProgressed {
                            result: QueryResult::GetProviders(Ok(GetProvidersOk::FinishedWithNoAdditionalRecord{ closest_peers })),
                            ..
                        } => {
                            println!("Finished getting providers, waiting for other peers to connect; closest peers: {closest_peers:?}");
                        },
                        KademliaEvent::OutboundQueryProgressed {
                            result: QueryResult::StartProviding(add_provider),
                            ..
                        } => {
                            add_provider?;
                            println!("Published this node as a provider for key");
                        },
                            ev => {
                                println!("Other Kademlia event: {ev:?}");
                            },
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: peer_id,
                        message_id: id,
                        message,
                    })) => println!("Got message: '{}' with id: {id} from peer: {peer_id}", String::from_utf8_lossy(&message.data)),
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Local node is listening on {address}");
                    }
                _ => {}
            }
        }
    }
}

// TODO:
// "/ip4/104.131.131.82/tcp/4001".parse()?,
// FromStr::from_str("QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ")?,

const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];
