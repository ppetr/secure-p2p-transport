use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use iroh::{
    PublicKey, Watcher,
    endpoint::{Connection, PathInfoList},
};
use tracing::{Level, event};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsRelayed {
    Yes,
    No,
    NotConnected,
}

impl From<IsRelayed> for Option<bool> {
    fn from(x: IsRelayed) -> Self {
        match x {
            IsRelayed::Yes => Some(true),
            IsRelayed::No => Some(false),
            IsRelayed::NotConnected => None,
        }
    }
}

/// Extracts the remote peer's public key (Endpoint ID) from an established Iroh connection.
pub fn get_remote_public_key(connection: &Connection) -> PublicKey {
    connection.remote_id()
}

fn is_pathinfolist_relayed(l: PathInfoList) -> IsRelayed {
    match l.into_iter().find(|p| p.is_selected()) {
        None => IsRelayed::NotConnected,
        Some(p) if p.is_relay() => IsRelayed::Yes,
        _ => IsRelayed::No,
    }
}

/// Returns whether `connection` is currently relayed (for example through n0.computer, see
/// https://docs.iroh.computer/concepts/relays). Returns `None` iff `connection` isn't connected.
pub fn is_relayed(connection: &Connection) -> IsRelayed {
    is_pathinfolist_relayed(connection.paths().get())
}

/// Returns an asynchronous stream that receives updates whether `connection` is currently relayed
/// (for example through n0.computer, see https://docs.iroh.computer/concepts/relays).
/// This allows callers to wait to wait until NAT traversel
/// (https://docs.iroh.computer/concepts/nat-traversal) kicks in before starting communication. Note
/// that this can also never happen, if NAT traversal fails.
/// The stream returns `None` iff `connection` isn't connected.
pub fn is_relayed_receiver(connection: &Connection) -> impl Stream<Item = IsRelayed> {
    connection
        .paths()
        .map(|l: PathInfoList| is_pathinfolist_relayed(l))
        .stream()
}

/// Wait until a direct connection is established with the remote peer. If the connection uses a
/// relay, wait until NAT traversal completes (https://docs.iroh.computer/concepts/nat-traversal).
/// Note that this condition may also never happen if NAT traversal fails, therefore it's
/// recommended to guard this call with a timeout.
/// Also, since QUIC allows peers to change networks, it can happen that the connection resorts back
/// to relaying even after this call finishes.
/// Cancellation safe.
pub async fn wait_for_direct(connection: &Connection) -> anyhow::Result<()> {
    let mut is_relayed = is_relayed_receiver(&connection);
    loop {
        let relayed = is_relayed.next().await.ok_or(anyhow::anyhow!(
            "Stream closed unexpectedly, probably connection has been closed"
        ))?;
        event!(
            Level::DEBUG,
            "Connection relayed {:?}; {:?}",
            relayed,
            connection.to_info()
        );
        if let IsRelayed::No = relayed {
            break Ok(());
        }
    }
}
