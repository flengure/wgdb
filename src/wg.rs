/// WireGuard kernel interface management via wireguard-control (netlink).
///
/// All functions are synchronous and must be called via spawn_blocking
/// from async context.
use anyhow::{Context, Result};
use std::collections::HashMap;

use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use crate::db::{Interface, Peer};

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a new WireGuard private key. Returns (private_b64, public_b64).
pub fn generate_keypair() -> Result<(String, String)> {
    let private = Key::generate_private();
    let public = private.get_public();
    Ok((private.to_base64(), public.to_base64()))
}

/// Generate a preshared key (32 random bytes, base64).
pub fn generate_psk() -> String {
    Key::generate_preshared().to_base64()
}

// ── Interface lifecycle ───────────────────────────────────────────────────────

/// Apply full interface configuration (private key, listen port, all peers).
/// The kernel WireGuard interface must already exist (created by net::create_link).
pub fn configure(iface: &Interface, peers: &[Peer]) -> Result<()> {
    let name: InterfaceName = iface.name.parse().context("invalid interface name")?;
    let private = Key::from_base64(&iface.private_key).context("invalid private key")?;

    let mut update = DeviceUpdate::new()
        .set_private_key(private)
        .set_listen_port(iface.listen_port as u16);

    for peer in peers {
        update = update.add_peer(build_peer_config(peer)?);
    }

    update.apply(&name, Backend::Kernel).context("wg configure")?;
    tracing::info!("wg: configured {} with {} peers", iface.name, peers.len());
    Ok(())
}

/// Hot-add or update a single peer on a live interface.
pub fn add_peer(iface_name: &str, peer: &Peer) -> Result<()> {
    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    DeviceUpdate::new()
        .add_peer(build_peer_config(peer)?)
        .apply(&name, Backend::Kernel)
        .context("wg add_peer")?;
    tracing::info!("wg: added peer {} to {}", &peer.pubkey[..8], iface_name);
    Ok(())
}

/// Remove a peer from a live interface by public key.
pub fn remove_peer(iface_name: &str, pubkey: &str) -> Result<()> {
    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    let key = Key::from_base64(pubkey).context("invalid pubkey")?;
    DeviceUpdate::new()
        .remove_peer_by_key(&key)
        .apply(&name, Backend::Kernel)
        .context("wg remove_peer")?;
    tracing::info!("wg: removed peer {} from {}", &pubkey[..8], iface_name);
    Ok(())
}

// ── Stats ─────────────────────────────────────────────────────────────────────

/// Read last-handshake timestamps from the live interface.
/// Returns a map of base64-pubkey → unix timestamp seconds.
pub fn peer_handshakes(iface_name: &str) -> Result<HashMap<String, i64>> {
    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    let device = wireguard_control::Device::get(&name, Backend::Kernel)
        .context("wg get device")?;

    let mut map = HashMap::new();
    for peer in &device.peers {
        if let Some(hs) = peer.stats.last_handshake_time {
            let ts = hs
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d: std::time::Duration| d.as_secs() as i64)
                .unwrap_or(0);
            map.insert(peer.config.public_key.to_base64(), ts);
        }
    }
    Ok(map)
}

pub struct InterfaceStats {
    pub peer_count: usize,
    pub rx_bytes:   u64,
    pub tx_bytes:   u64,
}

pub fn interface_stats(iface_name: &str) -> Result<InterfaceStats> {
    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    let device = wireguard_control::Device::get(&name, Backend::Kernel)
        .context("wg get device")?;

    let (rx, tx) = device
        .peers
        .iter()
        .fold((0u64, 0u64), |(rx, tx), p| (rx + p.stats.rx_bytes, tx + p.stats.tx_bytes));

    Ok(InterfaceStats {
        peer_count: device.peers.len(),
        rx_bytes: rx,
        tx_bytes: tx,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_peer_config(peer: &Peer) -> Result<PeerConfigBuilder> {
    let pubkey = Key::from_base64(&peer.pubkey).context("invalid peer pubkey")?;
    let mut cfg = PeerConfigBuilder::new(&pubkey);

    if let Some(psk) = &peer.psk {
        let psk_key = Key::from_base64(psk).context("invalid psk")?;
        cfg = cfg.set_preshared_key(psk_key);
    }

    // allowed_ips: the peer's allocated addresses
    if let Some(ipv4) = &peer.ipv4
        && let Ok((addr, prefix)) = parse_cidr_v4(ipv4) {
            cfg = cfg.add_allowed_ip(std::net::IpAddr::V4(addr), prefix);
        }
    if let Some(ipv6) = &peer.ipv6
        && let Ok((addr, prefix)) = parse_cidr_v6(ipv6) {
            cfg = cfg.add_allowed_ip(std::net::IpAddr::V6(addr), prefix);
        }

    Ok(cfg)
}

fn parse_cidr_v4(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = cidr.split_once('/').context("invalid IPv4 CIDR")?;
    Ok((ip.parse()?, prefix.parse()?))
}

fn parse_cidr_v6(cidr: &str) -> Result<(std::net::Ipv6Addr, u8)> {
    let (ip, prefix) = cidr.split_once('/').context("invalid IPv6 CIDR")?;
    Ok((ip.parse()?, prefix.parse()?))
}
