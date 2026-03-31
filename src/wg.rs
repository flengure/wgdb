//! WireGuard interface configuration — platform-specific implementations.
//!
//! All public functions are **synchronous** and must be called via
//! [`tokio::task::spawn_blocking`] from async context.
//!
//! # Platforms
//!
//! | Platform | Backend |
//! |----------|---------|
//! | Linux    | [`wireguard-control`] with `Backend::Kernel` (netlink) |
//! | macOS    | [`wireguard-control`] with `Backend::Userspace` (wireguard-go socket) |
//! | Windows  | WireGuard UAPI text protocol over a named pipe (`\\.\pipe\WireGuard\<name>`) |
//!
//! # Key encoding
//!
//! Keys are stored in the database as **Base64**.  The WireGuard UAPI protocol
//! (used for the Windows named-pipe path and Linux userspace sockets) encodes
//! keys as **hex**.  The conversion helpers at the bottom of this module handle
//! the translation on Windows.

use anyhow::{Context, Result};
use std::collections::HashMap;

use crate::db::{Interface, Peer};

// ── Public types ──────────────────────────────────────────────────────────────

/// Aggregate statistics for a WireGuard interface.
pub struct InterfaceStats {
    /// Number of currently configured peers.
    pub peer_count: usize,
    /// Total bytes received across all peers.
    pub rx_bytes: u64,
    /// Total bytes transmitted across all peers.
    pub tx_bytes: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unix implementation (Linux + macOS) via wireguard-control
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a new WireGuard keypair.
///
/// Returns `(private_key_base64, public_key_base64)`.
#[cfg(unix)]
pub fn generate_keypair() -> Result<(String, String)> {
    use wireguard_control::Key;
    let private = Key::generate_private();
    let public = private.get_public();
    Ok((private.to_base64(), public.to_base64()))
}

/// Generate a random 32-byte preshared key encoded as Base64.
#[cfg(unix)]
pub fn generate_psk() -> String {
    wireguard_control::Key::generate_preshared().to_base64()
}

/// Apply full interface configuration (private key, listen port, all peers) to
/// a live WireGuard interface.
///
/// On Linux the interface must already exist in the kernel (see
/// [`crate::net::create_link`]).  On macOS `wireguard-go` must be running and
/// its UNIX socket must be available.
#[cfg(unix)]
pub fn configure(iface: &Interface, peers: &[Peer]) -> Result<()> {
    use wireguard_control::{DeviceUpdate, InterfaceName, Key};

    let name: InterfaceName = iface.name.parse().context("invalid interface name")?;
    let private = Key::from_base64(&iface.private_key).context("invalid private key")?;

    let mut update = DeviceUpdate::new()
        .set_private_key(private)
        .set_listen_port(iface.listen_port as u16);

    for peer in peers {
        update = update.add_peer(build_peer_config(peer)?);
    }

    update
        .apply(&name, backend())
        .context("wg configure")?;
    tracing::info!("wg: configured {} with {} peers", iface.name, peers.len());
    Ok(())
}

/// Hot-add or update a single peer on a live interface without disrupting
/// existing sessions.
#[cfg(unix)]
pub fn add_peer(iface_name: &str, peer: &Peer) -> Result<()> {
    use wireguard_control::{DeviceUpdate, InterfaceName};

    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    DeviceUpdate::new()
        .add_peer(build_peer_config(peer)?)
        .apply(&name, backend())
        .context("wg add_peer")?;
    tracing::info!("wg: added peer {} to {}", &peer.pubkey[..8], iface_name);
    Ok(())
}

/// Remove a peer from a live interface by its Base64-encoded public key.
#[cfg(unix)]
pub fn remove_peer(iface_name: &str, pubkey: &str) -> Result<()> {
    use wireguard_control::{DeviceUpdate, InterfaceName, Key};

    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    let key = Key::from_base64(pubkey).context("invalid pubkey")?;
    DeviceUpdate::new()
        .remove_peer_by_key(&key)
        .apply(&name, backend())
        .context("wg remove_peer")?;
    tracing::info!("wg: removed peer {} from {}", &pubkey[..8], iface_name);
    Ok(())
}

/// Read last-handshake timestamps from a live interface.
///
/// Returns a map of `base64_pubkey → unix_timestamp_seconds`.
#[cfg(unix)]
pub fn peer_handshakes(iface_name: &str) -> Result<HashMap<String, i64>> {
    use wireguard_control::{Device, InterfaceName};

    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    let device = Device::get(&name, backend()).context("wg get device")?;

    let mut map = HashMap::new();
    for peer in &device.peers {
        if let Some(hs) = peer.stats.last_handshake_time {
            let ts = hs
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            map.insert(peer.config.public_key.to_base64(), ts);
        }
    }
    Ok(map)
}

/// Read aggregate traffic statistics from a live interface.
#[cfg(unix)]
pub fn interface_stats(iface_name: &str) -> Result<InterfaceStats> {
    use wireguard_control::{Device, InterfaceName};

    let name: InterfaceName = iface_name.parse().context("invalid interface name")?;
    let device = Device::get(&name, backend()).context("wg get device")?;

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

// ── Unix helpers ──────────────────────────────────────────────────────────────

/// Select the appropriate [`wireguard_control::Backend`] for this platform.
///
/// * Linux   → `Backend::Kernel`  (WireGuard netlink API)
/// * macOS   → `Backend::Userspace` (wireguard-go UNIX socket)
#[cfg(unix)]
fn backend() -> wireguard_control::Backend {
    #[cfg(target_os = "linux")]
    return wireguard_control::Backend::Kernel;

    #[cfg(not(target_os = "linux"))]
    return wireguard_control::Backend::Userspace;
}

/// Build a [`PeerConfigBuilder`] from a DB [`Peer`] row.
#[cfg(unix)]
fn build_peer_config(peer: &Peer) -> Result<wireguard_control::PeerConfigBuilder> {
    use wireguard_control::{Key, PeerConfigBuilder};

    let pubkey = Key::from_base64(&peer.pubkey).context("invalid peer pubkey")?;
    let mut cfg = PeerConfigBuilder::new(&pubkey);

    if let Some(psk) = &peer.psk {
        let psk_key = Key::from_base64(psk).context("invalid psk")?;
        cfg = cfg.set_preshared_key(psk_key);
    }

    if let Some(ipv4) = &peer.ipv4
        && let Ok((addr, prefix)) = parse_cidr_v4(ipv4)
    {
        cfg = cfg.add_allowed_ip(std::net::IpAddr::V4(addr), prefix);
    }
    if let Some(ipv6) = &peer.ipv6
        && let Ok((addr, prefix)) = parse_cidr_v6(ipv6)
    {
        cfg = cfg.add_allowed_ip(std::net::IpAddr::V6(addr), prefix);
    }

    Ok(cfg)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Windows implementation — WireGuard UAPI text protocol over named pipe
// ═══════════════════════════════════════════════════════════════════════════════
//
// The WireGuard UAPI protocol is a simple line-based text format documented at
// https://www.wireguard.com/xplatform/.  On Windows the WireGuard service
// exposes it over the named pipe `\\.\pipe\WireGuard\<interface>`.
//
// Keys in the UAPI protocol are 64-character hex strings.  The DB stores them
// as Base64.  The `b64_to_hex` / `hex_to_b64` helpers convert between formats.

/// Generate a new WireGuard keypair on Windows using `x25519-dalek`.
///
/// Returns `(private_key_base64, public_key_base64)`.
#[cfg(windows)]
pub fn generate_keypair() -> Result<(String, String)> {
    use base64::Engine as _;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let private = StaticSecret::from(bytes);
    let public = PublicKey::from(&private);
    let engine = base64::engine::general_purpose::STANDARD;
    Ok((
        engine.encode(private.as_bytes()),
        engine.encode(public.as_bytes()),
    ))
}

/// Generate a 32-byte preshared key encoded as Base64.
#[cfg(windows)]
pub fn generate_psk() -> String {
    use base64::Engine as _;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Apply full interface configuration via the WireGuard Windows named pipe.
#[cfg(windows)]
pub fn configure(iface: &Interface, peers: &[Peer]) -> Result<()> {
    let mut msg = format!(
        "set=1\nprivate_key={}\nlisten_port={}\nreplace_peers=true\n",
        b64_to_hex(&iface.private_key)?,
        iface.listen_port,
    );
    for peer in peers {
        msg.push_str(&peer_uapi_block(peer)?);
    }
    // Terminate the set command with a blank line.
    msg.push('\n');
    uapi_set(&iface.name, &msg)?;
    tracing::info!("wg: configured {} with {} peers", iface.name, peers.len());
    Ok(())
}

/// Hot-add or update a single peer via the named pipe.
#[cfg(windows)]
pub fn add_peer(iface_name: &str, peer: &Peer) -> Result<()> {
    let mut msg = format!("set=1\n{}", peer_uapi_block(peer)?);
    msg.push('\n');
    uapi_set(iface_name, &msg)?;
    tracing::info!("wg: added peer {} to {}", &peer.pubkey[..8], iface_name);
    Ok(())
}

/// Remove a peer by public key via the named pipe.
#[cfg(windows)]
pub fn remove_peer(iface_name: &str, pubkey: &str) -> Result<()> {
    let msg = format!(
        "set=1\npublic_key={}\nremove=true\n\n",
        b64_to_hex(pubkey)?
    );
    uapi_set(iface_name, &msg)?;
    tracing::info!("wg: removed peer {} from {}", &pubkey[..8], iface_name);
    Ok(())
}

/// Read last-handshake timestamps from the named pipe.
///
/// Returns a map of `base64_pubkey → unix_timestamp_seconds`.
#[cfg(windows)]
pub fn peer_handshakes(iface_name: &str) -> Result<HashMap<String, i64>> {
    let response = uapi_get(iface_name)?;
    let mut map = HashMap::new();
    let mut current_key: Option<String> = None;
    let mut last_hs: i64 = 0;

    for line in response.lines() {
        if let Some(hex) = line.strip_prefix("public_key=") {
            // Flush the previous peer's handshake if we had one.
            if let Some(key) = current_key.take() {
                if last_hs != 0 {
                    map.insert(key, last_hs);
                }
            }
            current_key = Some(hex_to_b64(hex)?);
            last_hs = 0;
        } else if let Some(ts) = line.strip_prefix("last_handshake_time_sec=") {
            last_hs = ts.parse().unwrap_or(0);
        }
    }
    // Flush last peer.
    if let Some(key) = current_key {
        if last_hs != 0 {
            map.insert(key, last_hs);
        }
    }
    Ok(map)
}

/// Read aggregate traffic statistics from the named pipe.
#[cfg(windows)]
pub fn interface_stats(iface_name: &str) -> Result<InterfaceStats> {
    let response = uapi_get(iface_name)?;
    let mut peer_count = 0usize;
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut in_peer = false;
    let mut peer_rx = 0u64;
    let mut peer_tx = 0u64;

    for line in response.lines() {
        if line.starts_with("public_key=") {
            if in_peer {
                // Flush previous peer.
                rx_bytes += peer_rx;
                tx_bytes += peer_tx;
                peer_count += 1;
            }
            in_peer = true;
            peer_rx = 0;
            peer_tx = 0;
        } else if let Some(v) = line.strip_prefix("rx_bytes=") {
            peer_rx = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("tx_bytes=") {
            peer_tx = v.parse().unwrap_or(0);
        }
    }
    if in_peer {
        rx_bytes += peer_rx;
        tx_bytes += peer_tx;
        peer_count += 1;
    }
    Ok(InterfaceStats { peer_count, rx_bytes, tx_bytes })
}

// ── Windows helpers ───────────────────────────────────────────────────────────

/// Send a UAPI GET request to the named pipe and return the full response.
#[cfg(windows)]
fn uapi_get(iface_name: &str) -> Result<String> {
    use std::io::{Read, Write};

    let path = format!(r"\\.\pipe\WireGuard\{iface_name}");
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open WireGuard pipe for '{iface_name}'"))?;

    pipe.write_all(b"get=1\n\n").context("write UAPI get")?;
    let mut resp = String::new();
    pipe.read_to_string(&mut resp).context("read UAPI response")?;
    Ok(resp)
}

/// Send a UAPI SET request to the named pipe.
///
/// `payload` must be a complete, newline-terminated UAPI set block ending
/// with a blank line.
#[cfg(windows)]
fn uapi_set(iface_name: &str, payload: &str) -> Result<()> {
    use std::io::Write;

    let path = format!(r"\\.\pipe\WireGuard\{iface_name}");
    let mut pipe = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .with_context(|| format!("open WireGuard pipe for '{iface_name}'"))?;

    pipe.write_all(payload.as_bytes())
        .context("write UAPI set")?;
    Ok(())
}

/// Build the UAPI text lines for a single peer.
#[cfg(windows)]
fn peer_uapi_block(peer: &Peer) -> Result<String> {
    let mut s = format!("public_key={}\n", b64_to_hex(&peer.pubkey)?);

    if let Some(psk) = &peer.psk {
        s.push_str(&format!("preshared_key={}\n", b64_to_hex(psk)?));
    }

    if let Some(ipv4) = &peer.ipv4 {
        s.push_str(&format!("allowed_ip={ipv4}\n"));
    }
    if let Some(ipv6) = &peer.ipv6 {
        s.push_str(&format!("allowed_ip={ipv6}\n"));
    }
    Ok(s)
}

/// Convert a Base64-encoded 32-byte WireGuard key to its lowercase hex form.
#[cfg(windows)]
fn b64_to_hex(b64: &str) -> Result<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("base64 decode key")?;
    Ok(hex::encode(bytes))
}

/// Convert a lowercase hex 32-byte WireGuard key to its Base64 form.
#[cfg(windows)]
fn hex_to_b64(h: &str) -> Result<String> {
    use base64::Engine as _;
    let bytes = hex::decode(h).context("hex decode key")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Common helpers (all platforms)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse an IPv4 CIDR string into `(Ipv4Addr, prefix_len)`.
fn parse_cidr_v4(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = cidr.split_once('/').context("invalid IPv4 CIDR")?;
    Ok((ip.parse()?, prefix.parse()?))
}

/// Parse an IPv6 CIDR string into `(Ipv6Addr, prefix_len)`.
fn parse_cidr_v6(cidr: &str) -> Result<(std::net::Ipv6Addr, u8)> {
    let (ip, prefix) = cidr.split_once('/').context("invalid IPv6 CIDR")?;
    Ok((ip.parse()?, prefix.parse()?))
}
