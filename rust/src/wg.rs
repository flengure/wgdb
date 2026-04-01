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
//! | Windows  | wireguard-go subprocess + UAPI named pipe |
//!
//! # Key encoding
//!
//! Keys are stored in the database as **Base64**.  The WireGuard UAPI protocol
//! encodes keys as lowercase **hex**.  The Windows helpers convert between the
//! two representations.

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

    update.apply(&name, backend()).context("wg configure")?;
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

    Ok(InterfaceStats { peer_count: device.peers.len(), rx_bytes: rx, tx_bytes: tx })
}

// ── Unix helpers ──────────────────────────────────────────────────────────────

#[cfg(unix)]
fn backend() -> wireguard_control::Backend {
    #[cfg(target_os = "linux")]
    return wireguard_control::Backend::Kernel;

    #[cfg(not(target_os = "linux"))]
    return wireguard_control::Backend::Userspace;
}

#[cfg(unix)]
fn build_peer_config(peer: &Peer) -> Result<wireguard_control::PeerConfigBuilder> {
    use wireguard_control::{Key, PeerConfigBuilder};

    let pubkey = Key::from_base64(&peer.pubkey).context("invalid peer pubkey")?;
    let mut cfg = PeerConfigBuilder::new(&pubkey);

    if let Some(psk) = &peer.psk {
        cfg = cfg.set_preshared_key(Key::from_base64(psk).context("invalid psk")?);
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
// Windows implementation — wireguard-go subprocess + UAPI named pipe
// ═══════════════════════════════════════════════════════════════════════════════
//
// Mirrors the macOS approach: net::create_link spawns `wireguard-go.exe <name>`,
// which creates a Wintun TUN adapter and listens on the named pipe
//   \\.\pipe\WireGuard\<name>
// using the standard WireGuard UAPI text protocol (same protocol as the Unix
// socket on macOS/Linux userspace).
//
// Requirement: wireguard-go.exe (+ its bundled wintun.dll) must be on PATH.
// https://github.com/WireGuard/wireguard-go
//
// Keys: DB stores Base64; UAPI protocol uses lowercase hex.

/// Generate a new WireGuard keypair on Windows.
///
/// Returns `(private_key_base64, public_key_base64)`.
#[cfg(windows)]
pub fn generate_keypair() -> Result<(String, String)> {
    use base64::Engine as _;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let private = StaticSecret::from(bytes);
    let public  = PublicKey::from(&private);
    let enc = base64::engine::general_purpose::STANDARD;
    Ok((enc.encode(private.as_bytes()), enc.encode(public.as_bytes())))
}

/// Generate a 32-byte preshared key encoded as Base64.
#[cfg(windows)]
pub fn generate_psk() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Apply full interface configuration via wireguard-go's UAPI named pipe.
#[cfg(windows)]
pub fn configure(iface: &Interface, peers: &[Peer]) -> Result<()> {
    use base64::Engine as _;

    let private_bytes = base64::engine::general_purpose::STANDARD
        .decode(&iface.private_key)
        .context("decode private key")?;

    let mut cmd = format!(
        "set=1\nprivate_key={}\nlisten_port={}\nreplace_peers=true\n",
        hex::encode(&private_bytes),
        iface.listen_port,
    );
    for peer in peers {
        cmd.push_str(&build_peer_lines(peer)?);
    }
    cmd.push('\n'); // empty line terminates command

    let resp = uapi_request(&iface.name, &cmd)?;
    check_errno(&resp)?;
    tracing::info!("wg: configured {} with {} peers", iface.name, peers.len());
    Ok(())
}

/// Hot-add or update a single peer without disrupting existing sessions.
#[cfg(windows)]
pub fn add_peer(iface_name: &str, peer: &Peer) -> Result<()> {
    let mut cmd = String::from("set=1\n");
    cmd.push_str(&build_peer_lines(peer)?);
    cmd.push('\n');

    let resp = uapi_request(iface_name, &cmd)?;
    check_errno(&resp)?;
    tracing::info!("wg: added peer {} to {iface_name}", &peer.pubkey[..8]);
    Ok(())
}

/// Remove a peer from a live interface by its Base64-encoded public key.
#[cfg(windows)]
pub fn remove_peer(iface_name: &str, pubkey: &str) -> Result<()> {
    use base64::Engine as _;

    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey)
        .context("decode pubkey")?;
    let cmd = format!("set=1\npublic_key={}\nremove=true\n\n", hex::encode(&pub_bytes));

    let resp = uapi_request(iface_name, &cmd)?;
    check_errno(&resp)?;
    tracing::info!("wg: removed peer {} from {iface_name}", &pubkey[..8]);
    Ok(())
}

/// Read last-handshake timestamps via wireguard-go UAPI.
///
/// Returns a map of `base64_pubkey → unix_timestamp_seconds`.
#[cfg(windows)]
pub fn peer_handshakes(iface_name: &str) -> Result<HashMap<String, i64>> {
    use base64::Engine as _;

    let resp = uapi_request(iface_name, "get=1\n\n")?;
    let mut map = HashMap::new();
    let mut cur_pubkey: Option<String> = None;
    let mut cur_ts: i64 = 0;

    for line in resp.lines() {
        if let Some(hex_key) = line.strip_prefix("public_key=") {
            if let Some(pk) = cur_pubkey.take()
                && cur_ts > 0
            {
                map.insert(pk, cur_ts);
            }
            if let Ok(bytes) = hex::decode(hex_key) {
                cur_pubkey = Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
            }
            cur_ts = 0;
        } else if let Some(val) = line.strip_prefix("last_handshake_time_sec=") {
            cur_ts = val.parse().unwrap_or(0);
        }
    }
    if let Some(pk) = cur_pubkey
        && cur_ts > 0
    {
        map.insert(pk, cur_ts);
    }
    Ok(map)
}

/// Read aggregate traffic statistics via wireguard-go UAPI.
#[cfg(windows)]
pub fn interface_stats(iface_name: &str) -> Result<InterfaceStats> {
    let resp = uapi_request(iface_name, "get=1\n\n")?;
    let mut peer_count = 0usize;
    let mut rx_bytes   = 0u64;
    let mut tx_bytes   = 0u64;

    for line in resp.lines() {
        if line.starts_with("public_key=") {
            peer_count += 1;
        } else if let Some(v) = line.strip_prefix("rx_bytes=") {
            rx_bytes += v.parse::<u64>().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("tx_bytes=") {
            tx_bytes += v.parse::<u64>().unwrap_or(0);
        }
    }
    Ok(InterfaceStats { peer_count, rx_bytes, tx_bytes })
}

/// Validate and import a Base64-encoded private key on Windows.
#[cfg(windows)]
pub fn import_private_key(b64: &str) -> Result<(String, String)> {
    use base64::Engine as _;
    use x25519_dalek::{PublicKey, StaticSecret};

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("invalid base64 in private_key")?;
    anyhow::ensure!(bytes.len() == 32, "private_key must be 32 bytes");
    let arr: [u8; 32] = bytes.try_into().unwrap();
    let public = PublicKey::from(&StaticSecret::from(arr));
    Ok((
        b64.to_string(),
        base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
    ))
}

// ── Unix import_private_key ───────────────────────────────────────────────────

#[cfg(unix)]
pub fn import_private_key(b64: &str) -> Result<(String, String)> {
    use wireguard_control::Key;
    let key = Key::from_base64(b64).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((b64.to_string(), key.get_public().to_base64()))
}

// ── Windows UAPI helpers ──────────────────────────────────────────────────────

/// Open `\\.\pipe\WireGuard\<iface>`, write `request`, return the response.
///
/// Each call opens a fresh connection — wireguard-go accepts one command per
/// connection (like the Unix socket).
#[cfg(windows)]
fn uapi_request(iface_name: &str, request: &str) -> Result<String> {
    use std::io::{Read, Write};

    let path = format!(r"\\.\pipe\WireGuard\{}", iface_name);
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| {
            format!("open wireguard-go pipe for '{iface_name}' — is wireguard-go running?")
        })?;

    pipe.write_all(request.as_bytes()).context("write UAPI request")?;

    let mut resp = Vec::new();
    let mut buf  = [0u8; 4096];
    loop {
        let n = pipe.read(&mut buf).context("read UAPI response")?;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
        if resp.ends_with(b"\n\n") {
            break;
        }
    }
    String::from_utf8(resp).context("UAPI response UTF-8")
}

/// Assert the UAPI response contains `errno=0`.
#[cfg(windows)]
fn check_errno(response: &str) -> Result<()> {
    for line in response.lines() {
        if let Some(val) = line.strip_prefix("errno=") {
            let code: i32 = val.trim().parse().unwrap_or(-1);
            anyhow::ensure!(code == 0, "UAPI error: errno={code}");
            return Ok(());
        }
    }
    anyhow::bail!("UAPI response missing errno line:\n{response}")
}

/// Build the UAPI `set=1` lines for a single peer (no trailing empty line).
#[cfg(windows)]
fn build_peer_lines(peer: &Peer) -> Result<String> {
    use base64::Engine as _;

    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(&peer.pubkey)
        .context("decode peer pubkey")?;
    let mut s = format!("public_key={}\n", hex::encode(&pub_bytes));

    if let Some(psk) = &peer.psk {
        let psk_bytes = base64::engine::general_purpose::STANDARD
            .decode(psk)
            .context("decode psk")?;
        s.push_str(&format!("preshared_key={}\n", hex::encode(&psk_bytes)));
    }
    if let Some(ipv4) = &peer.ipv4 {
        s.push_str(&format!("allowed_ip={ipv4}\n"));
    }
    if let Some(ipv6) = &peer.ipv6 {
        s.push_str(&format!("allowed_ip={ipv6}\n"));
    }
    Ok(s)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Common helpers (all platforms)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse an IPv4 CIDR string into `(Ipv4Addr, prefix_len)`.
#[cfg(unix)]
fn parse_cidr_v4(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = cidr.split_once('/').context("invalid IPv4 CIDR")?;
    Ok((ip.parse()?, prefix.parse()?))
}

/// Parse an IPv6 CIDR string into `(Ipv6Addr, prefix_len)`.
#[cfg(unix)]
fn parse_cidr_v6(cidr: &str) -> Result<(std::net::Ipv6Addr, u8)> {
    let (ip, prefix) = cidr.split_once('/').context("invalid IPv6 CIDR")?;
    Ok((ip.parse()?, prefix.parse()?))
}
