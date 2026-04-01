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
//! | Windows  | [`wireguard-nt`] kernel driver (creates Wintun adapters directly) |
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
// Windows implementation — wireguard-nt kernel driver
// ═══════════════════════════════════════════════════════════════════════════════
//
// wireguard-nt is the official WireGuard NT kernel driver for Windows.
// It creates and manages Wintun adapters directly without requiring the
// WireGuard Windows service or any .conf files.
//
// The library handle and live adapter handles are kept in module-level globals
// so that wg functions can access them by interface name without needing an
// explicit handle parameter (keeping the call-site API identical to Unix).
//
// Keys are stored in the database as Base64; wireguard-nt uses raw `[u8; 32]`.

/// wireguard.dll library handle — loaded once at startup.
#[cfg(windows)]
static WIREGUARD: std::sync::OnceLock<wireguard_nt::Wireguard> = std::sync::OnceLock::new();

/// Live adapter handles keyed by interface name.  Dropping an entry closes the
/// kernel handle and tears down the WireGuard interface.
#[cfg(windows)]
static ADAPTERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, wireguard_nt::Adapter>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Load wireguard.dll from the WireGuard for Windows installation directory.
/// Must be called once at startup (before any adapter operations) and requires
/// Administrator privileges.
#[cfg(windows)]
pub fn load_library() -> Result<()> {
    let wg = unsafe {
        wireguard_nt::load_from_path(r"C:\Program Files\WireGuard\wireguard.dll")
            .or_else(|_| wireguard_nt::load_from_path("wireguard.dll"))
            .context("load wireguard.dll — ensure WireGuard for Windows is installed and wgdb is running as Administrator")?
    };
    WIREGUARD.set(wg).ok(); // ignore "already initialised"
    Ok(())
}

#[cfg(windows)]
fn wg_lib() -> &'static wireguard_nt::Wireguard {
    WIREGUARD.get().expect("wireguard.dll not loaded — call wg::load_library() first")
}

/// Create (or reopen) a WireGuard adapter and bring it up.
///
/// Returns the adapter's LUID so `net::create_link` can convert it to a
/// Win32 interface index for IP address management.
#[cfg(windows)]
pub fn create_adapter(name: &str) -> Result<u64> {
    let adapter = wireguard_nt::Adapter::create(wg_lib(), "WireGuard", name, None)
        .or_else(|_| wireguard_nt::Adapter::open(wg_lib(), name))
        .with_context(|| format!("create wireguard-nt adapter '{name}'"))?;
    adapter.up().context("adapter up")?;
    let luid = adapter.get_luid();
    ADAPTERS.lock().unwrap().insert(name.to_string(), adapter);
    tracing::info!("wg: created adapter '{name}'");
    Ok(luid)
}

/// Drop the adapter handle for `name`, tearing down the WireGuard interface.
#[cfg(windows)]
pub fn delete_adapter(name: &str) -> Result<()> {
    let mut adapters = ADAPTERS.lock().unwrap();
    if let Some(adapter) = adapters.remove(name) {
        let _ = adapter.down();
        tracing::info!("wg: deleted adapter '{name}'");
    }
    Ok(())
}

/// Generate a new WireGuard keypair on Windows using `x25519-dalek`.
///
/// Returns `(private_key_base64, public_key_base64)`.
#[cfg(windows)]
pub fn generate_keypair() -> Result<(String, String)> {
    use base64::Engine as _;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
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

    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Apply full interface configuration (private key, listen port, all peers).
#[cfg(windows)]
pub fn configure(iface: &Interface, peers: &[Peer]) -> Result<()> {
    use base64::Engine as _;

    let adapters = ADAPTERS.lock().unwrap();
    let adapter = adapters
        .get(&iface.name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{}' not found — was the interface created?", iface.name))?;

    let private_key: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&iface.private_key)
        .context("decode private key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;

    let wg_peers = peers.iter().map(db_peer_to_set_peer).collect::<Result<Vec<_>>>()?;

    adapter
        .set_config(&wireguard_nt::SetInterface {
            private_key: Some(private_key),
            public_key: None,
            listen_port: Some(iface.listen_port as u16),
            peers: wg_peers,
        })
        .context("wireguard-nt set_config")?;

    tracing::info!("wg: configured {} with {} peers", iface.name, peers.len());
    Ok(())
}

/// Hot-add or update a single peer without disrupting existing sessions.
///
/// Reads the current peer list, appends the new peer, and writes back the
/// full configuration (wireguard-nt does not support incremental updates).
#[cfg(windows)]
pub fn add_peer(iface_name: &str, peer: &Peer) -> Result<()> {
    let adapters = ADAPTERS.lock().unwrap();
    let adapter = adapters
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;

    let current = adapter.get_config();
    let mut set_peers: Vec<wireguard_nt::SetPeer> =
        current.peers.iter().map(wg_peer_to_set_peer).collect();
    set_peers.push(db_peer_to_set_peer(peer)?);

    adapter
        .set_config(&wireguard_nt::SetInterface {
            private_key: Some(current.private_key),
            public_key: None,
            listen_port: Some(current.listen_port),
            peers: set_peers,
        })
        .context("wireguard-nt add_peer")?;

    tracing::info!("wg: added peer {} to {}", &peer.pubkey[..8], iface_name);
    Ok(())
}

/// Remove a peer from a live interface by its Base64-encoded public key.
#[cfg(windows)]
pub fn remove_peer(iface_name: &str, pubkey: &str) -> Result<()> {
    use base64::Engine as _;

    let pub_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(pubkey)
        .context("decode pubkey")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))?;

    let adapters = ADAPTERS.lock().unwrap();
    let adapter = adapters
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;

    let current = adapter.get_config();
    let set_peers: Vec<wireguard_nt::SetPeer> = current
        .peers
        .iter()
        .filter(|p| p.public_key != pub_bytes)
        .map(wg_peer_to_set_peer)
        .collect();

    adapter
        .set_config(&wireguard_nt::SetInterface {
            private_key: Some(current.private_key),
            public_key: None,
            listen_port: Some(current.listen_port),
            peers: set_peers,
        })
        .context("wireguard-nt remove_peer")?;

    tracing::info!("wg: removed peer {} from {}", &pubkey[..8], iface_name);
    Ok(())
}

/// Read last-handshake timestamps from a live interface.
///
/// Returns a map of `base64_pubkey → unix_timestamp_seconds`.
#[cfg(windows)]
pub fn peer_handshakes(iface_name: &str) -> Result<HashMap<String, i64>> {
    use base64::Engine as _;

    let adapters = ADAPTERS.lock().unwrap();
    let adapter = adapters
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;

    let config = adapter.get_config();
    let mut map = HashMap::new();
    for peer in &config.peers {
        if let Some(hs) = peer.last_handshake {
            let ts = hs
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            map.insert(
                base64::engine::general_purpose::STANDARD.encode(peer.public_key),
                ts,
            );
        }
    }
    Ok(map)
}

/// Read aggregate traffic statistics from a live interface.
#[cfg(windows)]
pub fn interface_stats(iface_name: &str) -> Result<InterfaceStats> {
    let adapters = ADAPTERS.lock().unwrap();
    let adapter = adapters
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;

    let config = adapter.get_config();
    let (rx, tx) = config
        .peers
        .iter()
        .fold((0u64, 0u64), |(rx, tx), p| (rx + p.rx_bytes, tx + p.tx_bytes));

    Ok(InterfaceStats { peer_count: config.peers.len(), rx_bytes: rx, tx_bytes: tx })
}

/// Validate and import a Base64-encoded private key supplied by the caller.
///
/// Returns `(private_key_base64, public_key_base64)` on success.
#[cfg(unix)]
pub fn import_private_key(b64: &str) -> Result<(String, String)> {
    use wireguard_control::Key;
    let key = Key::from_base64(b64).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((b64.to_string(), key.get_public().to_base64()))
}

/// Validate and import a Base64-encoded private key on Windows.
///
/// Returns `(private_key_base64, public_key_base64)` on success.
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

// ── Windows helpers ───────────────────────────────────────────────────────────

/// Convert a DB [`Peer`] to a [`wireguard_nt::SetPeer`].
///
/// Uses `0.0.0.0:0` as the endpoint for server-side peers that don't have one
/// configured — WireGuard learns the client's real endpoint dynamically on the
/// first handshake.
#[cfg(windows)]
fn db_peer_to_set_peer(peer: &Peer) -> Result<wireguard_nt::SetPeer> {
    use base64::Engine as _;

    let public_key: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&peer.pubkey)
        .context("decode peer pubkey")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))?;

    let preshared_key = peer.psk.as_deref().map(|psk| {
        base64::engine::general_purpose::STANDARD
            .decode(psk)
            .context("decode psk")
            .and_then(|b| {
                b.try_into()
                    .map_err(|_| anyhow::anyhow!("psk must be 32 bytes"))
            })
    }).transpose()?;

    let mut allowed_ips: Vec<ipnet::IpNet> = Vec::new();
    if let Some(v4) = &peer.ipv4 {
        allowed_ips.push(v4.parse().context("invalid ipv4 CIDR")?);
    }
    if let Some(v6) = &peer.ipv6 {
        allowed_ips.push(v6.parse().context("invalid ipv6 CIDR")?);
    }

    Ok(wireguard_nt::SetPeer {
        public_key: Some(public_key),
        preshared_key,
        keep_alive: None,
        endpoint: "0.0.0.0:0".parse().unwrap(),
        allowed_ips,
    })
}

/// Round-trip a [`wireguard_nt::WireguardPeer`] (from `get_config`) back into
/// a [`wireguard_nt::SetPeer`] so the full peer list can be rebuilt for
/// `set_config` when adding or removing a single peer.
#[cfg(windows)]
fn wg_peer_to_set_peer(peer: &wireguard_nt::WireguardPeer) -> wireguard_nt::SetPeer {
    wireguard_nt::SetPeer {
        public_key: Some(peer.public_key),
        preshared_key: if peer.preshared_key == [0u8; 32] {
            None
        } else {
            Some(peer.preshared_key)
        },
        keep_alive: if peer.persistent_keepalive == 0 {
            None
        } else {
            Some(peer.persistent_keepalive)
        },
        endpoint: peer.endpoint,
        allowed_ips: peer.allowed_ips.clone(),
    }
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
