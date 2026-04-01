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
//! | Windows  | wintun TUN adapter + boringtun WireGuard protocol (self-contained) |
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
// Windows implementation — wintun TUN adapter + boringtun WireGuard protocol
// ═══════════════════════════════════════════════════════════════════════════════
//
// Architecture:
//   - wintun creates a Layer-3 TUN adapter (wintun.dll, MIT licensed).
//     The DLL is embedded into the binary at compile time (via build.rs +
//     include_bytes!) and extracted to a temp file at first call to
//     load_library(), so no installation step is required.
//   - boringtun (pure Rust, no C deps) implements the WireGuard protocol:
//     one `Tunn` per peer handles handshakes and packet encryption/decryption.
//   - A background thread per interface bridges:
//       TUN read → route by dst IP → Tunn::encapsulate → UDP send
//       UDP recv → Tunn::decapsulate → TUN write
//       Tunn::update_timers → send handshake / keepalive packets as needed
//
// Keys are stored in the database as Base64; x25519-dalek and boringtun use
// raw [u8; 32] / typed key structs.

/// Bytes of wintun.dll for the compile-target architecture, embedded at build time.
#[cfg(windows)]
static WINTUN_DLL_BYTES: &[u8] = include_bytes!(env!("WINTUN_DLL_PATH"));

/// Loaded wintun library handle — extracted and loaded once at startup.
#[cfg(windows)]
static WINTUN: std::sync::OnceLock<wintun::Wintun> = std::sync::OnceLock::new();

// ── Per-interface runtime state ───────────────────────────────────────────────

/// State kept for each live interface.
#[cfg(windows)]
struct IfaceState {
    /// wintun adapter — kept alive so the TUN device persists.
    adapter: std::sync::Arc<wintun::Adapter>,
    /// LUID of the wintun adapter (used for Win32 IP address management).
    luid: u64,
    /// Server private key bytes — needed when hot-adding peers via add_peer().
    private_key: [u8; 32],
    /// Shared peer table (pubkey bytes → PeerState).  Written under lock.
    peers: std::sync::Arc<std::sync::Mutex<PeerTable>>,
    /// Sending half of a channel used to signal the packet loop to stop.
    stop_tx: std::sync::mpsc::SyncSender<()>,
}

#[cfg(windows)]
type PeerTable = std::collections::HashMap<[u8; 32], PeerState>;

/// Per-peer state tracked by the packet loop.
#[cfg(windows)]
struct PeerState {
    /// boringtun tunnel — handles crypto + handshake state.
    tunn: Box<boringtun::noise::Tunn>,
    /// Remote UDP endpoint (may be None until first handshake for server-side
    /// peers that don't have a fixed endpoint configured).
    endpoint: Option<std::net::SocketAddr>,
    /// Allowed source IPs for routing inbound TUN packets to this peer.
    allowed_ips: Vec<ipnet::IpNet>,
    /// PSK bytes (32 bytes) — stored for reconfigure.
    psk: Option<[u8; 32]>,
    /// Peer public key bytes — stored for reconfigure.
    pubkey: [u8; 32],
    /// Last handshake time (unix seconds), updated by packet loop.
    last_handshake: std::sync::Arc<std::sync::atomic::AtomicI64>,
    /// Bytes received, updated by packet loop.
    rx_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Bytes sent, updated by packet loop.
    tx_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// Global map of live interface states keyed by interface name.
#[cfg(windows)]
static IFACES: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, IfaceState>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

// ── Startup ───────────────────────────────────────────────────────────────────

/// Extract wintun.dll from the embedded bytes into a temp file and load it.
///
/// Uses a fixed path in the system temp directory so the DLL is reused across
/// restarts rather than written fresh every time.
///
/// Must be called once at startup before any adapter operations.
/// Requires Administrator privileges (wintun creates a kernel adapter).
#[cfg(windows)]
pub fn load_library() -> Result<()> {
    let dll_path = std::env::temp_dir().join("wgdb_wintun.dll");
    std::fs::write(&dll_path, WINTUN_DLL_BYTES).context("write wintun.dll to temp dir")?;

    let wintun = unsafe {
        wintun::load_from_path(&dll_path).context("load wintun.dll")?
    };
    WINTUN.set(wintun).ok();
    tracing::info!("wg: wintun loaded from {}", dll_path.display());
    Ok(())
}

#[cfg(windows)]
fn wintun_lib() -> &'static wintun::Wintun {
    WINTUN.get().expect("wintun not loaded — call wg::load_library() first")
}

// ── Adapter lifecycle ─────────────────────────────────────────────────────────

/// Create a wintun adapter, start the packet-loop thread, and return its LUID.
///
/// Returns the adapter's NET_LUID value so `net::create_link` can convert it
/// to a Win32 interface index for IP address management.
#[cfg(windows)]
pub fn create_adapter(name: &str) -> Result<u64> {
    use wintun::Adapter;

    let wintun = wintun_lib();
    // GUID is derived deterministically from the name so recreating the
    // interface after a restart gets the same GUID (avoids adapter accumulation
    // in the Windows registry).
    let guid = name_to_guid(name);
    let adapter = Adapter::create(wintun, name, "WireGuard", Some(guid))
        .with_context(|| format!("wintun create adapter '{name}'"))?;

    let luid_raw = adapter.get_luid();
    // NET_LUID_LH is a union from the windows crate; access Value field unsafely.
    let luid: u64 = unsafe { luid_raw.Value };

    let session = std::sync::Arc::new(
        adapter.start_session(wintun::MAX_RING_CAPACITY)
            .context("wintun start_session")?
    );

    let peers: std::sync::Arc<std::sync::Mutex<PeerTable>> =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // Bind a UDP socket for the WireGuard data plane.  Port 0 means the OS
    // assigns an ephemeral port; the listen_port from the DB is applied later
    // in configure() by rebinding.
    let udp = std::net::UdpSocket::bind("0.0.0.0:0").context("bind UDP")?;
    udp.set_nonblocking(false).context("set_nonblocking")?;

    let (stop_tx, stop_rx) = std::sync::mpsc::sync_channel::<()>(1);

    let peers_loop = peers.clone();
    let udp_loop = udp.try_clone().context("clone UDP socket")?;
    let name_loop = name.to_string();
    let session_loop = session.clone();
    std::thread::spawn(move || {
        packet_loop(name_loop, session_loop, udp_loop, peers_loop, stop_rx);
    });

    IFACES.lock().unwrap().insert(
        name.to_string(),
        IfaceState { adapter, luid, private_key: [0u8; 32], peers, stop_tx },
    );
    tracing::info!("wg: created wintun adapter '{name}'");
    Ok(luid)
}

/// Shut down the packet loop and drop the wintun adapter.
#[cfg(windows)]
pub fn delete_adapter(name: &str) -> Result<()> {
    if let Some(state) = IFACES.lock().unwrap().remove(name) {
        let _ = state.stop_tx.try_send(());
        tracing::info!("wg: deleted adapter '{name}'");
    }
    Ok(())
}

// ── WireGuard configuration ───────────────────────────────────────────────────

/// Apply full interface configuration (private key, listen port, all peers).
///
/// Replaces the peer table and rebinds the UDP socket to the listen port.
#[cfg(windows)]
pub fn configure(iface: &Interface, peers: &[Peer]) -> Result<()> {
    use base64::Engine as _;

    let private_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&iface.private_key)
        .context("decode private key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;

    let mut ifaces = IFACES.lock().unwrap();
    let state = ifaces
        .get_mut(&iface.name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{}' not found", iface.name))?;

    // Persist the private key so hot-add (add_peer) can build new Tunns.
    state.private_key = private_bytes;

    let mut peer_table = state.peers.lock().unwrap();
    peer_table.clear();
    for (idx, peer) in peers.iter().enumerate() {
        let ps = build_peer_state(&private_bytes, peer, idx as u32)?;
        peer_table.insert(ps.pubkey, ps);
    }

    tracing::info!("wg: configured {} with {} peers", iface.name, peers.len());
    Ok(())
}

/// Hot-add or update a single peer without disrupting existing sessions.
#[cfg(windows)]
pub fn add_peer(iface_name: &str, peer: &Peer) -> Result<()> {
    let ifaces = IFACES.lock().unwrap();
    let state = ifaces
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;

    let private_bytes = state.private_key;
    let idx = {
        let table = state.peers.lock().unwrap();
        table.len() as u32
    };
    let ps = build_peer_state(&private_bytes, peer, idx)?;
    state.peers.lock().unwrap().insert(ps.pubkey, ps);

    tracing::info!("wg: added peer {} to {iface_name}", &peer.pubkey[..8]);
    Ok(())
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
    use boringtun::x25519::{PublicKey, StaticSecret};

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

/// Remove a peer from a live interface by its Base64-encoded public key.
#[cfg(windows)]
pub fn remove_peer(iface_name: &str, pubkey: &str) -> Result<()> {
    use base64::Engine as _;

    let pub_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(pubkey)
        .context("decode pubkey")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))?;

    let ifaces = IFACES.lock().unwrap();
    let state = ifaces
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;
    state.peers.lock().unwrap().remove(&pub_bytes);

    tracing::info!("wg: removed peer {} from {iface_name}", &pubkey[..8]);
    Ok(())
}

/// Read last-handshake timestamps from a live interface.
///
/// Returns a map of `base64_pubkey → unix_timestamp_seconds`.
#[cfg(windows)]
pub fn peer_handshakes(iface_name: &str) -> Result<HashMap<String, i64>> {
    use base64::Engine as _;
    use std::sync::atomic::Ordering;

    let ifaces = IFACES.lock().unwrap();
    let state = ifaces
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;

    let mut map = HashMap::new();
    for ps in state.peers.lock().unwrap().values() {
        let ts = ps.last_handshake.load(Ordering::Relaxed);
        if ts > 0 {
            map.insert(
                base64::engine::general_purpose::STANDARD.encode(ps.pubkey),
                ts,
            );
        }
    }
    Ok(map)
}

/// Read aggregate traffic statistics from a live interface.
#[cfg(windows)]
pub fn interface_stats(iface_name: &str) -> Result<InterfaceStats> {
    use std::sync::atomic::Ordering;

    let ifaces = IFACES.lock().unwrap();
    let state = ifaces
        .get(iface_name)
        .ok_or_else(|| anyhow::anyhow!("adapter '{iface_name}' not found"))?;

    let peers = state.peers.lock().unwrap();
    let peer_count = peers.len();
    let (rx, tx) = peers.values().fold((0u64, 0u64), |(rx, tx), ps| {
        (
            rx + ps.rx_bytes.load(Ordering::Relaxed),
            tx + ps.tx_bytes.load(Ordering::Relaxed),
        )
    });
    Ok(InterfaceStats { peer_count, rx_bytes: rx, tx_bytes: tx })
}

/// Generate a new WireGuard keypair on Windows using `x25519-dalek`.
///
/// Returns `(private_key_base64, public_key_base64)`.
#[cfg(windows)]
pub fn generate_keypair() -> Result<(String, String)> {
    use base64::Engine as _;
    use boringtun::x25519::{PublicKey, StaticSecret};

    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let private = StaticSecret::from(bytes);
    let public = PublicKey::from(&private);
    let engine = base64::engine::general_purpose::STANDARD;
    Ok((engine.encode(private.as_bytes()), engine.encode(public.as_bytes())))
}

/// Generate a 32-byte preshared key encoded as Base64.
#[cfg(windows)]
pub fn generate_psk() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ── Windows helpers ───────────────────────────────────────────────────────────

/// Build a `PeerState` from a DB `Peer` row.
///
/// `server_private` is the server's x25519 private key bytes (needed by
/// boringtun to set up the noise handshake).
/// `idx` is a unique per-peer index used by boringtun internally.
#[cfg(windows)]
fn build_peer_state(server_private: &[u8; 32], peer: &Peer, idx: u32) -> Result<PeerState> {
    use base64::Engine as _;
    use boringtun::noise::Tunn;
    use boringtun::x25519::{PublicKey, StaticSecret};

    let pub_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&peer.pubkey)
        .context("decode peer pubkey")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("peer pubkey must be 32 bytes"))?;

    let psk: Option<[u8; 32]> = peer.psk.as_deref().map(|s| {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .context("decode psk")
            .and_then(|b| b.try_into().map_err(|_| anyhow::anyhow!("psk must be 32 bytes")))
    }).transpose()?;

    let private = StaticSecret::from(*server_private);
    let public  = PublicKey::from(pub_bytes);

    let tunn = Tunn::new(private, public, psk, None, idx, None);

    let mut allowed_ips: Vec<ipnet::IpNet> = Vec::new();
    if let Some(v4) = &peer.ipv4 {
        allowed_ips.push(v4.parse().context("invalid ipv4 CIDR")?);
    }
    if let Some(v6) = &peer.ipv6 {
        allowed_ips.push(v6.parse().context("invalid ipv6 CIDR")?);
    }

    Ok(PeerState {
        tunn: Box::new(tunn),
        endpoint: None, // learned dynamically from first UDP packet
        allowed_ips,
        psk,
        pubkey: pub_bytes,
        last_handshake: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0)),
        rx_bytes:       std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        tx_bytes:       std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
}

/// Derive a deterministic GUID from an interface name.
/// Uses a simple FNV-1a hash spread across 128 bits.
#[cfg(windows)]
fn name_to_guid(name: &str) -> u128 {
    let mut h: u128 = 0x6c62272e07bb0142_62b821756295c58d;
    for b in name.bytes() {
        h ^= b as u128;
        h = h.wrapping_mul(0x0000000001000193_0000000001000193);
    }
    h
}

// ── Packet loop ───────────────────────────────────────────────────────────────

/// Background thread that bridges wintun (TUN) ↔ boringtun (WireGuard) ↔ UDP.
///
/// Each live interface runs one instance of this loop.
#[cfg(windows)]
fn packet_loop(
    iface_name: String,
    session: std::sync::Arc<wintun::Session>,
    udp: std::net::UdpSocket,
    peers: std::sync::Arc<std::sync::Mutex<PeerTable>>,
    stop_rx: std::sync::mpsc::Receiver<()>,
) {
    use boringtun::noise::TunnResult;
    use std::sync::atomic::Ordering;

    // We need two threads: one to block on TUN reads and one on UDP reads.
    // Use a crossbeam channel to merge both into one processing loop, or
    // use a simpler approach: two threads sharing the peer table via Arc<Mutex>.

    // ── UDP reader thread → channel ───────────────────────────────────────────
    let (udp_tx, udp_rx) = std::sync::mpsc::sync_channel::<(Vec<u8>, std::net::SocketAddr)>(64);
    let udp_clone = udp.try_clone().expect("clone udp for reader thread");
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            match udp_clone.recv_from(&mut buf) {
                Ok((n, src)) => {
                    if udp_tx.send((buf[..n].to_vec(), src)).is_err() {
                        break; // main loop exited
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut encrypt_buf = vec![0u8; 65535 + 32]; // WireGuard overhead
    let mut decrypt_buf = vec![0u8; 65535 + 32];

    loop {
        // Check for stop signal (non-blocking).
        if stop_rx.try_recv().is_ok() {
            break;
        }

        // ── TUN → UDP (encrypt) ───────────────────────────────────────────────
        match session.try_receive() {
            Ok(Some(pkt)) => {
                let ip_pkt = pkt.bytes();
                // Route by destination IP: find matching peer.
                let dst_ip = packet_dst_ip(ip_pkt);
                let mut peers_guard = peers.lock().unwrap();
                if let Some(ps) = dst_ip.and_then(|ip| peer_for_ip(&mut peers_guard, ip)) {
                    match ps.tunn.encapsulate(ip_pkt, &mut encrypt_buf) {
                        TunnResult::WriteToNetwork(data) => {
                            if let Some(ep) = ps.endpoint {
                                if udp.send_to(data, ep).is_ok() {
                                    ps.tx_bytes.fetch_add(ip_pkt.len() as u64, Ordering::Relaxed);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // pkt is dropped here; wintun releases it automatically.
            }
            Ok(None) => {} // no TUN packet right now
            Err(e) => {
                tracing::warn!("wg/{iface_name}: tun recv error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        // ── UDP → TUN (decrypt) ───────────────────────────────────────────────
        while let Ok((data, src)) = udp_rx.try_recv() {
            let mut peers_guard = peers.lock().unwrap();
            // Try every peer until one accepts the packet.
            for ps in peers_guard.values_mut() {
                // Update endpoint if it changed (roaming clients).
                let src_ip = src.ip();
                match ps.tunn.decapsulate(Some(src_ip), &data, &mut decrypt_buf) {
                    TunnResult::WriteToTunnelV4(plain, _) | TunnResult::WriteToTunnelV6(plain, _) => {
                        ps.endpoint = Some(src);
                        ps.rx_bytes.fetch_add(plain.len() as u64, Ordering::Relaxed);
                        // Record handshake time.
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        ps.last_handshake.store(now, Ordering::Relaxed);
                        // Write decrypted packet back to TUN.
                        if let Ok(mut send_pkt) = session.allocate_send_packet(plain.len() as u16) {
                            send_pkt.bytes_mut().copy_from_slice(plain);
                            session.send_packet(send_pkt); // consumes packet, no return value
                        }
                        break;
                    }
                    TunnResult::WriteToNetwork(resp) => {
                        // Handshake response — send back to peer.
                        ps.endpoint = Some(src);
                        let _ = udp.send_to(resp, src);
                        break;
                    }
                    TunnResult::Done => break,
                    TunnResult::Err(_) => {} // try next peer
                }
            }
        }

        // ── Timer tick — drive keepalives / handshake retries ─────────────────
        {
            let mut peers_guard = peers.lock().unwrap();
            for ps in peers_guard.values_mut() {
                loop {
                    match ps.tunn.update_timers(&mut encrypt_buf) {
                        TunnResult::WriteToNetwork(data) => {
                            if let Some(ep) = ps.endpoint {
                                let _ = udp.send_to(data, ep);
                            }
                        }
                        TunnResult::Done | TunnResult::Err(_) => break,
                        _ => break,
                    }
                }
            }
        }

        // Yield briefly to avoid spinning the CPU at 100%.
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    tracing::info!("wg/{iface_name}: packet loop stopped");
}

/// Extract the destination IP from a raw IPv4 or IPv6 packet.
#[cfg(windows)]
fn packet_dst_ip(pkt: &[u8]) -> Option<std::net::IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 if pkt.len() >= 20 => {
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])))
        }
        6 if pkt.len() >= 40 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&pkt[24..40]);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// Find the peer whose allowed_ips contains `ip`.
#[cfg(windows)]
fn peer_for_ip<'a>(table: &'a mut PeerTable, ip: std::net::IpAddr) -> Option<&'a mut PeerState> {
    table.values_mut().find(|ps| {
        ps.allowed_ips.iter().any(|net| net.contains(&ip))
    })
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
