//! Network interface management — platform-specific implementations.
//!
//! Every public function shares the same async signature across platforms
//! so that [`crate::api`] and [`crate::main`] remain platform-agnostic.
//!
//! # Platforms
//!
//! | Platform | Backend |
//! |----------|---------|
//! | Linux    | rtnetlink (kernel netlink socket) |
//! | macOS    | BSD `ioctl` + spawned `wireguard-go` process |
//! | Windows  | Win32 IP Helper API |
//!
//! # Handle
//!
//! Each platform exposes a `Handle` type:
//!
//! * **Linux** — re-exported [`rtnetlink::Handle`]; holds a netlink connection.
//! * **macOS** — `Arc<Mutex<HashMap<name → pid>>>` tracking live wireguard-go
//!   child processes so they can be terminated on [`delete_link`].
//! * **Windows** — a unit struct; Win32 calls are stateless.

use anyhow::{Context, Result};
use std::net::IpAddr;

// ── Platform Handle type ──────────────────────────────────────────────────────

/// Linux: re-export rtnetlink's connection handle directly.
#[cfg(target_os = "linux")]
pub use rtnetlink::Handle;

/// macOS: tracks wireguard-go child PIDs so they can be killed on
/// [`delete_link`].  Cheap to clone (reference-counted).
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub struct Handle(
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
);

#[cfg(target_os = "macos")]
impl Handle {
    /// Create a fresh, empty handle.
    #[must_use]
    pub fn new() -> Self {
        Handle(std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )))
    }
}

#[cfg(target_os = "macos")]
impl Default for Handle {
    fn default() -> Self {
        Self::new()
    }
}

/// Windows: stateless — all Win32 calls open and close handles internally.
#[cfg(windows)]
#[derive(Clone)]
pub struct Handle;

#[cfg(windows)]
impl Handle {
    /// Create a new handle (no-op on Windows).
    #[must_use]
    pub fn new() -> Self {
        Handle
    }
}

#[cfg(windows)]
impl Default for Handle {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Linux implementation
// ═══════════════════════════════════════════════════════════════════════════════

/// Create a WireGuard kernel interface. Returns the link index.
/// Idempotent — if the interface already exists its index is returned.
#[cfg(target_os = "linux")]
pub async fn create_link(handle: &Handle, name: &str) -> Result<u32> {
    use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo, LinkMessage};

    if let Some(idx) = link_index(handle, name).await? {
        tracing::debug!("net: {name} already exists (idx {idx})");
        return Ok(idx);
    }

    let mut msg = LinkMessage::default();
    msg.attributes
        .push(LinkAttribute::IfName(name.to_string()));
    msg.attributes.push(LinkAttribute::LinkInfo(vec![
        LinkInfo::Kind(InfoKind::Other("wireguard".to_string())),
    ]));

    handle
        .link()
        .add(msg)
        .execute()
        .await
        .context("ip link add wireguard")?;

    link_index(handle, name)
        .await?
        .context("link not found after creation")
}

/// Delete a WireGuard interface by name.
/// No-op if the interface does not exist.
#[cfg(target_os = "linux")]
pub async fn delete_link(handle: &Handle, name: &str) -> Result<()> {
    let idx = match link_index(handle, name).await? {
        Some(i) => i,
        None => return Ok(()),
    };
    handle
        .link()
        .del(idx)
        .execute()
        .await
        .context("ip link del")?;
    tracing::info!("net: deleted {name}");
    Ok(())
}

/// Bring a link up (`ip link set <index> up`).
#[cfg(target_os = "linux")]
pub async fn link_up(handle: &Handle, index: u32) -> Result<()> {
    use netlink_packet_route::link::{LinkFlags, LinkMessage};

    let mut msg = LinkMessage::default();
    msg.header.index = index;
    msg.header.flags = LinkFlags::Up;
    msg.header.change_mask = LinkFlags::Up;
    handle
        .link()
        .set(msg)
        .execute()
        .await
        .context("ip link set up")
}

/// Set the MTU on a link.
#[cfg(target_os = "linux")]
pub async fn set_mtu(handle: &Handle, index: u32, mtu: u32) -> Result<()> {
    use netlink_packet_route::link::{LinkAttribute, LinkMessage};

    let mut msg = LinkMessage::default();
    msg.header.index = index;
    msg.attributes.push(LinkAttribute::Mtu(mtu));
    handle
        .link()
        .set(msg)
        .execute()
        .await
        .context("ip link set mtu")
}

/// Add an IP address (CIDR notation) to an interface.
/// Idempotent — `EEXIST` is silently ignored.
#[cfg(target_os = "linux")]
pub async fn add_address(handle: &Handle, index: u32, cidr: &str) -> Result<()> {
    let (addr, prefix) = parse_cidr(cidr)?;
    match handle.address().add(index, addr, prefix).execute().await {
        Ok(_) => {
            tracing::debug!("net: added {cidr} to index {index}");
            Ok(())
        }
        Err(rtnetlink::Error::NetlinkError(ref e))
            if e.code.map(|c| c.get() == -17).unwrap_or(false) =>
        {
            Ok(()) // EEXIST — already assigned
        }
        Err(e) => Err(e).context(format!("ip addr add {cidr}")),
    }
}

/// Remove all IP addresses from an interface.
#[cfg(target_os = "linux")]
pub async fn flush_addresses(handle: &Handle, index: u32) -> Result<()> {
    use futures::TryStreamExt;

    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    while let Some(msg) = addrs.try_next().await? {
        handle
            .address()
            .del(msg)
            .execute()
            .await
            .context("ip addr del")?;
    }
    Ok(())
}

/// Look up the interface index for a given name.
/// Returns `None` if the interface does not exist.
#[cfg(target_os = "linux")]
pub async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
    use futures::TryStreamExt;

    let mut stream = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    match stream.try_next().await {
        Ok(Some(msg)) => Ok(Some(msg.header.index)),
        Ok(None) => Ok(None),
        Err(rtnetlink::Error::NetlinkError(ref e))
            if e.code.map(|c| c.get() == -19).unwrap_or(false) =>
        {
            Ok(None) // ENODEV
        }
        Err(e) => Err(e).context("ip link get"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// macOS implementation — BSD ioctl + wireguard-go
// ═══════════════════════════════════════════════════════════════════════════════

/// Spawn `wireguard-go <name>`, wait up to 5 s for the interface to appear,
/// then return its interface index.
///
/// `wireguard-go` must be on `PATH` (e.g. `brew install wireguard-go`).
/// Idempotent — if the interface already exists the existing index is returned.
#[cfg(target_os = "macos")]
pub async fn create_link(handle: &Handle, name: &str) -> Result<u32> {
    if let Some(idx) = link_index(handle, name).await? {
        tracing::debug!("net: {name} already exists (idx {idx})");
        return Ok(idx);
    }

    // Spawn wireguard-go in the background.  We intentionally `forget` the
    // `Child` so it keeps running after this function returns; the PID is
    // stored in `handle` for later termination in [`delete_link`].
    let child = std::process::Command::new("wireguard-go")
        .arg(name)
        .spawn()
        .context("spawn wireguard-go — install with: brew install wireguard-go")?;
    let pid = child.id();
    std::mem::forget(child); // keep process alive; we track PID manually
    handle.0.lock().unwrap().insert(name.to_string(), pid);
    tracing::info!("net: spawned wireguard-go for {name} (pid {pid})");

    // Poll up to 5 s (50 × 100 ms) for the kernel interface to appear.
    for _ in 0..50u8 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Some(idx) = link_index(handle, name).await? {
            tracing::info!("net: {name} up (idx {idx})");
            return Ok(idx);
        }
    }
    anyhow::bail!("wireguard-go did not create interface {name} within 5 s")
}

/// Kill the `wireguard-go` process associated with `name`.
/// Removing the process automatically destroys the utun interface.
#[cfg(target_os = "macos")]
pub async fn delete_link(handle: &Handle, name: &str) -> Result<()> {
    if let Some(pid) = handle.0.lock().unwrap().remove(name) {
        // SIGTERM — wireguard-go handles this gracefully
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if ret != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            tracing::warn!("net: kill wireguard-go (pid {pid}): {}", std::io::Error::last_os_error());
        } else {
            tracing::info!("net: deleted {name} (killed wireguard-go pid {pid})");
        }
    }
    Ok(())
}

/// Set `IFF_UP` on the interface via `SIOCSIFFLAGS`.
///
/// `wireguard-go` typically brings the interface up itself, but we call this
/// explicitly to match the Linux behaviour.
#[cfg(target_os = "macos")]
pub async fn link_up(_handle: &Handle, index: u32) -> Result<()> {
    let name = index_to_name(index)?;
    unsafe {
        macos_ioctl::set_flags(&name, libc::IFF_UP as libc::c_short)
            .context("link_up SIOCSIFFLAGS")?;
    }
    Ok(())
}

/// Set the interface MTU via `SIOCSIFMTU`.
#[cfg(target_os = "macos")]
pub async fn set_mtu(_handle: &Handle, index: u32, mtu: u32) -> Result<()> {
    let name = index_to_name(index)?;
    unsafe {
        macos_ioctl::set_mtu(&name, mtu as libc::c_int).context("SIOCSIFMTU")?;
    }
    Ok(())
}

/// Add an IP address (CIDR) to an interface via `SIOCAIFADDR` (IPv4) or
/// `SIOCAIFADDR_IN6` (IPv6).
///
/// Idempotent — `EEXIST` is silently ignored.
#[cfg(target_os = "macos")]
pub async fn add_address(_handle: &Handle, index: u32, cidr: &str) -> Result<()> {
    let (addr, prefix) = parse_cidr(cidr)?;
    let name = index_to_name(index)?;
    match addr {
        IpAddr::V4(v4) => unsafe {
            macos_ioctl::add_addr_v4(&name, v4, prefix).context("SIOCAIFADDR")?;
        },
        IpAddr::V6(v6) => unsafe {
            macos_ioctl::add_addr_v6(&name, v6, prefix).context("SIOCAIFADDR_IN6")?;
        },
    }
    tracing::debug!("net: added {cidr} to {name}");
    Ok(())
}

/// Flush all IP addresses from an interface.
///
/// Uses `getifaddrs(3)` to enumerate, then `SIOCDIFADDR` / `SIOCDIFADDR_IN6`
/// to remove each address.
#[cfg(target_os = "macos")]
pub async fn flush_addresses(_handle: &Handle, index: u32) -> Result<()> {
    let name = index_to_name(index)?;
    let ifaddrs = nix::ifaddrs::getifaddrs().context("getifaddrs")?;
    for entry in ifaddrs {
        if entry.interface_name != name {
            continue;
        }
        let Some(addr) = entry.address else { continue };
        if let Some(sin) = addr.as_sockaddr_in() {
            // nix 0.29: SockaddrIn::ip() already returns Ipv4Addr
            let v4 = sin.ip();
            unsafe {
                macos_ioctl::del_addr_v4(&name, v4)
                    .context("SIOCDIFADDR")?;
            }
        } else if let Some(sin6) = addr.as_sockaddr_in6() {
            let v6 = sin6.ip();
            unsafe {
                macos_ioctl::del_addr_v6(&name, v6)
                    .context("SIOCDIFADDR_IN6")?;
            }
        }
    }
    Ok(())
}

/// Return the interface index for `name`, or `None` if it does not exist.
#[cfg(target_os = "macos")]
pub async fn link_index(_handle: &Handle, name: &str) -> Result<Option<u32>> {
    match nix::net::if_::if_nametoindex(name) {
        Ok(idx) => Ok(Some(idx)),
        Err(nix::errno::Errno::ENXIO) | Err(nix::errno::Errno::ENODEV) => Ok(None),
        // if_nametoindex returns ENXIO for unknown interface on macOS, but
        // be defensive and also treat any "no such device" variant as absent.
        Err(e) => Err(anyhow::anyhow!(e)).context("if_nametoindex"),
    }
}

// ── macOS helpers ─────────────────────────────────────────────────────────────

/// Convert an interface index to its name via `if_indextoname(3)`.
#[cfg(target_os = "macos")]
fn index_to_name(index: u32) -> Result<String> {
    let mut buf = [0u8; libc::IFNAMSIZ as usize];
    let ptr =
        unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast()) };
    anyhow::ensure!(!ptr.is_null(), "if_indextoname({index}) failed");
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
    Ok(cstr.to_str().context("interface name UTF-8")?.to_owned())
}

/// Low-level `ioctl` helpers for macOS network interface configuration.
///
/// All functions are `unsafe` because they perform raw system calls with
/// manually constructed C structures.  Callers must ensure `name` is a valid,
/// existing interface name.
#[cfg(target_os = "macos")]
mod macos_ioctl {
    use anyhow::{ensure, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};

    // BSD ioctl request codes (from <sys/sockio.h> and <netinet6/in6_var.h>).
    // Computed as _IOW / _IOWR macros would on Darwin.
    const SIOCGIFFLAGS:    libc::c_ulong = 0xC020_6911; // _IOWR('i',17,ifreq)
    const SIOCSIFFLAGS:    libc::c_ulong = 0x8020_6910; // _IOW ('i',16,ifreq)
    const SIOCSIFMTU:      libc::c_ulong = 0x8020_6934; // _IOW ('i',52,ifreq)
    const SIOCAIFADDR:     libc::c_ulong = 0x8044_692B; // _IOW ('i',43,ifaliasreq)
    const SIOCDIFADDR:     libc::c_ulong = 0x8020_6919; // _IOW ('i',25,ifreq)
    const SIOCAIFADDR_IN6: libc::c_ulong = 0x8080_691A; // _IOW ('i',26,in6_aliasreq)
    const SIOCDIFADDR_IN6: libc::c_ulong = 0x8050_690F; // _IOW ('i',15,in6_ifreq)

    // ND6 flag: mark address as permanent (no expiry).
    const IN6_IFF_NODAD: libc::c_int = 0x0020;

    /// Open a temporary `AF_INET/SOCK_DGRAM` socket for ioctl calls.
    /// The returned fd must be closed by the caller.
    unsafe fn open_sock4() -> Result<libc::c_int> {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        ensure!(fd >= 0, "socket(AF_INET): {}", std::io::Error::last_os_error());
        Ok(fd)
    }

    /// Open a temporary `AF_INET6/SOCK_DGRAM` socket for IPv6 ioctl calls.
    unsafe fn open_sock6() -> Result<libc::c_int> {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        ensure!(fd >= 0, "socket(AF_INET6): {}", std::io::Error::last_os_error());
        Ok(fd)
    }

    /// Copy an interface name into a fixed-size `[c_char; IFNAMSIZ]` buffer.
    fn copy_ifname(dst: &mut [libc::c_char; libc::IFNAMSIZ as usize], name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(libc::IFNAMSIZ as usize - 1);
        for (i, &b) in bytes[..len].iter().enumerate() {
            dst[i] = b as libc::c_char;
        }
    }

    /// Read-modify-write the interface flags to OR in `flags`.
    pub(super) unsafe fn set_flags(name: &str, flags: libc::c_short) -> Result<()> {
        let fd = open_sock4()?;
        let mut ifr: libc::ifreq = std::mem::zeroed();
        copy_ifname(&mut ifr.ifr_name, name);

        // Read current flags first.
        let ret = libc::ioctl(fd, SIOCGIFFLAGS, &mut ifr);
        if ret < 0 {
            libc::close(fd);
            anyhow::bail!("SIOCGIFFLAGS: {}", std::io::Error::last_os_error());
        }
        // OR in the requested flags.
        ifr.ifr_ifru.ifru_flags |= flags;
        let ret = libc::ioctl(fd, SIOCSIFFLAGS, &ifr);
        libc::close(fd);
        ensure!(ret >= 0, "SIOCSIFFLAGS: {}", std::io::Error::last_os_error());
        Ok(())
    }

    /// Set the interface MTU.
    pub(super) unsafe fn set_mtu(name: &str, mtu: libc::c_int) -> Result<()> {
        let fd = open_sock4()?;
        let mut ifr: libc::ifreq = std::mem::zeroed();
        copy_ifname(&mut ifr.ifr_name, name);
        ifr.ifr_ifru.ifru_mtu = mtu;
        let ret = libc::ioctl(fd, SIOCSIFMTU, &ifr);
        libc::close(fd);
        ensure!(ret >= 0, "SIOCSIFMTU({mtu}): {}", std::io::Error::last_os_error());
        Ok(())
    }

    /// Add an IPv4 alias address + prefix to an interface via `SIOCAIFADDR`.
    pub(super) unsafe fn add_addr_v4(name: &str, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        /// Mirrors `struct ifaliasreq` from `<net/if.h>`.
        #[repr(C)]
        struct IfAliasReq {
            ifra_name:      [libc::c_char; libc::IFNAMSIZ as usize],
            ifra_addr:      libc::sockaddr_in,
            ifra_broadaddr: libc::sockaddr_in,
            ifra_mask:      libc::sockaddr_in,
        }

        let mut req: IfAliasReq = std::mem::zeroed();
        copy_ifname(&mut req.ifra_name, name);

        // Address
        req.ifra_addr.sin_family = libc::AF_INET as libc::sa_family_t;
        req.ifra_addr.sin_len    = std::mem::size_of::<libc::sockaddr_in>() as u8;
        req.ifra_addr.sin_addr.s_addr = u32::from(addr).to_be();

        // Netmask derived from prefix length
        let mask = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix as u32) };
        req.ifra_mask.sin_family = libc::AF_INET as libc::sa_family_t;
        req.ifra_mask.sin_len    = std::mem::size_of::<libc::sockaddr_in>() as u8;
        req.ifra_mask.sin_addr.s_addr = mask.to_be();

        let fd = open_sock4()?;
        let ret = libc::ioctl(fd, SIOCAIFADDR, &req);
        libc::close(fd);
        // EEXIST means the address is already assigned — that's fine.
        if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            anyhow::bail!("SIOCAIFADDR: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Remove an IPv4 address from an interface via `SIOCDIFADDR`.
    pub(super) unsafe fn del_addr_v4(name: &str, addr: Ipv4Addr) -> Result<()> {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        copy_ifname(&mut ifr.ifr_name, name);
        let sin: &mut libc::sockaddr_in =
            &mut *(&mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in);
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_len    = std::mem::size_of::<libc::sockaddr_in>() as u8;
        sin.sin_addr.s_addr = u32::from(addr).to_be();

        let fd = open_sock4()?;
        let ret = libc::ioctl(fd, SIOCDIFADDR, &ifr);
        libc::close(fd);
        ensure!(ret >= 0, "SIOCDIFADDR: {}", std::io::Error::last_os_error());
        Ok(())
    }

    /// Add an IPv6 alias address + prefix to an interface via `SIOCAIFADDR_IN6`.
    pub(super) unsafe fn add_addr_v6(name: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        /// Mirrors `struct in6_addrlifetime` from `<netinet6/in6.h>`.
        #[repr(C)]
        struct In6AddrLifetime {
            ia6t_expire:    u64, // time_t
            ia6t_preferred: u64,
            ia6t_vltime:    u32,
            ia6t_pltime:    u32,
        }

        /// Mirrors `struct in6_aliasreq` from `<netinet6/in6_var.h>`.
        #[repr(C)]
        struct In6AliasReq {
            ifra_name:       [libc::c_char; libc::IFNAMSIZ as usize],
            ifra_addr:       libc::sockaddr_in6,
            ifra_dstaddr:    libc::sockaddr_in6,
            ifra_prefixmask: libc::sockaddr_in6,
            ifra_flags:      libc::c_int,
            ifra_lifetime:   In6AddrLifetime,
        }

        let mut req: In6AliasReq = std::mem::zeroed();
        copy_ifname(&mut req.ifra_name, name);

        req.ifra_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        req.ifra_addr.sin6_len    = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        req.ifra_addr.sin6_addr   = libc::in6_addr { s6_addr: addr.octets() };

        // Prefix mask
        req.ifra_prefixmask.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        req.ifra_prefixmask.sin6_len    = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        let mut mask = [0u8; 16];
        for i in 0..16usize {
            let start = i * 8;
            if start >= prefix as usize {
                break;
            }
            let bits = (prefix as usize - start).min(8);
            mask[i] = 0xFFu8 << (8 - bits);
        }
        req.ifra_prefixmask.sin6_addr = libc::in6_addr { s6_addr: mask };

        // Mark address as permanent (no duplicate-address detection delay).
        req.ifra_flags = IN6_IFF_NODAD;
        // Infinite lifetime
        req.ifra_lifetime.ia6t_vltime = 0xFFFF_FFFF;
        req.ifra_lifetime.ia6t_pltime = 0xFFFF_FFFF;

        let fd = open_sock6()?;
        let ret = libc::ioctl(fd, SIOCAIFADDR_IN6, &req);
        libc::close(fd);
        if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            anyhow::bail!("SIOCAIFADDR_IN6: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Remove an IPv6 address from an interface via `SIOCDIFADDR_IN6`.
    pub(super) unsafe fn del_addr_v6(name: &str, addr: Ipv6Addr) -> Result<()> {
        /// Mirrors the `in6_ifreq` layout for `SIOCDIFADDR_IN6`.
        #[repr(C)]
        struct In6IfreqDel {
            ifr_name: [libc::c_char; libc::IFNAMSIZ as usize],
            ifr_addr: libc::sockaddr_in6,
            // union padding to match sizeof(in6_ifreq) = 80 bytes
            _pad: [u8; 80 - libc::IFNAMSIZ as usize - std::mem::size_of::<libc::sockaddr_in6>()],
        }

        let mut req: In6IfreqDel = std::mem::zeroed();
        copy_ifname(&mut req.ifr_name, name);
        req.ifr_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        req.ifr_addr.sin6_len    = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        req.ifr_addr.sin6_addr   = libc::in6_addr { s6_addr: addr.octets() };

        let fd = open_sock6()?;
        let ret = libc::ioctl(fd, SIOCDIFADDR_IN6, &req);
        libc::close(fd);
        ensure!(ret >= 0, "SIOCDIFADDR_IN6: {}", std::io::Error::last_os_error());
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Windows implementation — Win32 IP Helper API
// ═══════════════════════════════════════════════════════════════════════════════

/// Locate an existing WireGuard interface by name and return its adapter index.
///
/// On Windows the WireGuard Windows service (or `wireguard.exe`) owns the
/// Wintun adapter lifecycle.  wgdb does not create adapters; the interface is
/// expected to already be managed by the service before this is called.
#[cfg(windows)]
pub async fn create_link(_handle: &Handle, name: &str) -> Result<u32> {
    link_index(_handle, name)
        .await?
        .with_context(|| format!("WireGuard interface '{name}' not found — ensure the WireGuard Windows service has created it"))
}

/// Stop the WireGuard Windows service for this tunnel interface.
///
/// This causes the Wintun adapter to be torn down and routes to be removed.
#[cfg(windows)]
pub async fn delete_link(_handle: &Handle, name: &str) -> Result<()> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
        SERVICE_CONTROL_STOP, SERVICE_STATUS, SC_MANAGER_CONNECT, SERVICE_STOP,
    };
    use windows::core::PCWSTR;

    let svc_name: Vec<u16> = format!("WireGuardTunnel${name}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .context("OpenSCManager")?;
        let svc = OpenServiceW(scm, PCWSTR(svc_name.as_ptr()), SERVICE_STOP);
        match svc {
            Ok(svc) => {
                let mut status = SERVICE_STATUS::default();
                let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
                let _ = CloseServiceHandle(svc);
                tracing::info!("net: stopped WireGuard service for {name}");
            }
            Err(e) => {
                // Service not found is not an error (already stopped / never started)
                tracing::warn!("net: could not open WireGuard service for {name}: {e}");
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    Ok(())
}

/// Bring the interface up — no-op on Windows; the WireGuard service does this.
#[cfg(windows)]
pub async fn link_up(_handle: &Handle, _index: u32) -> Result<()> {
    Ok(())
}

/// Set the MTU on a Windows interface via `SetIpInterfaceEntry`.
#[cfg(windows)]
pub async fn set_mtu(_handle: &Handle, index: u32, mtu: u32) -> Result<()> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    unsafe {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            InterfaceIndex: index,
            ..Default::default()
        };
        // WIN32_ERROR doesn't impl AnyhowContext directly — call .ok() first.
        GetIpInterfaceEntry(&mut row).ok().context("GetIpInterfaceEntry")?;
        row.NlMtu = mtu;
        SetIpInterfaceEntry(&mut row).ok().context("SetIpInterfaceEntry")?;
    }
    tracing::debug!("net: set MTU {mtu} on index {index}");
    Ok(())
}

/// Add a unicast IP address (CIDR) to a Windows interface via
/// `AddUnicastIpAddressEntry`.
///
/// Idempotent — `ERROR_OBJECT_ALREADY_EXISTS` is silently ignored.
#[cfg(windows)]
pub async fn add_address(_handle: &Handle, index: u32, cidr: &str) -> Result<()> {
    use windows::Win32::NetworkManagement::IpHelper::{
        AddUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
        InitializeUnicastIpAddressEntry,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };
    use windows::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;

    let (addr, prefix) = parse_cidr(cidr)?;

    unsafe {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = index;
        row.OnLinkPrefixLength = prefix;

        match addr {
            IpAddr::V4(v4) => {
                row.Address.si_family = AF_INET;
                row.Address.Ipv4 = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                            S_addr: u32::from(v4).to_be(),
                        },
                    },
                    ..Default::default()
                };
            }
            IpAddr::V6(v6) => {
                row.Address.si_family = AF_INET6;
                row.Address.Ipv6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: windows::Win32::Networking::WinSock::IN6_ADDR_0 {
                            Byte: v6.octets(),
                        },
                    },
                    ..Default::default()
                };
            }
        }

        // AddUnicastIpAddressEntry returns WIN32_ERROR, not Result — call .ok() first.
        match AddUnicastIpAddressEntry(&row).ok() {
            Ok(()) => {
                tracing::debug!("net: added {cidr} to index {index}");
                Ok(())
            }
            Err(e)
                if e.code() == ERROR_OBJECT_ALREADY_EXISTS.to_hresult() =>
            {
                Ok(()) // already assigned
            }
            Err(e) => Err(e).context(format!("AddUnicastIpAddressEntry({cidr})")),
        }
    }
}

/// Remove all unicast IP addresses from a Windows interface.
#[cfg(windows)]
pub async fn flush_addresses(_handle: &Handle, index: u32) -> Result<()> {
    use windows::Win32::NetworkManagement::IpHelper::{
        DeleteUnicastIpAddressEntry, FreeMibTable,
        GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_TABLE,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    unsafe {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        GetUnicastIpAddressTable(AF_UNSPEC, &mut table).ok().context("GetUnicastIpAddressTable")?;

        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        for row in rows {
            if row.InterfaceIndex == index {
                // Ignore errors — row may have already disappeared.
                let _ = DeleteUnicastIpAddressEntry(row);
            }
        }
        FreeMibTable(table.cast());
    }
    Ok(())
}

/// Return the interface index for `name` via `ConvertInterfaceAliasToLuid` +
/// `ConvertInterfaceLuidToIndex`, or `None` if the interface does not exist.
#[cfg(windows)]
pub async fn link_index(_handle: &Handle, name: &str) -> Result<Option<u32>> {
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };
    // NET_LUID_LH lives in the Ndis module, not IpHelper.
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH::default();
    unsafe {
        // ConvertInterfaceAliasToLuid returns WIN32_ERROR, not Result.
        if ConvertInterfaceAliasToLuid(
            windows::core::PCWSTR(wide.as_ptr()),
            &mut luid,
        ).is_err() {
            return Ok(None); // interface not found
        }
        let mut idx = 0u32;
        ConvertInterfaceLuidToIndex(&luid, &mut idx).ok().context("ConvertInterfaceLuidToIndex")?;
        Ok(Some(idx))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Common helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse a CIDR string like `"10.0.0.1/24"` into `(IpAddr, prefix_len)`.
pub(crate) fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = cidr
        .split_once('/')
        .context("CIDR missing prefix length")?;
    Ok((
        ip.parse().context("invalid IP in CIDR")?,
        prefix.parse().context("invalid prefix length in CIDR")?,
    ))
}
