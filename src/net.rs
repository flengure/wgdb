/// Network interface management via rtnetlink (no subprocess).
use anyhow::{Context, Result};
use futures::TryStreamExt;
use netlink_packet_route::link::{
    InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use rtnetlink::Handle;
use std::net::IpAddr;

/// Create a WireGuard kernel interface. Returns the link index.
/// If the interface already exists, returns its index without error.
pub async fn create_link(handle: &Handle, name: &str) -> Result<u32> {
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

/// Bring a link up.
pub async fn link_up(handle: &Handle, index: u32) -> Result<()> {
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

/// Set MTU on a link.
pub async fn set_mtu(handle: &Handle, index: u32, mtu: u32) -> Result<()> {
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

/// Add an IP address (CIDR) to an interface. Idempotent — ignores EEXIST.
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

/// Flush all addresses from an interface.
pub async fn flush_addresses(handle: &Handle, index: u32) -> Result<()> {
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

// ── Internal helpers ──────────────────────────────────────────────────────────

pub async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
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

fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = cidr
        .split_once('/')
        .context("CIDR missing prefix length")?;
    Ok((
        ip.parse().context("invalid IP")?,
        prefix.parse().context("invalid prefix")?,
    ))
}
