/// IP slot allocation — finds the next free IPv4 or IPv6 address within a
/// subnet by scanning existing active peers in the DB.
///
/// Slot 1 is always the server address. Client slots start at 2.
use anyhow::{bail, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::db::Db;

// ── Public entry points ───────────────────────────────────────────────────────

/// Returns the next free IPv4 address (as "/32") for the given interface.
pub fn next_free_ipv4(db: &Db, iface_id: i64, server_cidr: &str) -> Result<String> {
    let (base, prefix) = parse_ipv4_cidr(server_cidr)?;
    let host_bits = 32u32.saturating_sub(prefix as u32);
    let slot_max = if host_bits >= 31 {
        bail!("IPv4 subnet too small (/{prefix})");
    } else {
        (1u32 << host_bits) - 2 // exclude network + broadcast
    };

    let server_ip = server_cidr.split_once('/').map(|(ip, _)| ip).unwrap_or("");
    let server_slot = ipv4_to_slot(base, server_ip).unwrap_or(1);
    let mut used = used_ipv4_slots(db, iface_id, base)?;
    used.insert(server_slot);
    for slot in 1..=slot_max {
        if !used.contains(&slot) {
            let ip = slot_to_ipv4(base, slot);
            return Ok(format!("{ip}/32"));
        }
    }
    bail!("IPv4 address space exhausted for {server_cidr}")
}

/// Returns the next free IPv6 address (as "/128") for the given interface.
pub fn next_free_ipv6(db: &Db, iface_id: i64, server_cidr: &str) -> Result<String> {
    let (base, prefix) = parse_ipv6_cidr(server_cidr)?;
    let host_bits = 128u32.saturating_sub(prefix as u32);
    let slot_max: u32 = if host_bits >= 17 {
        65534 // cap so we don't scan 2^64 entries
    } else if host_bits == 0 {
        bail!("IPv6 subnet too small (/{prefix})");
    } else {
        (1u32 << host_bits).saturating_sub(1)
    };

    let server_ip = server_cidr.split_once('/').map(|(ip, _)| ip).unwrap_or("");
    let server_slot = ipv6_to_slot(base, server_ip).unwrap_or(1);
    let mut used = used_ipv6_slots(db, iface_id, base)?;
    used.insert(server_slot);
    for slot in 1..=slot_max {
        if !used.contains(&slot) {
            let ip = slot_to_ipv6(base, slot);
            return Ok(format!("{ip}/128"));
        }
    }
    bail!("IPv6 address space exhausted for {server_cidr}")
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn parse_ipv4_cidr(cidr: &str) -> Result<(u32, u8)> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid CIDR: {cidr}"))?;
    let ip: Ipv4Addr = ip_str.parse()?;
    let prefix: u8 = prefix_str.parse()?;
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    let base = u32::from(ip) & mask;
    Ok((base, prefix))
}

fn parse_ipv6_cidr(cidr: &str) -> Result<(u128, u8)> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid CIDR: {cidr}"))?;
    let ip: Ipv6Addr = ip_str.parse()?;
    let prefix: u8 = prefix_str.parse()?;
    let mask = if prefix == 0 { 0u128 } else { !0u128 << (128 - prefix) };
    let base = u128::from(ip) & mask;
    Ok((base, prefix))
}

fn slot_to_ipv4(base: u32, slot: u32) -> Ipv4Addr {
    Ipv4Addr::from(base + slot)
}

fn slot_to_ipv6(base: u128, slot: u32) -> Ipv6Addr {
    Ipv6Addr::from(base + slot as u128)
}

fn ipv4_to_slot(base: u32, ip: &str) -> Option<u32> {
    let addr: Ipv4Addr = ip.trim_end_matches("/32").parse().ok()?;
    let n = u32::from(addr);
    if n >= base { Some(n - base) } else { None }
}

fn ipv6_to_slot(base: u128, ip: &str) -> Option<u32> {
    let addr: Ipv6Addr = ip.trim_end_matches("/128").parse().ok()?;
    let n = u128::from(addr);
    let diff = n.checked_sub(base)?;
    u32::try_from(diff).ok()
}

fn used_ipv4_slots(db: &Db, iface_id: i64, base: u32) -> Result<std::collections::HashSet<u32>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT ipv4 FROM peers WHERE iface_id = ?1 AND status = 'active' AND ipv4 IS NOT NULL",
    )?;
    let slots: std::collections::HashSet<u32> = stmt
        .query_map(rusqlite::params![iface_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .filter_map(|ip| ipv4_to_slot(base, &ip))
        .collect();
    Ok(slots)
}

fn used_ipv6_slots(db: &Db, iface_id: i64, base: u128) -> Result<std::collections::HashSet<u32>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT ipv6 FROM peers WHERE iface_id = ?1 AND status = 'active' AND ipv6 IS NOT NULL",
    )?;
    let slots: std::collections::HashSet<u32> = stmt
        .query_map(rusqlite::params![iface_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .filter_map(|ip| ipv6_to_slot(base, &ip))
        .collect();
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_slot_roundtrip() {
        let (base, _) = parse_ipv4_cidr("10.0.0.1/24").unwrap();
        assert_eq!(base, u32::from(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(slot_to_ipv4(base, 1), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(slot_to_ipv4(base, 2), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ipv4_to_slot(base, "10.0.0.5/32"), Some(5));
    }

    #[test]
    fn ipv6_slot_roundtrip() {
        let (base, _) = parse_ipv6_cidr("fd00::1/64").unwrap();
        assert_eq!(slot_to_ipv6(base, 2), "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6_to_slot(base, "fd00::5/128"), Some(5));
    }
}
