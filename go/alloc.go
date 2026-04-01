package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/jmoiron/sqlx"
)

// nextFreeIPv4 returns the next free IPv4 address as "/32" CIDR for the given interface.
// Slot 1 is always the server; clients start at slot 2.
func nextFreeIPv4(db *sqlx.DB, ifaceID int64, serverCIDR string) (string, error) {
	base, prefix, err := parseIPv4CIDR(serverCIDR)
	if err != nil {
		return "", err
	}
	hostBits := 32 - prefix
	if hostBits >= 31 {
		return "", fmt.Errorf("IPv4 subnet too small (/%d)", prefix)
	}
	slotMax := (uint32(1) << hostBits) - 2 // exclude network + broadcast

	serverIP, _, _ := net.ParseCIDR(serverCIDR)
	serverSlot := ipv4ToSlot(base, serverIP)

	used, err := usedIPv4Slots(db, ifaceID, base)
	if err != nil {
		return "", err
	}
	used[serverSlot] = struct{}{}

	for slot := uint32(1); slot <= slotMax; slot++ {
		if _, inUse := used[slot]; !inUse {
			ip := slotToIPv4(base, slot)
			return fmt.Sprintf("%s/32", ip), nil
		}
	}
	return "", fmt.Errorf("IPv4 address space exhausted for %s", serverCIDR)
}

// nextFreeIPv6 returns the next free IPv6 address as "/128" CIDR for the given interface.
func nextFreeIPv6(db *sqlx.DB, ifaceID int64, serverCIDR string) (string, error) {
	base, prefix, err := parseIPv6CIDR(serverCIDR)
	if err != nil {
		return "", err
	}
	hostBits := 128 - prefix
	var slotMax uint32
	if hostBits == 0 {
		return "", fmt.Errorf("IPv6 subnet too small (/%d)", prefix)
	} else if hostBits >= 17 {
		slotMax = 65534
	} else {
		slotMax = (uint32(1) << hostBits) - 1
	}

	serverIP, _, _ := net.ParseCIDR(serverCIDR)
	serverSlot := ipv6ToSlot(base, serverIP)

	used, err := usedIPv6Slots(db, ifaceID, base)
	if err != nil {
		return "", err
	}
	used[serverSlot] = struct{}{}

	for slot := uint32(1); slot <= slotMax; slot++ {
		if _, inUse := used[slot]; !inUse {
			ip := slotToIPv6(base, slot)
			return fmt.Sprintf("%s/128", ip), nil
		}
	}
	return "", fmt.Errorf("IPv6 address space exhausted for %s", serverCIDR)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseIPv4CIDR(cidr string) (uint32, uint, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}
	ip = ip.To4()
	if ip == nil {
		return 0, 0, fmt.Errorf("not an IPv4 CIDR: %s", cidr)
	}
	ones, _ := ipNet.Mask.Size()
	base := binary.BigEndian.Uint32([]byte(ipNet.IP))
	return base, uint(ones), nil
}

func parseIPv6CIDR(cidr string) ([16]byte, uint, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return [16]byte{}, 0, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()
	var base [16]byte
	copy(base[:], ipNet.IP.To16())
	return base, uint(ones), nil
}

func slotToIPv4(base, slot uint32) net.IP {
	n := base + slot
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b)
}

func slotToIPv6(base [16]byte, slot uint32) net.IP {
	result := make([]byte, 16)
	copy(result, base[:])
	// add slot to the last 4 bytes (big-endian)
	n := binary.BigEndian.Uint32(result[12:]) + slot
	binary.BigEndian.PutUint32(result[12:], n)
	return net.IP(result)
}

func ipv4ToSlot(base uint32, ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	n := binary.BigEndian.Uint32([]byte(ip4))
	if n < base {
		return 0
	}
	return n - base
}

func ipv6ToSlot(base [16]byte, ip net.IP) uint32 {
	ip16 := ip.To16()
	if ip16 == nil {
		return 0
	}
	baseN := binary.BigEndian.Uint32(base[12:])
	ipN := binary.BigEndian.Uint32([]byte(ip16[12:]))
	if ipN < baseN {
		return 0
	}
	return ipN - baseN
}

func usedIPv4Slots(db *sqlx.DB, ifaceID int64, base uint32) (map[uint32]struct{}, error) {
	var addrs []string
	err := db.Select(&addrs, `SELECT ipv4 FROM peers WHERE iface_id=? AND status='active' AND ipv4 IS NOT NULL`, ifaceID)
	if err != nil {
		return nil, err
	}
	used := make(map[uint32]struct{})
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			ip = net.ParseIP(a)
		}
		if ip != nil {
			used[ipv4ToSlot(base, ip)] = struct{}{}
		}
	}
	return used, nil
}

func usedIPv6Slots(db *sqlx.DB, ifaceID int64, base [16]byte) (map[uint32]struct{}, error) {
	var addrs []string
	err := db.Select(&addrs, `SELECT ipv6 FROM peers WHERE iface_id=? AND status='active' AND ipv6 IS NOT NULL`, ifaceID)
	if err != nil {
		return nil, err
	}
	used := make(map[uint32]struct{})
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			ip = net.ParseIP(a)
		}
		if ip != nil {
			used[ipv6ToSlot(base, ip)] = struct{}{}
		}
	}
	return used, nil
}
