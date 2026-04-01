package main

// WireGuard management — common code (key generation, configuration, stats).
// Platform-specific interface creation/deletion is in wg_linux.go (kernel) and
// wg_userspace.go (macOS + Windows, embedded wireguard-go library).

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jmoiron/sqlx"
)

// ── Manager ───────────────────────────────────────────────────────────────────

// WGManager manages live WireGuard devices.  Platform-specific fields are
// provided by platformState (wg_linux.go / wg_userspace.go).
type WGManager struct {
	mu sync.RWMutex
	platformState
}

// InterfaceStats is aggregate traffic data for a WireGuard interface.
type InterfaceStats struct {
	PeerCount int    `json:"peer_count"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
}

// newWGManager constructs a WGManager (delegates to platform init).
// Implemented per-platform in wg_linux.go / wg_userspace.go.

// ── Key generation ────────────────────────────────────────────────────────────

// GenerateKeypair returns (privateKeyBase64, publicKeyBase64).
func GenerateKeypair() (string, string, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate keypair: %w", err)
	}
	return priv.String(), priv.PublicKey().String(), nil
}

// ImportPrivateKey validates a base64-encoded private key and derives the
// public key.  Returns (privateB64, publicB64).
func ImportPrivateKey(b64 string) (string, string, error) {
	key, err := wgtypes.ParseKey(b64)
	if err != nil {
		return "", "", fmt.Errorf("parse private key: %w", err)
	}
	return key.String(), key.PublicKey().String(), nil
}

// GeneratePSK returns a random 32-byte pre-shared key as base64.
func GeneratePSK() (string, error) {
	k, err := wgtypes.GenerateKey()
	if err != nil {
		return "", err
	}
	return k.String(), nil
}

// ── Configuration ─────────────────────────────────────────────────────────────

// Configure applies a full replacement configuration (private key, listen port,
// all peers) to a live WireGuard interface.  The logical name is used to
// locate the interface via wgctrl.
func (m *WGManager) Configure(logicalName string, iface *Interface, peers []Peer) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl.New: %w", err)
	}
	defer c.Close()

	privKey, err := wgtypes.ParseKey(iface.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	port := int(iface.ListenPort)

	var pcs []wgtypes.PeerConfig
	for i := range peers {
		pc, err := buildPeerConfig(&peers[i])
		if err != nil {
			return err
		}
		pcs = append(pcs, pc)
	}

	return c.ConfigureDevice(logicalName, wgtypes.Config{
		PrivateKey:   &privKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers:        pcs,
	})
}

// AddPeer hot-adds or updates a single peer on a live interface.
func (m *WGManager) AddPeer(logicalName string, peer *Peer) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl.New: %w", err)
	}
	defer c.Close()

	pc, err := buildPeerConfig(peer)
	if err != nil {
		return err
	}
	if err := c.ConfigureDevice(logicalName, wgtypes.Config{Peers: []wgtypes.PeerConfig{pc}}); err != nil {
		return err
	}
	realName := m.realInterfaceName(logicalName)
	for _, cidr := range peerAllowedIPs(peer) {
		if err := addRoute(realName, cidr); err != nil {
			slog.Warn("add route", "iface", logicalName, "cidr", cidr, "err", err)
		}
	}
	return nil
}

// RemovePeer removes a peer from a live interface by its base64 public key.
// Pass peer to also remove its routes; peer may be nil.
func (m *WGManager) RemovePeer(logicalName, pubkey string) error {
	return m.RemovePeerWithRoutes(logicalName, pubkey, nil)
}

func (m *WGManager) RemovePeerWithRoutes(logicalName, pubkey string, peer *Peer) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl.New: %w", err)
	}
	defer c.Close()

	pk, err := wgtypes.ParseKey(pubkey)
	if err != nil {
		return fmt.Errorf("parse pubkey: %w", err)
	}
	if err := c.ConfigureDevice(logicalName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pk, Remove: true}},
	}); err != nil {
		return err
	}
	if peer != nil {
		realName := m.realInterfaceName(logicalName)
		for _, cidr := range peerAllowedIPs(peer) {
			if err := removeRoute(realName, cidr); err != nil {
				slog.Warn("remove route", "iface", logicalName, "cidr", cidr, "err", err)
			}
		}
	}
	return nil
}

// Handshakes returns a map of base64_pubkey → last-handshake unix timestamp.
func (m *WGManager) Handshakes(logicalName string) (map[string]int64, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl.New: %w", err)
	}
	defer c.Close()

	d, err := c.Device(logicalName)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(d.Peers))
	for _, p := range d.Peers {
		if !p.LastHandshakeTime.Equal(time.Time{}) {
			out[p.PublicKey.String()] = p.LastHandshakeTime.Unix()
		}
	}
	return out, nil
}

// Stats returns aggregate traffic statistics for a live interface.
func (m *WGManager) Stats(logicalName string) (*InterfaceStats, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl.New: %w", err)
	}
	defer c.Close()

	d, err := c.Device(logicalName)
	if err != nil {
		return nil, err
	}
	stats := &InterfaceStats{PeerCount: len(d.Peers)}
	for _, p := range d.Peers {
		stats.RxBytes += uint64(p.ReceiveBytes)
		stats.TxBytes += uint64(p.TransmitBytes)
	}
	return stats, nil
}

// BringUpInterface orchestrates the full startup sequence for a WireGuard
// interface: pre_up hooks → create link → configure WG → assign addresses →
// bring up → add routes → post_up hooks.
func (m *WGManager) BringUpInterface(db *sqlx.DB, iface *Interface) error {
	peers, err := dbListPeersForIface(db, iface.ID)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}
	mtu := 0
	if iface.Mtu != nil {
		mtu = int(*iface.Mtu)
	}

	runHooks(derefStrWG(iface.PreUp), iface.Name)

	if err := m.createLink(iface.Name, mtu); err != nil {
		return fmt.Errorf("create link %s: %w", iface.Name, err)
	}
	if err := m.Configure(iface.Name, iface, peers); err != nil {
		return fmt.Errorf("configure %s: %w", iface.Name, err)
	}
	realName := m.realInterfaceName(iface.Name)
	if iface.AddressV4 != nil {
		if err := addAddress(realName, *iface.AddressV4); err != nil {
			return fmt.Errorf("add address %s: %w", *iface.AddressV4, err)
		}
	}
	if iface.AddressV6 != nil {
		if err := addAddress(realName, *iface.AddressV6); err != nil {
			return fmt.Errorf("add address %s: %w", *iface.AddressV6, err)
		}
	}
	if err := linkUp(realName); err != nil {
		return fmt.Errorf("link up %s: %w", realName, err)
	}
	for i := range peers {
		for _, cidr := range peerAllowedIPs(&peers[i]) {
			if err := addRoute(realName, cidr); err != nil {
				slog.Warn("add route", "iface", iface.Name, "cidr", cidr, "err", err)
			}
		}
	}

	runHooks(derefStrWG(iface.PostUp), iface.Name)
	return nil
}

// DeleteLink tears down a live WireGuard interface with pre/post down hooks.
func (m *WGManager) DeleteLink(name string) error {
	return m.DeleteLinkWithHooks(name, nil)
}

// DeleteLinkWithHooks tears down a live WireGuard interface, running hooks and
// removing peer routes if iface is provided.
func (m *WGManager) DeleteLinkWithHooks(name string, iface *Interface) error {
	if iface != nil {
		runHooks(derefStrWG(iface.PreDown), name)
	}
	if err := m.deleteLink(name); err != nil {
		return err
	}
	if iface != nil {
		runHooks(derefStrWG(iface.PostDown), name)
	}
	return nil
}

// FlushAndReaddresses removes all addresses from an interface and re-adds them.
func (m *WGManager) FlushAndReaddresses(iface *Interface) error {
	realName := m.realInterfaceName(iface.Name)
	if err := flushAddresses(realName); err != nil {
		return err
	}
	if iface.AddressV4 != nil {
		if err := addAddress(realName, *iface.AddressV4); err != nil {
			return err
		}
	}
	if iface.AddressV6 != nil {
		if err := addAddress(realName, *iface.AddressV6); err != nil {
			return err
		}
	}
	return nil
}

// SetMTU applies an MTU to a live interface.
func (m *WGManager) SetMTU(name string, mtu int) error {
	return setMTU(m.realInterfaceName(name), mtu)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// peerAllowedIPs returns the list of CIDR strings for a peer's allocated IPs.
func peerAllowedIPs(peer *Peer) []string {
	var out []string
	if peer.Ipv4 != nil && *peer.Ipv4 != "" {
		out = append(out, *peer.Ipv4)
	}
	if peer.Ipv6 != nil && *peer.Ipv6 != "" {
		out = append(out, *peer.Ipv6)
	}
	return out
}

func derefStrWG(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func buildPeerConfig(peer *Peer) (wgtypes.PeerConfig, error) {
	pk, err := wgtypes.ParseKey(peer.Pubkey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parse peer pubkey: %w", err)
	}
	pc := wgtypes.PeerConfig{
		PublicKey:         pk,
		ReplaceAllowedIPs: true,
	}
	if peer.Psk != nil {
		psk, err := wgtypes.ParseKey(*peer.Psk)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("parse psk: %w", err)
		}
		pc.PresharedKey = &psk
	}
	if peer.Ipv4 != nil {
		_, ipNet, err := net.ParseCIDR(*peer.Ipv4)
		if err == nil {
			pc.AllowedIPs = append(pc.AllowedIPs, *ipNet)
		}
	}
	if peer.Ipv6 != nil {
		_, ipNet, err := net.ParseCIDR(*peer.Ipv6)
		if err == nil {
			pc.AllowedIPs = append(pc.AllowedIPs, *ipNet)
		}
	}
	return pc, nil
}
