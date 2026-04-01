//go:build linux

package main

// Linux: use the WireGuard kernel module.
// Interface creation/deletion via `ip link`; wgctrl uses the kernel netlink backend.

import (
	"fmt"
	"os/exec"
)

// platformState on Linux is empty — no in-process device to track.
type platformState struct{}

func newWGManager() *WGManager { return &WGManager{} }

// realInterfaceName returns the kernel interface name (same as logical on Linux).
func (m *WGManager) realInterfaceName(name string) string { return name }

// createLink creates a kernel WireGuard interface (idempotent).
func (m *WGManager) createLink(name string, _ int) error {
	// Idempotent: if interface already exists, `ip link add` will fail but
	// the interface is usable.  We ignore the error and check existence instead.
	out, err := exec.Command("ip", "link", "add", name, "type", "wireguard").CombinedOutput()
	if err != nil {
		// Already exists is fine.
		chk, _ := exec.Command("ip", "link", "show", name).CombinedOutput()
		if len(chk) == 0 {
			return fmt.Errorf("ip link add %s type wireguard: %s: %w", name, out, err)
		}
	}
	return nil
}

// deleteLink removes the kernel interface.
func (m *WGManager) deleteLink(name string) error {
	out, err := exec.Command("ip", "link", "del", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link del %s: %s: %w", name, out, err)
	}
	return nil
}
