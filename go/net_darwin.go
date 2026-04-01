//go:build darwin

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func addAddress(ifName, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	_ = ipNet
	if ip.To4() != nil {
		// Point-to-point: same address for local and remote (utun style)
		out, err := exec.Command("ifconfig", ifName, "inet", ip.String(), ip.String()).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ifconfig %s inet %s: %s: %w", ifName, ip, out, err)
		}
	} else {
		out, err := exec.Command("ifconfig", ifName, "inet6", cidr).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ifconfig %s inet6 %s: %s: %w", ifName, cidr, out, err)
		}
	}
	return nil
}

func flushAddresses(ifName string) error {
	out, _ := exec.Command("ifconfig", ifName).Output()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			if parts := strings.Fields(line); len(parts) >= 2 {
				exec.Command("ifconfig", ifName, "inet", parts[1], "delete").Run()
			}
		} else if strings.HasPrefix(line, "inet6 ") {
			if parts := strings.Fields(line); len(parts) >= 2 {
				addr := strings.Split(parts[1], "%")[0]
				exec.Command("ifconfig", ifName, "inet6", addr, "delete").Run()
			}
		}
	}
	return nil
}

func linkUp(ifName string) error {
	out, err := exec.Command("ifconfig", ifName, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s up: %s: %w", ifName, out, err)
	}
	return nil
}

func setMTU(ifName string, mtu int) error {
	out, err := exec.Command("ifconfig", ifName, "mtu", strconv.Itoa(mtu)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s mtu %d: %s: %w", ifName, mtu, out, err)
	}
	return nil
}
