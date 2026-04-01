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
		mask := net.IP(ipNet.Mask)
		netmask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
		out, err := exec.Command("ifconfig", ifName, "inet", ip.String(), ip.String(), "netmask", netmask).CombinedOutput()
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

func addRoute(ifName, cidr string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	var out []byte
	if ip.To4() != nil {
		out, err = exec.Command("route", "add", "-net", cidr, "-interface", ifName).CombinedOutput()
	} else {
		out, err = exec.Command("route", "add", "-inet6", cidr, "-interface", ifName).CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("route add %s via %s: %s: %w", cidr, ifName, out, err)
	}
	return nil
}

func removeRoute(ifName, cidr string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	var out []byte
	if ip.To4() != nil {
		out, err = exec.Command("route", "delete", "-net", cidr, "-interface", ifName).CombinedOutput()
	} else {
		out, err = exec.Command("route", "delete", "-inet6", cidr, "-interface", ifName).CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("route delete %s via %s: %s: %w", cidr, ifName, out, err)
	}
	return nil
}
