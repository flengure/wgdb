//go:build windows

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
)

func addAddress(ifName, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	_ = ipNet
	if ip.To4() != nil {
		mask := net.IP(ipNet.Mask).String()
		out, err := exec.Command("netsh", "interface", "ip", "add", "address",
			"name="+ifName, ip.String(), mask).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh add address %s: %s: %w", cidr, out, err)
		}
	} else {
		ones, _ := ipNet.Mask.Size()
		out, err := exec.Command("netsh", "interface", "ipv6", "add", "address",
			"interface="+ifName,
			fmt.Sprintf("%s/%d", ip.String(), ones)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh add ipv6 address %s: %s: %w", cidr, out, err)
		}
	}
	return nil
}

func flushAddresses(ifName string) error {
	exec.Command("netsh", "interface", "ip", "delete", "address", ifName, "all").Run()
	exec.Command("netsh", "interface", "ipv6", "delete", "address", ifName, "all").Run()
	return nil
}

func linkUp(ifName string) error {
	// wintun adapter comes up automatically when the WireGuard device starts.
	return nil
}

func setMTU(ifName string, mtu int) error {
	out, err := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		ifName, "mtu="+strconv.Itoa(mtu), "store=persistent").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set mtu %d on %s: %s: %w", mtu, ifName, out, err)
	}
	return nil
}

func addRoute(ifName, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()
	if ip.To4() != nil {
		out, err := exec.Command("netsh", "interface", "ip", "add", "route",
			fmt.Sprintf("%s/%d", ipNet.IP.String(), ones), ifName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh add route %s %s: %s: %w", cidr, ifName, out, err)
		}
	} else {
		out, err := exec.Command("netsh", "interface", "ipv6", "add", "route",
			fmt.Sprintf("%s/%d", ipNet.IP.String(), ones), ifName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh add ipv6 route %s %s: %s: %w", cidr, ifName, out, err)
		}
	}
	return nil
}

func removeRoute(ifName, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()
	if ip.To4() != nil {
		out, err := exec.Command("netsh", "interface", "ip", "delete", "route",
			fmt.Sprintf("%s/%d", ipNet.IP.String(), ones), ifName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh delete route %s %s: %s: %w", cidr, ifName, out, err)
		}
	} else {
		out, err := exec.Command("netsh", "interface", "ipv6", "delete", "route",
			fmt.Sprintf("%s/%d", ipNet.IP.String(), ones), ifName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh delete ipv6 route %s %s: %s: %w", cidr, ifName, out, err)
		}
	}
	return nil
}
