//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strconv"
)

func addAddress(ifName, cidr string) error {
	out, err := exec.Command("ip", "addr", "add", cidr, "dev", ifName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr add %s dev %s: %s: %w", cidr, ifName, out, err)
	}
	return nil
}

func flushAddresses(ifName string) error {
	exec.Command("ip", "addr", "flush", "dev", ifName).Run()
	return nil
}

func linkUp(ifName string) error {
	out, err := exec.Command("ip", "link", "set", ifName, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set %s up: %s: %w", ifName, out, err)
	}
	return nil
}

func setMTU(ifName string, mtu int) error {
	out, err := exec.Command("ip", "link", "set", ifName, "mtu", strconv.Itoa(mtu)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set %s mtu %d: %s: %w", ifName, mtu, out, err)
	}
	return nil
}
