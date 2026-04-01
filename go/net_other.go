//go:build !linux && !darwin && !windows

package main

import "fmt"

func addAddress(ifName, cidr string) error {
	return fmt.Errorf("addAddress not implemented on this platform")
}

func flushAddresses(ifName string) error {
	return fmt.Errorf("flushAddresses not implemented on this platform")
}

func linkUp(ifName string) error {
	return fmt.Errorf("linkUp not implemented on this platform")
}

func setMTU(ifName string, mtu int) error {
	return fmt.Errorf("setMTU not implemented on this platform")
}

func addRoute(ifName, cidr string) error {
	return fmt.Errorf("addRoute not implemented on this platform")
}

func removeRoute(ifName, cidr string) error {
	return fmt.Errorf("removeRoute not implemented on this platform")
}
