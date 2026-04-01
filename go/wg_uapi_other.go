//go:build !linux && !darwin && !windows

package main

import (
	"fmt"
	"net"
)

func platformUAPIListen(name string) (net.Listener, error) {
	return nil, fmt.Errorf("WireGuard UAPI not supported on this platform")
}
