//go:build windows

package main

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func platformUAPIListen(name string) (net.Listener, error) {
	return ipc.UAPIListen(name)
}
