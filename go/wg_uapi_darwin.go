//go:build darwin

package main

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func platformUAPIListen(name string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(name, f)
}
