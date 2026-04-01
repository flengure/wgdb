//go:build windows

package main

import (
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc"
)

func platformUAPIListen(name string) (net.Listener, error) {
	// When running as a Windows service under SYSTEM, O:SY (owner=SYSTEM) works.
	// When running interactively as Administrator it does not — override with O:BA.
	if !isWindowsService() {
		if sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)"); err == nil {
			ipc.UAPISecurityDescriptor = sd
		}
	}
	return ipc.UAPIListen(name)
}
