//go:build !linux

package main

// macOS + Windows: embed the wireguard-go library in-process.
// A TUN device is created, the WireGuard protocol runs in goroutines, and a
// UAPI socket (macOS) / named pipe (Windows) is served so wgctrl can
// configure the device by logical name.
//
// Platform-specific UAPI listener creation is in wg_uapi_darwin.go /
// wg_uapi_windows.go (they have different signatures in this library version).

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type wgDevice struct {
	dev      *device.Device
	tunDev   tun.Device
	uapi     net.Listener
	realName string // actual kernel interface name (may differ on macOS)
}

// platformState stores active in-process WireGuard devices.
type platformState struct {
	devMu   sync.RWMutex
	devices map[string]*wgDevice
}

func newWGManager() *WGManager {
	return &WGManager{
		platformState: platformState{devices: make(map[string]*wgDevice)},
	}
}

// realInterfaceName returns the kernel interface name for an in-process device.
func (m *WGManager) realInterfaceName(name string) string {
	m.devMu.RLock()
	defer m.devMu.RUnlock()
	if d, ok := m.devices[name]; ok {
		return d.realName
	}
	return name
}

// createLink creates an embedded wireguard-go device for the given logical name.
func (m *WGManager) createLink(name string, mtu int) error {
	m.devMu.Lock()
	defer m.devMu.Unlock()

	if _, exists := m.devices[name]; exists {
		return nil // already up
	}

	if mtu <= 0 {
		mtu = device.DefaultMTU
	}

	// macOS requires "utun" or "utunN"; use "utun" to auto-assign.
	tunName := name
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	}

	tunDev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		return fmt.Errorf("create TUN %s: %w", name, err)
	}

	realName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return fmt.Errorf("get TUN name for %s: %w", name, err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[%s] ", name))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	// Open UAPI socket/pipe using the logical name so wgctrl can find it.
	uapiLn, err := platformUAPIListen(name)
	if err != nil {
		dev.Close()
		tunDev.Close()
		return fmt.Errorf("UAPI listen %s: %w", name, err)
	}

	// Serve UAPI connections in a goroutine.
	go func() {
		for {
			c, err := uapiLn.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	dev.Up()

	m.devices[name] = &wgDevice{
		dev:      dev,
		tunDev:   tunDev,
		uapi:     uapiLn,
		realName: realName,
	}
	return nil
}

// deleteLink tears down an in-process WireGuard device.
func (m *WGManager) deleteLink(name string) error {
	m.devMu.Lock()
	d, ok := m.devices[name]
	if ok {
		delete(m.devices, name)
	}
	m.devMu.Unlock()

	if d == nil {
		return nil
	}

	d.uapi.Close()
	d.dev.Close()
	d.tunDev.Close()

	// Remove the UAPI socket file on Unix.
	if runtime.GOOS != "windows" {
		os.Remove(filepath.Join("/var/run/wireguard", name+".sock"))
	}
	return nil
}
