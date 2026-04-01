//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "wgdb"

func isWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

type wgdbService struct {
	dbPath     string
	addr       string
	adminToken string
}

func (s *wgdbService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	go func() {
		run(s.dbPath, s.addr, s.adminToken, stop)
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			return false, 0
		}
	}
	return false, 0
}

func runWindowsService(dbPath, addr, adminToken string) {
	if err := svc.Run(serviceName, &wgdbService{dbPath: dbPath, addr: addr, adminToken: adminToken}); err != nil {
		fatalf("service run: %v", err)
	}
}

func handleServiceCommand(cmd, dbPath, addr, adminToken string) bool {
	switch cmd {
	case "install":
		if err := installService(dbPath, addr, adminToken); err != nil {
			fatalf("install service: %v", err)
		}
		fmt.Println("service installed")
		return true
	case "uninstall":
		if err := uninstallService(); err != nil {
			fatalf("uninstall service: %v", err)
		}
		fmt.Println("service uninstalled")
		return true
	case "start":
		if err := startService(); err != nil {
			fatalf("start service: %v", err)
		}
		fmt.Println("service started")
		return true
	case "stop":
		if err := stopService(); err != nil {
			fatalf("stop service: %v", err)
		}
		fmt.Println("service stopped")
		return true
	}
	return false
}

func installService(dbPath, addr, adminToken string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: "wgdb WireGuard Manager",
		Description: "WireGuard VPN management daemon",
	}, "-db", dbPath, "-addr", addr, "-admin-token", adminToken)
	if err != nil {
		return err
	}
	s.Close()
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Delete()
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("service did not stop within 10 seconds")
}
