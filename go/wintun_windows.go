//go:build windows

package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

// initWintun writes the embedded wintun.dll next to the executable so that
// the wintun package's LoadLibraryEx (LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
// can find it. Requires the process to already be running as administrator.
func initWintun() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dllPath := filepath.Join(filepath.Dir(exePath), "wintun.dll")
	// Skip if already present.
	if _, err := os.Stat(dllPath); err == nil {
		return nil
	}
	return os.WriteFile(dllPath, wintunDLL, 0644)
}
