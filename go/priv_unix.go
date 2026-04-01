//go:build !windows

package main

import "os"

func checkPrivileges() {
	if os.Getuid() != 0 {
		fatalf("must be run as root (try: sudo wgdb)")
	}
}
