//go:build !windows

package main

import "os/exec"

func hookShellCommand(cmd string) *exec.Cmd {
	return exec.Command("sh", "-c", cmd)
}
