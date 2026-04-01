package main

import (
	"log/slog"
	"strings"
)

// runHooks executes a newline-separated list of shell commands, replacing %i
// with ifName before each execution.  Errors are logged but do not abort.
func runHooks(hooks string, ifName string) {
	if hooks == "" {
		return
	}
	for _, line := range strings.Split(hooks, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cmd := strings.ReplaceAll(line, "%i", ifName)
		c := hookShellCommand(cmd)
		if out, err := c.CombinedOutput(); err != nil {
			slog.Warn("hook error", "cmd", cmd, "err", err, "output", strings.TrimSpace(string(out)))
		}
	}
}
