//go:build !windows

package main

func isWindowsService() bool                                        { return false }
func runWindowsService(dbPath, addr, adminToken string)             {}
func handleServiceCommand(cmd, dbPath, addr, adminToken string) bool { return false }
