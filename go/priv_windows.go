//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

func checkPrivileges() {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	); err != nil {
		fatalf("check admin: %v", err)
	}
	defer windows.FreeSid(sid)

	ok, err := windows.Token(0).IsMember(sid)
	if err != nil {
		fatalf("check admin: %v", err)
	}
	if !ok {
		fatalf("must be run as Administrator")
	}
}
