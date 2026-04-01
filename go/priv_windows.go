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

	// The WireGuard UAPI named pipe security descriptor sets O:SY (owner=SYSTEM).
	// Creating an object with a different owner requires SeRestorePrivilege.
	if err := enablePrivilege("SeRestorePrivilege"); err != nil {
		fatalf("enable SeRestorePrivilege: %v", err)
	}
}

func enablePrivilege(name string) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return err
	}
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer tok.Close()
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	tp.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}
