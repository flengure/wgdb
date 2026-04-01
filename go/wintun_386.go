//go:build windows && 386

package main

import _ "embed"

//go:embed wintun/x86/wintun.dll
var wintunDLL []byte
