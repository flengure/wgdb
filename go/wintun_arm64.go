//go:build windows && arm64

package main

import _ "embed"

//go:embed wintun/arm64/wintun.dll
var wintunDLL []byte
