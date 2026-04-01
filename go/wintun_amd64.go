//go:build windows && amd64

package main

import _ "embed"

//go:embed wintun/amd64/wintun.dll
var wintunDLL []byte
