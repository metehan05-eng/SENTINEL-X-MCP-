//go:build windows

package main

import "strings"

func runtimeIsWindows() bool { return true }

// windowsPath normalises separators, because a client started from cmd.exe or
// PowerShell will not resolve a forward-slash path.
func windowsPath(p string) string { return strings.ReplaceAll(p, "/", `\`) }
