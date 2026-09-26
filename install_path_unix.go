//go:build !windows

package main

func runtimeIsWindows() bool { return false }

// windowsPath is a no-op outside Windows; POSIX paths need no conversion.
func windowsPath(p string) string { return p }
