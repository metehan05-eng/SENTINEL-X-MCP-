//go:build windows

package utils

import (
	"os"
	"os/exec"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) {
	// CREATE_NEW_PROCESS_GROUP; Job Objects would be the stronger choice but
	// are not wired up here. SENTINEL-X is developed and primarily deployed
	// on Linux/macOS hosts.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200}
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func osGetenvFallback(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
