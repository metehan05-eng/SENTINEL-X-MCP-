//go:build !windows

package utils

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child in its own process group so that a timeout
// can reap the whole tree, not just the direct child. A tool that forks a
// helper would otherwise survive the kill and keep the pipe open.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup terminates the child's entire process group with SIGKILL, after
// the polite SIGTERM grace period has already been attempted by
// exec.CommandContext.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = cmd.Process.Kill()
}

func osGetenvFallback(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
