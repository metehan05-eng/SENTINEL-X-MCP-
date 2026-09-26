//go:build !windows

package tools

import (
	"os"
	"syscall"
)

// fileUID returns the owning UID. os.FileInfo.Sys() is *syscall.Stat_t on
// Unix; the assertion keeps this compiling on platforms that differ.
func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

func fileGID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}
