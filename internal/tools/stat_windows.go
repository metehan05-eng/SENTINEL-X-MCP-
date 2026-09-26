//go:build windows

package tools

import "os"

func fileUID(os.FileInfo) (int, bool) { return 0, false }
func fileGID(os.FileInfo) (int, bool) { return 0, false }
