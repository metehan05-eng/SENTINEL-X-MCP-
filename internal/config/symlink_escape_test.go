package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditPathAllowedResistsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	// A "sensitive" dir outside the roots, reachable only through a symlink.
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "id_rsa"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(root, "allowed")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(allowed, "pivot")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	c := &Config{AuditRoots: []string{allowed}}
	escape := filepath.Join(allowed, "pivot", "id_rsa")
	if ok, why := c.AuditPathAllowed(escape); ok {
		t.Fatalf("SECURITY: symlink escape permitted: %s", why)
	}
	if ok, _ := c.AuditPathAllowed(filepath.Join(allowed, "pivot")); ok {
		t.Error("symlinked directory itself must be refused too")
	}
}
