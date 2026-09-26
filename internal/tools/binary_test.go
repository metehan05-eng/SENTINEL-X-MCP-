package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parser is exercised against the test binary itself, which is a real ELF
// produced by the Go toolchain. Asserting on a hand-written fixture would only
// prove the fixture matches the expectations.
func TestInspectELFOnRealBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate the test binary: %v", err)
	}

	rep, err := inspectBinary(self)
	if err != nil {
		t.Fatalf("inspectBinary on a real ELF: %v", err)
	}
	if rep.Format != "elf" {
		t.Fatalf("format = %q, want elf", rep.Format)
	}
	if rep.Arch == "" {
		t.Error("architecture should be reported")
	}
	if len(rep.Mitigations) == 0 {
		t.Fatal("no mitigations were evaluated")
	}

	// Whether the Go toolchain emits a PIE depends on the Go version and the
	// distribution's build configuration, so asserting a specific verdict here
	// would be testing the environment rather than the parser. What must hold
	// is that the verdict and the findings agree with each other.
	switch rep.Mitigations["position_independent"] {
	case "yes", "no", "unknown":
	default:
		t.Errorf("unexpected PIE verdict: %q", rep.Mitigations["position_independent"])
	}
	hasPIEFinding := false
	for _, f := range rep.Findings {
		if strings.Contains(f.Summary, "position-independent") {
			hasPIEFinding = true
		}
	}
	if rep.Mitigations["position_independent"] == "no" && !hasPIEFinding {
		t.Error("a non-PIE verdict must come with a finding saying so")
	}
	if rep.Mitigations["position_independent"] == "yes" && hasPIEFinding {
		t.Error("a PIE binary must not be reported as non-position-independent")
	}

	// The stack must be non-executable whatever the build config.
	if rep.Mitigations["non_executable_stack"] == "no (stack is executable)" {
		t.Error("the Go toolchain does not build with an executable stack; the flag parsing is wrong")
	}
	relro := rep.Mitigations["relro"]
	if relro != "full" && relro != "partial" && relro != "no" {
		t.Errorf("unexpected relro verdict: %q", relro)
	}
	if rep.TextRelocs {
		t.Error("a Go binary should not have text relocations")
	}
	// Findings must be populated and the verdict must be internally consistent.
	if len(rep.Findings) == 0 {
		t.Error("expected at least the informational mitigations as findings")
	}
	if rep.Hardened {
		// If the verdict says hardened, no high or medium finding may exist.
		for _, f := range rep.Findings {
			if f.Severity == "high" || f.Severity == "medium" {
				t.Errorf("Hardened=true contradicts finding %q (%s)", f.Summary, f.Severity)
			}
		}
	}
}

func TestInspectBinaryRejectsNonBinaries(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "notabin")
	if err := os.WriteFile(text, []byte("just some text, definitely not an ELF header"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBinary(text); err == nil {
		t.Error("a text file must not be reported as a binary")
	}

	// A file too short to carry magic bytes.
	tiny := filepath.Join(dir, "tiny")
	if err := os.WriteFile(tiny, []byte{0x01}, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBinary(tiny); err == nil {
		t.Error("a 1-byte file must not be reported as a binary")
	}
}

func TestCollectBinariesSkipsNoise(t *testing.T) {
	dir := t.TempDir()
	mk := func(rel string, mode os.FileMode) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("\x7fELF fake"), mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("app", 0o755)
	mk("sub/helper", 0o755)
	mk("data.txt", 0o644)           // not executable
	mk("node_modules/x/bin", 0o755) // skipped directory
	mk(".git/hooks/pre-commit", 0o755)

	files, truncated, err := collectBinaries(dir, true, 100)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("a small tree should not be truncated")
	}
	for _, f := range files {
		if filepath.Base(f) == "data.txt" {
			t.Error("a non-executable file should be skipped")
		}
		if filepath.Base(f) == "pre-commit" {
			t.Error(".git should be skipped")
		}
		if filepath.Base(f) == "bin" {
			t.Error("node_modules should be skipped")
		}
	}

	// Non-recursive must not descend.
	shallow, _, err := collectBinaries(dir, false, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range shallow {
		if filepath.Base(f) == "helper" {
			t.Error("non-recursive walk descended into a subdirectory")
		}
	}
}

func TestCollectBinariesRespectsLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 12; i++ {
		p := filepath.Join(dir, "f"+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte("\x7fELF"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files, truncated, err := collectBinaries(dir, false, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Errorf("want 5 files, got %d", len(files))
	}
	if !truncated {
		t.Error("hitting the limit must be reported as truncation, not silently passed off as complete")
	}
}
