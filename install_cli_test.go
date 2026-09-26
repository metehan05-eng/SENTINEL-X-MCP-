package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Go's flag package stops at the first non-flag argument, so without this
// reordering `sentinel-x install opencode -env K=V` would report
// "unknown client \"-env\"".
func TestReorderArgsPullsFlagsAheadOfPositionals(t *testing.T) {
	valueFlags := map[string]bool{"-client": true, "-path": true, "-env": true}
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			"flag after positional",
			[]string{"opencode", "-env", "K=V"},
			[]string{"-env", "K=V", "opencode"},
		},
		{
			"equals form needs no lookahead",
			[]string{"opencode", "-env=K=V"},
			[]string{"-env=K=V", "opencode"},
		},
		{
			"boolean flag keeps its position",
			[]string{"claude", "opencode", "--dry-run"},
			[]string{"--dry-run", "claude", "opencode"},
		},
		{
			"value flag with equals, bool, value flag with space",
			[]string{"cursor", "--dry-run", "-client", "opencode"},
			[]string{"--dry-run", "-client", "opencode", "cursor"},
		},
		{
			// The flag package accepts both spellings, and the double-dash form
			// is what people actually type. Keying the lookup on the single-dash
			// form alone sent the value through as a positional argument, which
			// then failed as "unknown client --env".
			"double dash value flag keeps its value",
			[]string{"cursor", "--env", "SENTINELX_SCOPE_TARGETS=10.0.0.5", "--dry-run"},
			[]string{"--env", "SENTINELX_SCOPE_TARGETS=10.0.0.5", "--dry-run", "cursor"},
		},
		{
			"triple dash value flag is still a value flag",
			[]string{"opencode", "---client", "cursor"},
			[]string{"---client", "cursor", "opencode"},
		},
		{
			"double dash ends flag parsing",
			[]string{"--", "-not-a-flag", "opencode"},
			[]string{"-not-a-flag", "opencode"},
		},
		{
			"already ordered",
			[]string{"-dry-run", "opencode"},
			[]string{"-dry-run", "opencode"},
		},
		{
			"empty",
			nil,
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reorderArgs(c.in, valueFlags)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("reorderArgs(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// A value flag at the end with nothing after it must not panic.
func TestReorderArgsTrailingValueFlag(t *testing.T) {
	got := reorderArgs([]string{"opencode", "-env"}, map[string]bool{"-env": true})
	if want := []string{"-env", "opencode"}; !reflect.DeepEqual(got, want) {
		t.Errorf("reorderArgs = %v, want %v", got, want)
	}
}

func TestParseEnvFlags(t *testing.T) {
	env, err := parseEnvFlags(multiFlag{"A=1", "B=two=three"})
	if err != nil {
		t.Fatal(err)
	}
	if env["A"] != "1" || env["B"] != "two=three" {
		t.Errorf("env = %v; a value containing '=' must survive", env)
	}

	for _, bad := range []string{"noequals", "=novalue"} {
		if _, err := parseEnvFlags(multiFlag{bad}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}

	// No flags means no environment, not an empty map that would be written.
	env, err = parseEnvFlags(nil)
	if err != nil || env != nil {
		t.Errorf("parseEnvFlags(nil) = %v, %v; want nil, nil", env, err)
	}
}

func TestSelectClients(t *testing.T) {
	// An explicit name resolves regardless of detection.
	got, err := selectClients([]string{"OpenCode"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "opencode" {
		t.Errorf("selectClients = %v, want [opencode]", got)
	}

	// Several at once.
	got, err = selectClients([]string{"claude", "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("selectClients = %v, want 2 clients", got)
	}

	if _, err := selectClients([]string{"vscode"}); err == nil {
		t.Error("an unknown client must be an error, not a silent skip")
	}
}

// A relative path would break the moment a GUI client starts the server from
// a different working directory.
func TestBinaryPathIsAbsolute(t *testing.T) {
	got, err := binaryPath("")
	if err != nil {
		t.Fatal(err)
	}
	if !isAbs(got) {
		t.Errorf("binaryPath() = %q, want an absolute path", got)
	}

	got, err = binaryPath("./sentinel-x")
	if err != nil {
		t.Fatal(err)
	}
	if !isAbs(got) {
		t.Errorf("binaryPath(./sentinel-x) = %q, want an absolute path", got)
	}

	if _, err := binaryPath("/definitely/not/here/sentinel-x"); err == nil {
		t.Error("registering a non-existent binary must fail")
	}
	if _, err := binaryPath(t.TempDir()); err == nil {
		t.Error("registering a directory must fail")
	}
}

func isAbs(p string) bool { return p != "" && (p[0] == '/' || p[0] == '\\') }

// A bare command name is kept verbatim so the client resolves it through PATH.
// That is what makes a config portable: recording an absolute path pins it to
// the account and checkout location of the machine that installed it.
func TestBinaryPathKeepsBareCommandName(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, ServerCommandName)
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	got, err := binaryPath(ServerCommandName)
	if err != nil {
		t.Fatalf("binaryPath(%q) returned an error: %v", ServerCommandName, err)
	}
	if got != ServerCommandName {
		t.Errorf("binaryPath = %q, want the bare name %q", got, ServerCommandName)
	}
}

// A name that is not on PATH must fail at install time, not silently inside the
// client where the failure looks like a broken server rather than a typo.
func TestBinaryPathRejectsBareNameNotOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := binaryPath(ServerCommandName); err == nil {
		t.Errorf("binaryPath accepted %q with an empty PATH", ServerCommandName)
	}
}

// A relative path with a separator is still a path, and must be resolved and
// checked rather than treated as a command name.
func TestBinaryPathStillResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sx"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := binaryPath(filepath.Join(dir, "sx"))
	if err != nil {
		t.Fatalf("binaryPath returned an error: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("binaryPath = %q, want an absolute path", got)
	}
	if _, err := binaryPath(filepath.Join(dir, "missing")); err == nil {
		t.Error("binaryPath accepted a path that does not exist")
	}
	if _, err := binaryPath(dir); err == nil {
		t.Error("binaryPath accepted a directory")
	}
}
