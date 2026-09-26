package utils

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sentinel-x/sentinel-x/internal/config"
)

func testRunner(t *testing.T, mutate func(*config.Config)) *Runner {
	t.Helper()
	cfg := &config.Config{
		Timeouts: config.Timeouts{
			Recon: 5 * time.Second, Scan: 5 * time.Second, VulnQuery: 5 * time.Second,
			Audit: 5 * time.Second, HTTP: 5 * time.Second, Max: 10 * time.Second,
		},
		Policy: config.Policy{
			AllowedBinaries: []string{"sh", "sleep", "echo", "yes"},
			DeniedBinaries:  []string{"bash", "sudo", "curl"},
			MaxOutputBytes:  4096,
			MaxConcurrency:  2,
			RedactPatterns:  []string{`(?i)password\s*=\s*\S+`},
		},
	}
	cfg.Policy.DeniedArgPatterns = []string{
		`[;&|` + "`" + `$(){}<>]`,
		"[\n\r]",
	}
	cfg.Policy.BinaryArgDenylist = map[string][]string{
		"sleep": {`(?i)^--help$`},
	}
	if mutate != nil {
		mutate(cfg)
	}
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

func TestCheckArgsGlobalRules(t *testing.T) {
	r := testRunner(t, nil)
	// Shell metacharacters are refused everywhere. Arguments are passed as an
	// argv vector so these cannot execute, but their presence means the caller
	// is attempting to smuggle a command in.
	for _, bad := range [][]string{
		{"a; id"}, {"a && id"}, {"a | id"}, {"$(id)"}, {"`id`"}, {"a > /tmp/x"},
		{"a\nb"}, {"a\rb"},
	} {
		if err := r.CheckArgs("echo", bad); !errors.Is(err, ErrArgumentDenied) {
			t.Errorf("CheckArgs(echo, %q) = %v, want ErrArgumentDenied", bad, err)
		}
	}
	if err := r.CheckArgs("echo", []string{"-n", "hello world", "https://example.com"}); err != nil {
		t.Errorf("benign args rejected: %v", err)
	}
}

func TestCheckArgsPerBinaryScoping(t *testing.T) {
	r := testRunner(t, nil)
	// A rule scoped to one binary must not fire for another. This is the
	// property that lets `searchsploit -p` be refused while `nmap -p 1-1024`
	// is allowed.
	if err := r.CheckArgs("sleep", []string{"--help"}); !errors.Is(err, ErrArgumentDenied) {
		t.Errorf("the sleep rule should have fired: %v", err)
	}
	if err := r.CheckArgs("echo", []string{"--help"}); err != nil {
		t.Errorf("a sleep-scoped rule leaked onto echo: %v", err)
	}
}

func TestBinaryAllowAndDeny(t *testing.T) {
	r := testRunner(t, nil)

	if err := r.checkBinary("bash"); !errors.Is(err, ErrBinaryDenied) {
		t.Errorf("a denied binary should be refused, got %v", err)
	}
	if err := r.checkBinary("sudo"); !errors.Is(err, ErrBinaryDenied) {
		t.Errorf("a denied binary should be refused, got %v", err)
	}
	if err := r.checkBinary("nmap"); !errors.Is(err, ErrBinaryNotAllowed) {
		t.Errorf("a binary outside the allowlist should be refused, got %v", err)
	}
	if err := r.checkBinary(""); !errors.Is(err, ErrBinaryNotAllowed) {
		t.Errorf("an empty binary name should be refused, got %v", err)
	}
	// A path must not be a way to smuggle a different binary past the check.
	if err := r.checkBinary("/bin/sleep"); err != nil {
		t.Errorf("an absolute path to an allowed binary should resolve: %v", err)
	}
	if err := r.checkBinary("/bin/bash"); !errors.Is(err, ErrBinaryDenied) {
		t.Errorf("a path must not bypass the denylist: %v", err)
	}
}

func TestRunTimeoutIsEnforced(t *testing.T) {
	r := testRunner(t, nil)
	ctx := context.Background()

	start := time.Now()
	res, err := r.Run(ctx, Spec{Binary: "sleep", Args: []string{"30"}, Timeout: 300 * time.Millisecond})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run returned a hard error instead of a timed-out result: %v", err)
	}
	if !res.TimedOut {
		t.Error("TimedOut should be set")
	}
	if elapsed > 5*time.Second {
		t.Errorf("the timeout was not enforced: took %s", elapsed)
	}
	if res.Note == "" {
		t.Error("a timed-out result must explain itself in Note")
	}
}

func TestRunKillsTheProcessGroup(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not available")
	}
	// The script backgrounds a child and then waits. The child is a distinct
	// process, so it only dies if the whole process group is signalled — a
	// kill aimed at the direct child would leave it running.
	// The script is written to a file rather than passed as -c because the
	// runner (correctly) refuses shell metacharacters in argv.
	dir := t.TempDir()
	script := dir + "/forker.sh"
	const marker = "sentinel-x-orphan-marker"
	body := "#!/bin/sh\n" +
		"sleep 30 -- " + marker + "\n" +
		"sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	r := testRunner(t, nil)
	res, err := r.Run(context.Background(), Spec{
		Binary:  "sh",
		Args:    []string{script},
		Timeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.TimedOut {
		t.Fatal("expected the command to be reported as timed out")
	}

	// Give the kernel a moment to reap, then confirm no orphan survived.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !orphanExists(marker) {
			return // the group kill worked
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("a backgrounded child survived the timeout; the process group was not killed")
}

// orphanExists reports whether any live process still carries marker in its
// command line.
func orphanExists(marker string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue // the process exited between readdir and read
		}
		if strings.Contains(strings.ReplaceAll(string(b), "\x00", " "), marker) {
			return true
		}
	}
	return false
}

func TestOutputIsCapped(t *testing.T) {
	r := testRunner(t, nil)
	ctx := context.Background()

	// 5 MB of output against a 4 KB cap must be clipped, not buffered whole.
	res, err := r.Run(ctx, Spec{
		Binary:    "yes",
		Args:      []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		MaxOutput: 4096,
		Timeout:   3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Stdout) > 4096 {
		t.Errorf("stdout was %d bytes, want at most 4096", len(res.Stdout))
	}
	if !res.Truncated {
		t.Error("Truncated should be reported when the cap is hit")
	}
}

func TestSecretsAreRedactedFromResults(t *testing.T) {
	r := testRunner(t, nil)
	ctx := context.Background()

	res, err := r.Run(ctx, Spec{
		Binary:  "echo",
		Args:    []string{"db_password = hunter2xyz"},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(res.Stdout, "hunter2xyz") {
		t.Errorf("a secret reached the result unredacted: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, RedactorMask) {
		t.Errorf("expected the redaction mask in %q", res.Stdout)
	}
}

func TestNonZeroExitIsNotAnError(t *testing.T) {
	r := testRunner(t, nil)
	// Tools routinely encode findings in their exit status; that must be
	// reported in the result, not raised as a failure that hides the output.
	res, err := r.Run(context.Background(), Spec{
		Binary: "sh", Args: []string{"-c", "exit 3"}, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("a non-zero exit should not be an error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
	if res.OK {
		t.Error("OK should be false for a non-zero exit")
	}
}

func TestCapBufferNeverExceedsLimit(t *testing.T) {
	c := newCapBuffer(10)
	n, err := c.Write(make([]byte, 100))
	if err != nil || n != 100 {
		t.Errorf("Write must report a full write so the child never sees EPIPE: n=%d err=%v", n, err)
	}
	if len(c.String()) != 10 {
		t.Errorf("buffered %d bytes, want 10", len(c.String()))
	}
	if !c.Truncated() {
		t.Error("Truncated should be true")
	}
	// Further writes must be discarded, not appended.
	_, _ = c.Write([]byte("more"))
	if len(c.String()) != 10 {
		t.Errorf("buffer grew past its limit: %d", len(c.String()))
	}
}

func TestTruncateMarksTheCut(t *testing.T) {
	s := strings.Repeat("x", 5000)
	got := Truncate(s, 100)
	if len(got) >= len(s) {
		t.Errorf("Truncate did not shorten the string: %d bytes", len(got))
	}
	if !strings.HasPrefix(got, strings.Repeat("x", 100)) {
		t.Error("Truncate should keep the leading portion verbatim")
	}
	if !strings.Contains(got, "truncated") || !strings.Contains(got, "5000") {
		t.Errorf("a truncated string must state that it was cut and how much was lost, or the model cannot tell a clipped view from a complete one: %q", got)
	}
	// A string already within the limit is returned untouched.
	if short := Truncate("hello", 100); short != "hello" {
		t.Errorf("Truncate altered a short string: %q", short)
	}
}

func TestRedactorFoundDoesNotLeakTheSecret(t *testing.T) {
	r := NewRedactor([]string{`(?i)password\s*=\s*\S+`})
	hits := r.Found("password = hunter2")
	if len(hits) != 1 {
		t.Fatalf("expected one hit, got %v", hits)
	}
	if strings.Contains(strings.Join(hits, " "), "hunter2") {
		t.Error("Found must report the pattern, never the matched text")
	}
}
