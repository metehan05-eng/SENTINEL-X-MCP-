package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe to read while a goroutine is still writing
// into it. A plain bytes.Buffer is not: reading it from the test while the
// copying goroutine appends is a data race, and it is the test that is wrong,
// not the server.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// buildServer compiles the binary once for the tests that need a real process.
func buildServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sentinel-x")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

// A stdio MCP client signals the end of a session by closing stdin. If the
// server does not exit then, one process is leaked per session: they outlive the
// client, hold the binary open so the next install fails with "text file busy",
// and keep their process environment alive after the assessment is over.
func TestServeExitsWhenClientClosesStdin(t *testing.T) {
	bin := buildServer(t)

	cmd := exec.Command(bin, "serve")
	cmd.Env = append(os.Environ(), "SENTINELX_SCOPE_TARGETS=127.0.0.0/8")
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// A pipe that is closed immediately stands in for a client that connects
	// and disconnects without saying anything.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = pr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	pr.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve exited with %v; stderr:\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Error("serve did not exit within 10s of stdin closing")
	}
}

// The same, but after a real handshake, so the check covers the path a client
// actually takes rather than an immediate EOF.
func TestServeExitsAfterHandshake(t *testing.T) {
	bin := buildServer(t)

	cmd := exec.Command(bin, "serve")
	cmd.Env = append(os.Environ(), "SENTINELX_SCOPE_TARGETS=127.0.0.0/8")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	handshake := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1"},
		},
	}
	line, _ := json.Marshal(handshake)
	if _, err := stdin.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")); err != nil {
		t.Fatal(err)
	}

	// Wait for the initialize response so the server is genuinely running.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stdout.String(), `"serverInfo"`) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stdout.String(), `"serverInfo"`) {
		_ = cmd.Process.Kill()
		t.Fatalf("no initialize response; stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
	stdin.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve exited with %v; stderr:\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Error("serve did not exit within 10s of the client disconnecting")
	}
}

// An MCP client reads stderr as failure, and reports every line it finds there as
// an error. Logging the handshake and every tool call there made a healthy run
// look like a stream of errors, which is how a real one goes unnoticed. On a
// clean run stderr must be empty, and stdout must carry only JSON-RPC.
func TestServeIsSilentOnStderrWhenNotVerbose(t *testing.T) {
	bin := buildServer(t)

	cmd := exec.Command(bin, "serve")
	cmd.Env = append(os.Environ(),
		"SENTINELX_SCOPE_TARGETS=127.0.0.0/8",
		// Guard against the environment it inherits silently enabling the
		// diagnostics this test is asserting are absent.
		"SENTINELX_VERBOSE=false",
		"SENTINELX_VERBOSE=",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sentinelx_reverse_lookup","arguments":{"ip":"8.8.8.8"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sentinelx_reverse_lookup","arguments":{"ip":"127.0.0.1"}}}`,
	} {
		if _, err := stdin.Write([]byte(msg + "\n")); err != nil {
			break
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for strings.Count(stdout.String(), "\n") < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	stdin.Close()
	_ = cmd.Wait()

	if s := stderr.String(); s != "" {
		t.Errorf("stderr was not empty on a clean run:\n%s", s)
	}
	// Every stdout line must be a complete JSON-RPC message. A stray print
	// there corrupts the framing and the client drops the connection.
	for i, l := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var probe map[string]any
		if err := json.Unmarshal([]byte(l), &probe); err != nil {
			t.Errorf("stdout line %d is not JSON-RPC: %v\n%s", i+1, err, l)
		}
	}
}

// Verbose is the documented way to get the trace back, so it has to still work.
func TestServeVerboseStillLogs(t *testing.T) {
	bin := buildServer(t)

	cmd := exec.Command(bin, "serve")
	cmd.Env = append(os.Environ(),
		"SENTINELX_SCOPE_TARGETS=127.0.0.0/8",
		"SENTINELX_VERBOSE=true",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sentinelx_reverse_lookup","arguments":{"ip":"8.8.8.8"}}}`,
	} {
		if _, err := stdin.Write([]byte(msg + "\n")); err != nil {
			break
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(stderr.String(), "reverse_lookup") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	stdin.Close()
	_ = cmd.Wait()

	if !strings.Contains(stderr.String(), "reverse_lookup") {
		t.Errorf("verbose run did not log the tool call; stderr:\n%s", stderr.String())
	}
}
