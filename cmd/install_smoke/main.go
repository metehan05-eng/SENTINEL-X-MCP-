//go:build smoke

// Proves the installer produces a configuration each client can actually
// consume: the file is read back with the same reader the client would use,
// the recorded command is executed, and a real MCP handshake and tools/list
// must succeed.
//
// Checking that the JSON was written is not enough — the failure mode this
// guards against is a well-formed file in the wrong dialect, which the client
// accepts at the JSON level and then refuses to start from.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentinel-x/sentinel-x/internal/install"
)

func main() {
	bin := os.Getenv("SENTINELX_BIN")
	if bin == "" {
		bin = "./sentinel-x"
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		fatal("resolving %s: %v", bin, err)
	}

	// Every client is forced, so the test does not depend on which apps happen
	// to be installed on the machine running it.
	clients := []install.Client{install.ClaudeDesktop, install.Cursor, install.OpenCode}
	home, err := os.MkdirTemp("", "sentinel-x-home-")
	if err != nil {
		fatal("temp home: %v", err)
	}
	defer os.RemoveAll(home)
	// Point the installers at the sandbox for every client.
	os.Setenv("HOME", home)
	os.Unsetenv("XDG_CONFIG_HOME")

	fmt.Printf("sandbox HOME=%s\n\n", home)
	failures := 0

	for _, c := range clients {
		path, err := c.Path()
		if err != nil {
			fmt.Printf("%-9s SKIP: %v\n", c, err)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fatal("mkdir: %v", err)
		}
		// Seed a neighbouring entry that must survive the write.
		if err := seedExistingEntry(path, c); err != nil {
			fatal("seed %s: %v", path, err)
		}

		run := exec.Command(abs, "install", string(c), "-env", "SENTINELX_VERBOSE=false")
		run.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME=")
		if out, err := run.CombinedOutput(); err != nil {
			fmt.Printf("%-9s INSTALL FAILED: %v\n%s", c, err, out)
			failures++
			continue
		}

		if err := verifyRegistration(path, c, abs); err != nil {
			fmt.Printf("%-9s FAILED: %v\n", c, err)
			failures++
			continue
		}

		// The decisive check: run the command the client would run.
		cmd, env, err := readCommandForClient(path, c)
		if err != nil {
			fmt.Printf("%-9s FAILED to read back: %v\n", c, err)
			failures++
			continue
		}
		if err := handshake(cmd, env); err != nil {
			fmt.Printf("%-9s FAILED to start: %v\n", c, err)
			failures++
			continue
		}
		fmt.Printf("%-9s ok  %s\n", c, strings.TrimPrefix(path, home))
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("INSTALL SMOKE FAILED (%d problems)\n", failures)
		os.Exit(1)
	}
	fmt.Println("INSTALL SMOKE PASSED — all three clients start the server")
}

// seedExistingEntry writes a config that already contains a foreign server and
// an unrelated setting, so the install is proven non-destructive.
func seedExistingEntry(path string, c install.Client) error {
	var doc map[string]any
	if c == install.OpenCode {
		doc = map[string]any{
			"model": "anthropic/claude-sonnet-4-6",
			"mcp": map[string]any{
				"github": map[string]any{"type": "remote", "url": "https://example.test/mcp"},
			},
		}
	} else {
		doc = map[string]any{
			"mcpServers": map[string]any{
				"filesystem": map[string]any{"command": "/usr/bin/npx"},
			},
			"unrelatedSetting": "must survive",
		}
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(blob, '\n'), 0o600)
}

// verifyRegistration re-reads the written file through the installer's own
// parser and asserts the entry exists in the client's dialect and that the
// neighbouring content survived.
func verifyRegistration(path string, c install.Client, wantBin string) error {
	cfg, err := install.ReadConfig(path)
	if err != nil {
		return fmt.Errorf("written config no longer parses: %w", err)
	}
	servers, err := install.ServersFor(cfg, c)
	if err != nil {
		return err
	}
	raw, ok := servers[install.ServerName]
	if !ok {
		return fmt.Errorf("no %q entry under %q", install.ServerName, c.ConfigKey())
	}
	var entry map[string]any
	if err := json.Unmarshal(raw, &entry); err != nil {
		return fmt.Errorf("entry is not an object: %w", err)
	}

	if c == install.OpenCode {
		if entry["type"] != "local" {
			return fmt.Errorf(`entry type = %v, want "local"`, entry["type"])
		}
		if _, present := entry["env"]; present {
			return fmt.Errorf(`entry has "env", which OpenCode rejects`)
		}
		if _, present := entry["environment"]; !present {
			return fmt.Errorf(`entry has no "environment" key`)
		}
	} else {
		if _, present := entry["environment"]; present {
			return fmt.Errorf(`entry has "environment", which is OpenCode-only`)
		}
	}

	// The neighbouring entry and setting must be intact.
	if c == install.OpenCode {
		if _, present := servers["github"]; !present {
			return fmt.Errorf("the pre-existing github server was destroyed")
		}
		if string(cfg["model"]) == "" {
			return fmt.Errorf(`the "model" setting was destroyed`)
		}
	} else {
		if _, present := servers["filesystem"]; !present {
			return fmt.Errorf("the pre-existing filesystem server was destroyed")
		}
		if string(cfg["unrelatedSetting"]) != `"must survive"` {
			return fmt.Errorf("an unrelated setting was destroyed")
		}
	}
	return nil
}

// readCommandForClient extracts exactly the argv and environment the client
// would use, in that client's dialect.
func readCommandForClient(path string, c install.Client) ([]string, []string, error) {
	cfg, err := install.ReadConfig(path)
	if err != nil {
		return nil, nil, err
	}
	servers, _ := install.ServersFor(cfg, c)
	raw, ok := servers[install.ServerName]
	if !ok {
		return nil, nil, fmt.Errorf("no entry")
	}
	var entry map[string]any
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, nil, err
	}
	var argv []string
	var env []string

	if c == install.OpenCode {
		cmd, ok := entry["command"].([]any)
		if !ok {
			return nil, nil, fmt.Errorf(`OpenCode "command" must be an array, got %T`, entry["command"])
		}
		for _, a := range cmd {
			s, ok := a.(string)
			if !ok {
				return nil, nil, fmt.Errorf("command array holds a %T", a)
			}
			argv = append(argv, s)
		}
		if e, ok := entry["environment"].(map[string]any); ok {
			for k, v := range e {
				env = append(env, k+"="+fmt.Sprint(v))
			}
		}
	} else {
		s, ok := entry["command"].(string)
		if !ok {
			return nil, nil, fmt.Errorf(`"command" must be a string, got %T`, entry["command"])
		}
		argv = append(argv, s)
		for _, a := range asAnySlice(entry["args"]) {
			argv = append(argv, fmt.Sprint(a))
		}
		if e, ok := entry["env"].(map[string]any); ok {
			for k, v := range e {
				env = append(env, k+"="+fmt.Sprint(v))
			}
		}
	}
	if len(argv) == 0 {
		return nil, nil, fmt.Errorf("entry has no command")
	}
	return argv, env, nil
}

func asAnySlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// handshake runs the registered command and requires a full MCP initialize and
// tools/list exchange to succeed.
func handshake(argv []string, env []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot execute %s: %w", argv[0], err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	enc := json.NewEncoder(stdin)
	br := bufio.NewReaderSize(stdout, 1<<20)

	type req struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}
	type resp struct {
		ID     int `json:"id"`
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			Tools           []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	read := func(id int) (resp, error) {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			line, err := br.ReadString('\n')
			if err != nil {
				return resp{}, fmt.Errorf("reading response: %w", err)
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var r resp
			if json.Unmarshal([]byte(line), &r) != nil {
				continue // a log line
			}
			if r.ID == id {
				return r, nil
			}
		}
		return resp{}, fmt.Errorf("timed out waiting for response %d", id)
	}

	if err := enc.Encode(req{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "install-smoke", "version": "1"},
	}}); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	init, err := read(1)
	if err != nil {
		return err
	}
	if init.Error != nil {
		return fmt.Errorf("initialize failed: %s", init.Error.Message)
	}

	if err := enc.Encode(req{JSONRPC: "2.0", Method: "notifications/initialized"}); err != nil {
		return err
	}
	if err := enc.Encode(req{JSONRPC: "2.0", ID: 2, Method: "tools/list", Params: map[string]any{}}); err != nil {
		return fmt.Errorf("tools/list: %w", err)
	}
	list, err := read(2)
	if err != nil {
		return err
	}
	if list.Error != nil {
		return fmt.Errorf("tools/list failed: %s", list.Error.Message)
	}
	if len(list.Result.Tools) == 0 {
		return fmt.Errorf("tools/list returned no tools")
	}
	fmt.Printf("         %d tools, %s\n", len(list.Result.Tools), init.Result.ProtocolVersion)
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "install-smoke: "+format+"\n", args...)
	os.Exit(1)
}
