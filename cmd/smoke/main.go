//go:build smoke

// Command smoke drives the SENTINEL-X stdio transport end to end: it performs
// the MCP handshake, lists the tools and invokes a representative sample of
// them, then checks that the safety policy actually refuses a hostile call.
//
// Run with:  go run -tags smoke ./cmd/smoke
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func main() {
	bin := os.Getenv("SENTINELX_BIN")
	if bin == "" {
		bin = "./sentinel-x"
	}

	cmd := exec.Command(bin)
	cmd.Stderr = os.Stderr
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		fatal("start: %v", err)
	}
	defer cmd.Process.Kill()

	in := bufio.NewReaderSize(stdout, 1<<20)
	id := 0

	send := func(method string, params any) rpc {
		id++
		p, _ := json.Marshal(params)
		line, _ := json.Marshal(rpc{JSONRPC: "2.0", ID: id, Method: method, Params: p})
		if _, err := stdin.Write(append(line, '\n')); err != nil {
			fatal("write: %v", err)
		}
		var r rpc
		dec := json.NewDecoder(in)
		if err := dec.Decode(&r); err != nil {
			fatal("read (method %s): %v", method, err)
		}
		return r
	}

	// --- handshake -------------------------------------------------------
	r := send("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "smoke", "version": "1"},
	})
	var init struct {
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
		Capabilities struct {
			Tools map[string]any `json:"tools"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(r.Result, &init); err != nil {
		fatal("parse initialize: %v", err)
	}
	fmt.Printf("initialize OK  server=%s/%s  tools_capability=%v\n",
		init.ServerInfo.Name, init.ServerInfo.Version, init.Capabilities.Tools != nil)
	if len(init.Instructions) == 0 {
		fatal("server advertised no instructions")
	}

	stdin.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))

	// --- tools/list ------------------------------------------------------
	r = send("tools/list", map[string]any{})
	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			InputSchema struct {
				Properties map[string]any `json:"properties"`
				Required   []string       `json:"required"`
			} `json:"inputSchema"`
			Annotations struct {
				ReadOnlyHint *bool `json:"readOnlyHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &list); err != nil {
		fatal("parse tools/list: %v", err)
	}
	fmt.Printf("tools/list OK  count=%d\n", len(list.Tools))
	if len(list.Tools) < 10 {
		fatal("expected at least 10 tools, got %d", len(list.Tools))
	}
	seen := map[string]bool{}
	for _, t := range list.Tools {
		seen[t.Name] = true
		if t.Annotations.ReadOnlyHint == nil || !*t.Annotations.ReadOnlyHint {
			fatal("tool %s is not annotated read-only", t.Name)
		}
		if t.Description == "" {
			fatal("tool %s has no description", t.Name)
		}
		if len(t.InputSchema.Properties) == 0 {
			fatal("tool %s has an empty input schema", t.Name)
		}
	}
	fmt.Printf("             all tools read-only-annotated, described, schema-bearing\n")

	// --- tool calls ------------------------------------------------------
	cases := []struct {
		name string
		args map[string]any
	}{
		{"sentinelx_dns_lookup", map[string]any{"hostname": "example.com", "record_type": "A"}},
		{"sentinelx_port_scan", map[string]any{"target": "127.0.0.1", "ports": "22,80", "scan_profile": "quick", "timeout_seconds": 60}},
		{"sentinelx_tls_audit", map[string]any{"target": "127.0.0.1", "ports": "443", "timeout_seconds": 40}},
		{"sentinelx_cve_lookup", map[string]any{"cve_id": "CVE-2021-44228"}},
		{"sentinelx_version_risk", map[string]any{"product": "OpenSSH", "version": "8.2p1"}},
		{"sentinelx_host_posture_audit", map[string]any{}},
		{"sentinelx_config_audit", map[string]any{"path": "/etc/ssh/sshd_config"}},
		{"sentinelx_secret_scan", map[string]any{"path": "/etc", "max_hits": 5}},
		{"sentinelx_permission_audit", map[string]any{"path": "/etc/passwd"}},
		{"sentinelx_reverse_lookup", map[string]any{"ip": "127.0.0.1"}},
		{"sentinelx_dns_security_audit", map[string]any{"domain": "example.com", "check_zone_transfer": false}},
		{"sentinelx_subdomain_discovery", map[string]any{"domain": "example.com", "limit": 10, "include_unresolved": false}},
		{"sentinelx_sbom_inventory", map[string]any{"path": "/opt"}},
		{"sentinelx_binary_hardening", map[string]any{"path": "/bin/ls"}},
		{"sentinelx_k8s_security_audit", map[string]any{}},
		{"sentinelx_log_threat_analysis", map[string]any{"path": "/var/log", "min_failures": 5}},
	}
	for _, c := range cases {
		if !seen[c.name] {
			fatal("tool %s missing from tools/list", c.name)
		}
		r = send("tools/call", map[string]any{"name": c.name, "arguments": c.args})
		var res struct {
			IsError bool `json:"isError"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(r.Result, &res); err != nil {
			fatal("parse result of %s: %v", c.name, err)
		}
		body := ""
		if len(res.Content) > 0 {
			body = res.Content[0].Text
		}
		// Every successful response must be a JSON envelope with our fields.
		var env map[string]any
		if err := json.Unmarshal([]byte(body), &env); err != nil {
			fatal("%s did not return JSON: %v (body=%.180s)", c.name, err, body)
		}
		status := "ok"
		if res.IsError {
			status = "tool-error"
		}
		if _, present := env["error"]; present {
			status = "policy/tool error: " + fmt.Sprint(env["error"])
		}
		fmt.Printf("call %-32s %-14s tool=%v scope=%v\n", c.name, status, env["tool"], env["scope_notice"] != nil)
	}

	// --- policy must refuse a hostile call --------------------------------
	bad := []struct {
		name string
		args map[string]any
	}{
		{"sentinelx_dns_lookup", map[string]any{"hostname": "example.com; rm -rf /"}},
		{"sentinelx_port_scan", map[string]any{"target": "127.0.0.1", "ports": "-sS --script vuln"}},
		{"sentinelx_config_audit", map[string]any{"path": "/etc/passwd/../../root/.ssh/id_rsa"}},
		{"sentinelx_cve_lookup", map[string]any{"cve_id": "../../etc/passwd"}},
		// The audit-root policy must hold for the new filesystem readers too,
		// including the symlink-escape shape.
		{"sentinelx_sbom_inventory", map[string]any{"path": "/root/.ssh"}},
		{"sentinelx_binary_hardening", map[string]any{"path": "/etc/../root/.ssh/id_rsa"}},
		{"sentinelx_k8s_security_audit", map[string]any{"path": "/root/.kube/config"}},
		{"sentinelx_log_threat_analysis", map[string]any{"path": "/etc/../root/.bash_history"}},
		{"sentinelx_dns_security_audit", map[string]any{"domain": "example.com; rm -rf /"}},
	}
	fmt.Println()
	for _, c := range bad {
		r = send("tools/call", map[string]any{"name": c.name, "arguments": c.args})
		var res struct {
			IsError bool                    `json:"isError"`
			Content []struct{ Text string } `json:"content"`
		}
		json.Unmarshal(r.Result, &res)
		msg := ""
		if len(res.Content) > 0 {
			msg = res.Content[0].Text
		}
		if len(msg) > 150 {
			msg = msg[:150] + "…"
		}
		refused := strings.Contains(msg, "policy") || strings.Contains(msg, "not a valid") ||
			strings.Contains(msg, "expected") || strings.Contains(msg, "required") ||
			strings.Contains(msg, "invalid")
		mark := "ok "
		if !refused {
			mark = "BAD"
		}
		fmt.Printf("%s refused %-28s %s\n", mark, c.name, msg)
	}

	// --- unknown tool -----------------------------------------------------
	r = send("tools/call", map[string]any{"name": "sentinelx_exploit", "arguments": map[string]any{}})
	if len(r.Error) == 0 {
		fatal("server accepted a call to a non-existent tool")
	}
	fmt.Printf("ok  refused unknown tool sentinelx_exploit\n")

	fmt.Println("\nSMOKE TEST PASSED")
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "SMOKE FAIL: "+format+"\n", a...)
	os.Exit(1)
}
