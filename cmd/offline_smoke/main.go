//go:build smoke

// Offline-mode verification. Runs the real server with SENTINELX_OFFLINE=1 and
// asserts that every network-backed tool declines to make an outbound call
// while the purely local tools keep working.
//
// This is a policy guarantee, so it is checked against the built binary rather
// than against the packages: the environment is the thing under test.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResp struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func main() {
	bin := os.Getenv("SENTINELX_BIN")
	if bin == "" {
		bin = "./sentinel-x"
	}

	// Force the policy through the environment the operator would use.
	os.Setenv("SENTINELX_OFFLINE", "1")

	cmd := exec.Command(bin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fatal("stdin: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fatal("stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		fatal("start: %v", err)
	}
	br := bufio.NewReaderSize(stdout, 1<<20)
	enc := json.NewEncoder(stdin)

	id := 0
	call := func(method string, params any) rpcResp {
		id++
		if err := enc.Encode(rpcReq{JSONRPC: "2.0", ID: id, Method: method, Params: params}); err != nil {
			fatal("encode: %v", err)
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				fatal("read: %v", err)
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var r rpcResp
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				continue // a server log line, not a response
			}
			if r.ID == id {
				return r
			}
		}
	}

	call("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "offline-smoke", "version": "1"},
	})

	// Tools that must NOT reach the network while offline.
	blocked := []struct {
		tool string
		args map[string]any
	}{
		{"sentinelx_dns_lookup", map[string]any{"hostname": "example.com"}},
		{"sentinelx_dns_security_audit", map[string]any{"domain": "example.com"}},
		{"sentinelx_subdomain_discovery", map[string]any{"domain": "example.com"}},
		{"sentinelx_cve_lookup", map[string]any{"cve_id": "CVE-2021-44228"}},
		{"sentinelx_cve_search", map[string]any{"keyword": "log4j"}},
		{"sentinelx_version_risk", map[string]any{"product": "OpenSSH", "version": "8.2p1"}},
		{"sentinelx_http_headers", map[string]any{"url": "http://example.com"}},
		{"sentinelx_reverse_lookup", map[string]any{"ip": "127.0.0.1"}},
		{"sentinelx_whois_lookup", map[string]any{"target": "example.com"}},
	}

	fmt.Println("--- tools that must refuse network access while offline ---")
	failures := 0
	for _, c := range blocked {
		r := call("tools/call", map[string]any{"name": c.tool, "arguments": c.args})
		body := textOf(r.Result)
		offline := strings.Contains(strings.ToLower(body), "offline")
		leaked := looksLikeLiveData(body)
		status := "refused"
		if !offline {
			status = "DID NOT REFUSE"
			failures++
		}
		if leaked {
			status += " + LOOKS LIKE LIVE DATA"
			failures++
		}
		fmt.Printf("  %-32s %-22s %s\n", c.tool, status, snippet(body, 70))
	}

	// Local-only tools must keep working offline.
	fmt.Println("\n--- local tools that must still work offline ---")
	local := []struct {
		tool string
		args map[string]any
	}{
		{"sentinelx_host_posture_audit", map[string]any{}},
		{"sentinelx_permission_audit", map[string]any{"path": "/etc/passwd"}},
		{"sentinelx_sbom_inventory", map[string]any{"path": "/opt"}},
		{"sentinelx_binary_hardening", map[string]any{"path": "/bin/ls"}},
	}
	for _, c := range local {
		r := call("tools/call", map[string]any{"name": c.tool, "arguments": c.args})
		body := textOf(r.Result)
		var env map[string]any
		status := "ok"
		if err := json.Unmarshal([]byte(body), &env); err != nil {
			status = "BAD RESPONSE"
			failures++
		} else if _, present := env["error"]; present {
			status = "error: " + snippet(fmt.Sprint(env["error"]), 50)
			failures++
		}
		fmt.Printf("  %-32s %-22s\n", c.tool, status)
	}

	// In offline mode no dependency may have been correlated against the NVD.
	fmt.Println("\n--- dependency audit must report nothing as audited ---")
	r := call("tools/call", map[string]any{"name": "sentinelx_dependency_audit",
		"arguments": map[string]any{"path": "/opt", "audit": false}})
	if strings.Contains(textOf(r.Result), `"offline":false`) {
		fmt.Println("  FAIL: offline dependency audit claims it queried the NVD")
		failures++
	} else {
		fmt.Println("  ok  no NVD correlation claimed")
	}

	cmd.Process.Kill()
	cmd.Wait()

	fmt.Println()
	if failures > 0 {
		fmt.Printf("OFFLINE SMOKE FAILED (%d problems)\n", failures)
		os.Exit(1)
	}
	fmt.Println("OFFLINE SMOKE PASSED")
}

// looksLikeLiveData flags a response that carries signs of a real network
// answer, which would mean the offline guard did not hold.
func looksLikeLiveData(body string) bool {
	markers := []string{
		`"cves":[`,        // a populated NVD result set
		`"ttl":`,          // a dig answer
		`"records":`,      // whois
		`"subdomains":[{`, // crt.sh results
		`"server":`,       // a TLS or HTTP handshake
		`"status_code":2`, // an HTTP response
		`"audited":[`,     // correlated CVEs
	}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func textOf(raw json.RawMessage) string {
	var res struct {
		Content []struct{ Text string } `json:"content"`
	}
	if json.Unmarshal(raw, &res) != nil || len(res.Content) == 0 {
		return ""
	}
	return res.Content[0].Text
}

func snippet(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "offline-smoke: "+format+"\n", args...)
	os.Exit(1)
}
