//go:build smoke

// Command live_smoke runs the parsers against live network output instead of a
// checked-in fixture.
//
// The two bugs it was written to catch — dig rejecting an unsupported option
// and the TLS parser silently dropping nmap's script block — both produced
// results that looked like plausible negative answers. Unit tests built from
// hand-written fixtures passed throughout, because the fixtures agreed with the
// parsers instead of with nmap. Any parser that has only ever been tested
// against invented input has not been tested.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const target = "example.com"

func main() {
	bin := os.Getenv("SENTINELX_BIN")
	if bin == "" {
		bin = "./sentinel-x"
	}
	fmt.Printf("Live parse check against %s (dig output, not a fixture)\n\n", target)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "serve")
	cmd.Env = append(os.Environ(), "SENTINELX_SCOPE_TARGETS="+target)
	// The server logs its own progress to stderr; a pipe that is never drained
	// fills up and blocks the process.
	cmd.Stderr = nil
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fail("stdin pipe", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fail("stdout pipe", err)
	}
	if err := cmd.Start(); err != nil {
		fail("start server", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	in := bufio.NewWriter(stdin)
	out := bufio.NewReaderSize(stdout, 1<<20)

	// Handshake before any tool call, otherwise the server may reject the
	// session before it is initialised.
	write(in, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "live_smoke", "version": "1"},
		},
	})
	if _, err := readReply(out); err != nil {
		fail("initialize", err)
	}
	write(in, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	id := 0
	call := func(tool string, args map[string]any) (map[string]any, error) {
		id++
		write(in, map[string]any{
			"jsonrpc": "2.0", "id": id, "method": "tools/call",
			"params": map[string]any{"name": tool, "arguments": args},
		})
		env, err := readReply(out)
		if err != nil {
			return nil, err
		}
		if e, bad := env["error"]; bad {
			return nil, fmt.Errorf("rpc error: %v", e)
		}
		// Surface a tool-level failure here rather than in each branch. A tool
		// that reports isError carries its reason in the payload; reading
		// structured fields off it anyway yields confident zeros, which is how
		// a broken tool looks like a clean result.
		if msg := stringOf(dataMap(env)["error"]); msg != "" {
			return nil, fmt.Errorf("tool reported: %s", truncate(msg, 300))
		}
		return env, nil
	}

	problems := 0
	check := func(name string, ok bool, detail string) {
		if ok {
			fmt.Printf("  %-44s ok   %s\n", name, detail)
			return
		}
		fmt.Printf("  %-44s FAIL %s\n", name, detail)
		problems++
	}

	// Every record type the tool claims to support, queried against a name that
	// is known to answer. A parser that returns nothing here is broken; a
	// parser that returns nothing for CAA is reporting a fact about the target.
	for _, tc := range []struct {
		rt    string
		want  int
		hard  bool
		notes string
	}{
		{"NS", 2, true, ""},
		{"A", 2, true, ""},
		{"AAAA", 2, true, ""},
		{"MX", 1, true, ""},
		{"TXT", 2, true, ""},
		{"SOA", 1, true, ""},
		{"CAA", 0, false, "informational: example.com publishes none"},
	} {
		data, err := call("sentinelx_dns_lookup", map[string]any{
			"hostname": target, "record_type": tc.rt,
		})
		if err != nil {
			check("dns_lookup "+tc.rt, false, err.Error())
			continue
		}
		d := dataMap(data)
		recs := sliceOf(d["records"])
		detail := fmt.Sprintf("%d record(s)", len(recs))
		if n := len(sliceOf(d["warnings"])); n > 0 {
			detail += fmt.Sprintf(", %d warning(s)", n)
		}
		if tc.hard {
			check("dns_lookup "+tc.rt, len(recs) >= tc.want, detail)
		} else {
			check("dns_lookup "+tc.rt+" (informational)", true, detail)
		}
		if tc.hard && len(recs) < tc.want {
			if raw := stringOf(d["raw"]); raw != "" {
				fmt.Printf("      raw: %s\n", truncate(raw, 400))
			}
		}
	}

	// The certificate fields are what an operator acts on, so they are checked
	// structurally rather than by counting entries.
	td, err := call("sentinelx_tls_audit", map[string]any{"target": target, "ports": "443"})
	if err != nil {
		check("tls_audit parsed the endpoint", false, err.Error())
	} else {
		d := dataMap(td)
		certs := mapSlice(d["certificates"])
		suites := sliceOf(d["cipher_suites"])
		protos := sliceOf(d["protocols"])
		detail := fmt.Sprintf("cert=%d suite=%d protocol=%d", len(certs), len(suites), len(protos))
		ok := len(certs) > 0 && len(suites) > 0 && len(protos) > 0
		if ok {
			c := certs[0]
			sub, _ := c["subject"].(string)
			iss, _ := c["issuer"].(string)
			na, _ := c["not_after"].(string)
			ok = sub != "" && strings.Contains(sub, "example.com") && iss != "" && na != ""
			detail += fmt.Sprintf(", subject=%q", sub)
			if na != "" {
				detail += fmt.Sprintf(", not_after=%s", na)
			}
		}
		check("tls_audit parsed the endpoint", ok, detail)
		if !ok {
			if raw := stringOf(d["raw_excerpt"]); raw != "" {
				fmt.Printf("      raw excerpt:\n%s\n", indent(truncate(raw, 1200)))
			} else {
				fmt.Printf("      raw excerpt: (empty)\n")
			}
		}
		for _, f := range findingsOf(d) {
			fmt.Printf("      finding [%s] %s\n", stringOf(f["severity"]), stringOf(f["summary"]))
		}
	}

	hd, err := call("sentinelx_http_headers", map[string]any{"url": "https://" + target})
	if err != nil {
		check("http_headers parsed the response", false, err.Error())
	} else {
		d := dataMap(hd)
		status, _ := d["status"].(string)
		// headers is a JSON object, not an array, so it has to be read as a
		// map or the count is always zero.
		hdrs := mapOf(d["headers"])
		detail := fmt.Sprintf("status=%q header(s)=%d", status, len(hdrs))
		// Status carries the whole status line, which for a modern endpoint is
		// "HTTP/2 206" rather than "200 OK": the tool requests bytes 0-4095
		// with --range, so 206 is the expected success code. The status line
		// is therefore split and the code checked, not the leading token.
		code := statusCode(status)
		check("http_headers parsed the response", code >= 200 && code < 400, detail+fmt.Sprintf(" code=%d", code))
		if srv, _ := hdrs["Server"].(string); srv != "" {
			fmt.Printf("      server: %s\n", srv)
		}
	}

	da, err := call("sentinelx_dns_security_audit", map[string]any{"domain": target})
	if err != nil {
		check("dns_security_audit produced a grade", false, err.Error())
	} else {
		d := dataMap(da)
		grade := stringOf(d["grade"])
		checks := sliceOf(d["checks"])
		ns := sliceOf(d["nameservers"])
		detail := fmt.Sprintf("grade=%s checks=%d ns=%d", grade, len(checks), len(ns))
		check("dns_security_audit produced a grade", grade != "" && len(checks) > 0, detail)
	}

	fmt.Println()
	if problems > 0 {
		fmt.Printf("LIVE PARSE CHECK FAILED (%d problems)\n", problems)
		os.Exit(1)
	}
	fmt.Println("LIVE PARSE CHECK PASSED")
}

func write(w *bufio.Writer, v any) {
	b, _ := json.Marshal(v)
	_, _ = w.Write(append(b, '\n'))
	_ = w.Flush()
}

// readReply reads newline-delimited JSON until it finds a response, skipping the
// server's progress notifications.
func readReply(r *bufio.Reader) (map[string]any, error) {
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			if len(line) == 0 {
				return nil, err
			}
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			if err != nil {
				return nil, err
			}
			continue
		}
		var env map[string]any
		if json.Unmarshal(line, &env) != nil {
			if err != nil {
				return nil, err
			}
			continue
		}
		if _, ok := env["id"]; ok {
			return env, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func fail(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

// dataMap unwraps the MCP content envelope into the tool's own data object.
//
// mcp-go wraps every tool result as
//
//	{"result": {"content": [{"type": "text", "text": "{...tool json...}"}]}}
//
// so the payload is JSON-encoded text inside a content array. Treating
// "content" as a string, or skipping the array hop, silently yields an empty map
// and every assertion below then reports a clean-looking zero.
func dataMap(env map[string]any) map[string]any {
	res, _ := env["result"].(map[string]any)
	if res == nil {
		return map[string]any{}
	}
	if err, _ := res["isError"].(bool); err {
		if txt := contentText(res); txt != "" {
			return map[string]any{"error": txt}
		}
	}
	if txt := contentText(res); txt != "" {
		var inner map[string]any
		if json.Unmarshal([]byte(txt), &inner) == nil {
			if d, ok := inner["data"].(map[string]any); ok {
				return d
			}
		}
	}
	if d, ok := res["data"].(map[string]any); ok {
		return d
	}
	return map[string]any{}
}

// contentText concatenates the text blocks of an MCP tool result.
func contentText(res map[string]any) string {
	var sb strings.Builder
	for _, block := range sliceOf(res["content"]) {
		m, ok := block.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["text"].(string); t != "" {
			sb.WriteString(t)
		}
	}
	return strings.TrimSpace(sb.String())
}

func sliceOf(v any) []any { s, _ := v.([]any); return s }
func mapSlice(v any) []map[string]any {
	raw := sliceOf(v)
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
func mapOf(v any) map[string]any                   { m, _ := v.(map[string]any); return m }
func findingsOf(d map[string]any) []map[string]any { return mapSlice(d["findings"]) }
func stringOf(v any) string                        { s, _ := v.(string); return s }

// statusCode pulls the numeric code out of a status line such as
// "HTTP/1.1 200 OK" or "HTTP/2 206".
func statusCode(line string) int {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return 0
	}
	return n
}
func indent(s string) string {
	var sb strings.Builder
	for _, l := range strings.Split(s, "\n") {
		sb.WriteString("        " + l + "\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
