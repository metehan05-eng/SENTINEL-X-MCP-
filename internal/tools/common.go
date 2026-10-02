// Package tools contains the SENTINEL-X MCP tool modules.
//
// Every tool in this package is strictly observational: it discovers, queries
// or reports. Nothing here can modify a target system, write to a filesystem,
// or execute a payload. The package-level Registry wires them into the MCP
// server.
package tools

import (
	"context"
	"encoding/json"

	"errors"
	"fmt"
	"github.com/sentinel-x/sentinel-x/internal/cache"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/sentinel-x/sentinel-x/internal/config"
	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// Handler is the signature every SENTINEL-X tool implements. It is an alias
// rather than a distinct type so handlers can be handed straight to
// server.MCPServer.AddTool without a conversion at every registration point.
type Handler = server.ToolHandlerFunc

// Deps is the shared dependency set handed to every module.
type Deps struct {
	Cfg    *config.Config
	Runner *utils.Runner

	// Cache is passed here rather than hung off Config because Config is a
	// memoised singleton: a runtime field on it is shared mutable state that
	// any holder can rewrite.
	Cache *cache.Cache
}

// Registry maps tool names to their handler.
type Registry map[string]Handler

// All builds the complete tool registry for the server.
//
// Handlers are wrapped in the result cache here rather than inside each tool,
// so a tool added later is cached without anyone remembering. Tools that send
// non-idempotent traffic are excluded: serving a cached "active scan" reads as
// a fresh result, and an active result is the one thing in this server a
// reader must be able to trust is current.
func All(d Deps) Registry {
	r := Registry{}
	for _, t := range AllTools(d) {
		if uncacheable[t.Tool.Name] {
			r[t.Tool.Name] = t.Handler
			continue
		}
		r[t.Tool.Name] = cachedHandler(d, t)
	}
	return r
}

// uncacheable lists tools whose results must never be served from cache.
//
// Three of these are not about staleness at all but about having side effects,
// which a cache cannot reproduce: setup installs packages, baseline writes a
// file, and sarif_report may write one. Replaying "wrote /tmp/report.sarif"
// without touching the disk hands back a success for an action that did not
// happen, which is worse than a slow call.
var uncacheable = map[string]bool{
	"sentinelx_nuclei_scan": true,
	"sentinelx_xss_probe":   true,
	"sentinelx_setup":       true,
	// A live view of the machine's sockets goes stale within seconds, so a
	// memoised copy would be wrong by the time anyone read it.
	"sentinelx_traffic_audit": true,
	"sentinelx_baseline":      true,
	"sentinelx_sarif_report":  true,
}

// cachedHandler memoises a tool's successful response.
func cachedHandler(d Deps, t Tool) Handler {
	inner := t.Handler
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		store := d.Cache
		if store == nil {
			return inner(ctx, req)
		}
		args := req.GetArguments()
		if e, hit, age := store.Get(t.Tool.Name, args); hit {
			// The cached envelope is replayed with the age spliced in, so the
			// disclosure sits at the top level where a model will read it
			// rather than buried in the data.
			var env map[string]any
			if json.Unmarshal(e.Result, &env) == nil {
				n := cache.NewNotice(true, age)
				env["cache_hit"] = n.CacheHit
				env["cache_age_ms"] = n.CacheAgeMS
				env["cache_note"] = n.Note
				// The observation time is left alone. Rewriting it to now()
				// would make a ten-minute-old scan look like it just ran, and
				// the age above it is easy for a model to drop from its
				// summary.
				env["duration_ms"] = 0
				merged, err := mcp.NewToolResultJSON(env)
				if err == nil {
					return merged, nil
				}
			}
		}
		res, err := inner(ctx, req)
		if err != nil || res == nil || res.IsError {
			return res, err
		}
		if len(res.Content) == 0 {
			return res, nil
		}
		if txt, isTxt := res.Content[0].(mcp.TextContent); isTxt {
			if json.Valid([]byte(txt.Text)) {
				store.Put(t.Tool.Name, args, json.RawMessage(txt.Text))
			}
		}
		return res, nil
	}
}

// AllTools returns every tool with its full descriptor. All collapses this to
// name/handler pairs, but `sentinel-x doctor` needs the metadata too: a tool it
// cannot report as unusable is exactly the failure it exists to prevent.
func AllTools(d Deps) []Tool {
	out := []Tool{}
	for _, set := range toolSets(d) {
		out = append(out, set...)
	}
	return out
}

// Tool pairs a schema with its handler.
type Tool struct {
	Tool    mcp.Tool
	Handler Handler

	// Requires lists the external binaries a tool needs. These are candidates,
	// not hard requirements: a tool passes several to requireBinary and runs on
	// whichever resolves first, so a tool is usable when any one is present.
	Requires []string
}

// ---------------------------------------------------------------------------
// Result helpers
//
// All tool output is returned as JSON. A model parses JSON far more reliably
// than it parses a wall of nmap text, and the structure makes the evidence
// separable from the interpretation.
// ---------------------------------------------------------------------------

// Envelope is the top-level shape of every SENTINEL-X response.
type Envelope[T any] struct {
	Tool        string    `json:"tool"`
	Target      string    `json:"target,omitempty"`
	Timestamp   string    `json:"timestamp"`
	DurationMS  int64     `json:"duration_ms"`
	ScopeNotice string    `json:"scope_notice,omitempty"`
	Redacted    bool      `json:"secrets_redacted"`
	Warnings    []string  `json:"warnings,omitempty"`
	Command     *CmdTrace `json:"command,omitempty"`
	Data        T         `json:"data"`
}

// CmdTrace records the exact invocation, so any finding is reproducible and
// auditable.
type CmdTrace struct {
	Binary    string   `json:"binary"`
	Args      []string `json:"args"`
	ExitCode  int      `json:"exit_code"`
	TimedOut  bool     `json:"timed_out"`
	Truncated bool     `json:"truncated"`
}

func traceFrom(res *utils.Result) *CmdTrace {
	if res == nil {
		return nil
	}
	return &CmdTrace{
		Binary:    res.Command,
		Args:      res.Args,
		ExitCode:  res.ExitCode,
		TimedOut:  res.TimedOut,
		Truncated: res.Truncated,
	}
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// ok renders a successful response. The typed call keeps `data` precisely
// shaped in the JSON schema for the model.
func ok[T any](d Deps, tool, target string, start time.Time, res *utils.Result, data T, warnings ...string) (*mcp.CallToolResult, error) {
	env := Envelope[T]{
		Tool:       tool,
		Target:     target,
		Timestamp:  now(),
		DurationMS: time.Since(start).Milliseconds(),
		Redacted:   true,
		Command:    traceFrom(res),
		Data:       data,
		Warnings:   warnings,
	}
	if !d.Cfg.Policy.EnforceScope {
		env.ScopeNotice = config.ScopeWarning
	}
	env.Warnings = append(env.Warnings, execWarnings(res)...)
	env.Warnings = dedupe(env.Warnings)

	out, err := mcp.NewToolResultJSON(env)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("failed to encode result", err), nil
	}
	return out, nil
}

func execWarnings(res *utils.Result) []string {
	if res == nil {
		return nil
	}
	var w []string
	if res.TimedOut {
		w = append(w, "the command hit its timeout and was terminated; output is partial")
	}
	if res.Truncated {
		w = append(w, "output exceeded the configured size cap and was clipped")
	}
	if res.ExitCode > 0 && res.Note != "" {
		w = append(w, res.Note)
	}
	return w
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fail renders an error in the same envelope shape as a success, so the model
// always has a predictable place to look for the failure reason.
func fail(tool, target string, start time.Time, cause error) (*mcp.CallToolResult, error) {
	env := map[string]any{
		"tool":        tool,
		"timestamp":   now(),
		"duration_ms": time.Since(start).Milliseconds(),
		"error":       cause.Error(),
	}
	if target != "" {
		env["target"] = target
	}
	out, err := mcp.NewToolResultJSON(env)
	if err != nil {
		return mcp.NewToolResultError(cause.Error()), nil
	}
	out.IsError = true
	return out, nil
}

// failf is fail with formatting, and infers the envelope from the tool name so
// the two cannot drift apart.
func failf(tool, target string, start time.Time, format string, a ...any) (*mcp.CallToolResult, error) {
	return fail(tool, target, start, fmt.Errorf(format, a...))
}

// ---------------------------------------------------------------------------
// Argument extraction
// ---------------------------------------------------------------------------

// requireArg reads a mandatory string argument and trims it. mcp-go's
// RequireString reports a protocol-level error, which the MCP layer renders
// into a proper tool error without wasting a round trip.
func requireArg(req mcp.CallToolRequest, key string) (string, error) {
	v, err := req.RequireString(key)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

// argTimeout resolves a caller-supplied timeout against the module default
// and the global ceiling. Callers can shorten a budget but never extend it
// past the hard cap, which keeps a single tool call from pinning a process
// slot indefinitely.
func argTimeout(d Deps, req mcp.CallToolRequest, def time.Duration) time.Duration {
	secs := int(req.GetInt("timeout_seconds", 0))
	if secs <= 0 {
		return def
	}
	dur := time.Duration(secs) * time.Second
	if dur > d.Cfg.Timeouts.Max {
		dur = d.Cfg.Timeouts.Max
	}
	return dur
}

// scopeCheck applies the network policy and returns a ready-made error.
func scopeCheck(d Deps, host string) error {
	if allowed, why := d.Cfg.NetworkAllowed(host); !allowed {
		return &ScopeError{Host: host, Reason: why}
	}
	return nil
}

// ScopeError signals a policy refusal rather than a tool failure.
type ScopeError struct {
	Host   string
	Reason string
}

func (e *ScopeError) Error() string {
	return fmt.Sprintf("policy refusal: %s", e.Reason)
}

// translateExec converts a policy violation into an actionable message for the
// caller, who is frequently an LLM that guessed at a flag name.
func translateExec(err error) error {
	switch {
	case errors.Is(err, utils.ErrBinaryNotFound):
		return fmt.Errorf("%w — install the tool or pick a different one; the SENTINEL-X module list documents the fallbacks", err)
	case errors.Is(err, utils.ErrArgumentDenied):
		return fmt.Errorf("%w — SENTINEL-X only permits read-only invocations; remove the flag and retry", err)
	case errors.Is(err, utils.ErrBinaryNotAllowed), errors.Is(err, utils.ErrBinaryDenied):
		return fmt.Errorf("%w — the binary is not permitted by the server's allowlist", err)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("the operation was cancelled or timed out: %w", err)
	default:
		return err
	}
}

// requireBinary resolves a binary or explains which fallbacks are usable.
func requireBinary(d Deps, candidates ...string) (string, error) {
	for _, c := range candidates {
		if ok, _ := d.Runner.Available(c); ok {
			return c, nil
		}
	}
	return "", fmt.Errorf("none of the required binaries are installed or allowlisted: %s (checked: %s)",
		strings.Join(candidates, ", "), strings.Join(candidates, ", "))
}

// stringList reads a repeated string argument with sane bounds.
func stringList(req mcp.CallToolRequest, key string, max int) []string {
	raw := req.GetStringSlice(key, nil)
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

// csvList accepts either a JSON array or a comma-separated string, because
// models produce both for the same field.
func csvList(req mcp.CallToolRequest, key string) []string {
	if arr := stringList(req, key, 128); len(arr) > 0 {
		return arr
	}
	raw := strings.TrimSpace(req.GetString(key, ""))
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
