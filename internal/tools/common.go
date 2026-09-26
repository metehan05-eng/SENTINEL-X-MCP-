// Package tools contains the SENTINEL-X MCP tool modules.
//
// Every tool in this package is strictly observational: it discovers, queries
// or reports. Nothing here can modify a target system, write to a filesystem,
// or execute a payload. The package-level Registry wires them into the MCP
// server.
package tools

import (
	"context"
	"errors"
	"fmt"
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
}

// Registry maps tool names to their handler.
type Registry map[string]Handler

// All builds the complete tool registry for the server.
func All(d Deps) Registry {
	r := Registry{}
	for _, set := range toolSets(d) {
		for _, t := range set {
			r[t.Tool.Name] = t.Handler
		}
	}
	return r
}

// Tool pairs a schema with its handler.
type Tool struct {
	Tool    mcp.Tool
	Handler Handler
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
