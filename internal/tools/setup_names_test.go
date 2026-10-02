package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// setup must be able to name the missing tools, or the model cannot tell the
// user what is about to break.
func TestSetupRequirementNamesIncludeUninstallables(t *testing.T) {
	names := map[string]bool{}
	for _, n := range setupRequirementNames() {
		names[n] = true
	}
	for _, want := range []string{"whois", "nmap", "dig", "nuclei"} {
		if !names[want] {
			t.Errorf("%q is not in the setup requirement list", want)
		}
	}
}

// Installing must not shell out for the tools it refuses to install.
func TestSetupRefusesUninstallablesWithoutRunningAnything(t *testing.T) {
	t.Setenv("SENTINELX_AUTO_INSTALL", "on")
	deps := setupDeps(t)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"action": "install", "requirements": []any{"nuclei"}}

	res, err := setupTool(deps).Handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	txt := res.Content[0].(mcp.TextContent).Text
	var env struct {
		Data struct {
			Results []map[string]any `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(txt), &env); err != nil {
		t.Fatalf("bad envelope: %s", txt)
	}
	r := env.Data.Results[0]
	if r["installed"] == true {
		t.Fatalf("nuclei was reported as installed: %v", r)
	}
	if _, ran := r["command"]; ran {
		t.Fatalf("a command was run for nuclei: %v", r["command"])
	}
	if note, _ := r["note"].(string); note == "" {
		t.Fatal("no explanation given for the refusal")
	}
}
