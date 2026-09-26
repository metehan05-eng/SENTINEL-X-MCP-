package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The dialects differ in exactly the ways that silently break an install.
// OpenCode validates with additionalProperties:false, so an "env" key or a
// string "command" there is a hard startup failure.
func TestRenderOpenCodeUsesTheSchemaShape(t *testing.T) {
	raw, err := Render(OpenCode, Entry{
		Command: "/usr/local/bin/sentinel-x",
		Env:     map[string]string{"SENTINELX_SCOPE_TARGETS": "corp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	if got["type"] != "local" {
		t.Errorf(`type = %v, want "local" (required by McpLocalConfig)`, got["type"])
	}
	cmd, ok := got["command"].([]any)
	if !ok {
		t.Fatalf("command is %T, want an array of strings", got["command"])
	}
	if len(cmd) != 1 || cmd[0] != "/usr/local/bin/sentinel-x" {
		t.Errorf("command = %v, want [\"/usr/local/bin/sentinel-x\"]", cmd)
	}
	// A missing key yields the nil zero value, so the presence test has to be
	// written as `!ok`; writing it as `ok` makes the assertion vacuous.
	if _, present := got["env"]; present {
		t.Error(`"env" is not a valid OpenCode key; it must be "environment"`)
	}
	env, ok := got["environment"].(map[string]any)
	if !ok {
		t.Fatalf("environment is %T, want an object", got["environment"])
	}
	if env["SENTINELX_SCOPE_TARGETS"] != "corp.example.com" {
		t.Errorf("environment = %v", env)
	}

	// Reject anything the schema would not accept.
	assertNoUnknownKeys(t, got, "type", "command", "environment", "enabled")
}

func TestRenderClaudeAndCursorUseMcpServersShape(t *testing.T) {
	for _, c := range []Client{ClaudeDesktop, Cursor} {
		raw, err := Render(c, Entry{
			Command: "/usr/local/bin/sentinel-x",
			Env:     map[string]string{"NVD_API_KEY": "k"},
		})
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got["command"] != "/usr/local/bin/sentinel-x" {
			t.Errorf("%s: command = %v, want a plain string", c, got["command"])
		}
		if _, present := got["environment"]; present {
			t.Errorf("%s: %q is an OpenCode key and is not valid here", c, "environment")
		}
		env, ok := got["env"].(map[string]any)
		if !ok {
			t.Fatalf("%s: env is %T, want an object", c, got["env"])
		}
		if env["NVD_API_KEY"] != "k" {
			t.Errorf("%s: env = %v", c, env)
		}
	}
}

func TestRenderDropsEmptyEnvValues(t *testing.T) {
	raw, err := Render(OpenCode, Entry{Command: "/x", Env: map[string]string{
		"SENTINELX_SCOPE_TARGETS": "  ",
		"NVD_API_KEY":             "real",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SCOPE_TARGETS") {
		t.Errorf("a blank value was written into the config: %s", raw)
	}
	if !strings.Contains(string(raw), "NVD_API_KEY") {
		t.Errorf("a real value was dropped: %s", raw)
	}
}

func TestApplyPreservesUnrelatedConfiguration(t *testing.T) {
	// A realistic config with another MCP server and unrelated settings.
	original := `{
      "model": "anthropic/claude-sonnet-4-6",
      "mcp": {
        "other-server": {"type": "remote", "url": "https://example.test/mcp"}
      },
      "permission": {"bash": {"git *": "allow"}}
    }`
	cfg := mustParse(t, original)

	if err := Apply(cfg, OpenCode, Entry{Command: "/usr/local/bin/sentinel-x"}); err != nil {
		t.Fatal(err)
	}

	// Unrelated top-level keys must survive.
	if _, present := cfg["model"]; !present {
		t.Error(`"model" was dropped`)
	}
	if _, present := cfg["permission"]; !present {
		t.Error(`"permission" was dropped`)
	}
	if cfg["$schema"] == nil {
		t.Error("OpenCode config should carry a $schema so the editor validates it")
	}

	servers, err := ServersFor(cfg, OpenCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := servers["other-server"]; !present {
		t.Error("the pre-existing MCP server was dropped")
	}
	if _, present := servers[ServerName]; !present {
		t.Error("sentinel-x was not registered")
	}

	// The preserved entry must be byte-identical, not re-encoded differently.
	var origOther, nowOther json.RawMessage
	json.Unmarshal(json.RawMessage(`{"type":"remote","url":"https://example.test/mcp"}`), &origOther)
	nowOther = servers["other-server"]
	if !jsonEqual(t, origOther, nowOther) {
		t.Errorf("the other server was altered:\n got %s\nwant %s", nowOther, origOther)
	}
}

func TestApplyPreservesClaudeDesktopEntries(t *testing.T) {
	cfg := mustParse(t, `{"mcpServers": {"other": {"command": "/bin/other", "env": {"A": "1"}}}}`)
	if err := Apply(cfg, ClaudeDesktop, Entry{Command: "/x"}); err != nil {
		t.Fatal(err)
	}
	servers, _ := ServersFor(cfg, ClaudeDesktop)
	if _, present := servers["other"]; !present {
		t.Error("the pre-existing Claude Desktop server was dropped")
	}
	if _, present := servers[ServerName]; !present {
		t.Error("sentinel-x was not registered")
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	cfg := mustParse(t, `{}`)
	e := Entry{Command: "/x", Env: map[string]string{"A": "1"}}
	for i := 0; i < 3; i++ {
		if err := Apply(cfg, OpenCode, e); err != nil {
			t.Fatal(err)
		}
	}
	servers, _ := ServersFor(cfg, OpenCode)
	if len(servers) != 1 {
		t.Errorf("repeated installs produced %d entries, want 1", len(servers))
	}
}

func TestRemoveOnlyTouchesSentinelX(t *testing.T) {
	cfg := mustParse(t, `{"mcp": {"other": {"type": "remote", "url": "https://x.test"}}}`)
	if err := Apply(cfg, OpenCode, Entry{Command: "/x"}); err != nil {
		t.Fatal(err)
	}
	if !Remove(cfg, OpenCode) {
		t.Fatal("Remove reported nothing to remove")
	}
	servers, _ := ServersFor(cfg, OpenCode)
	if _, present := servers[ServerName]; present {
		t.Error("sentinel-x survived removal")
	}
	if _, present := servers["other"]; !present {
		t.Error("removal deleted an unrelated server")
	}
	if Remove(cfg, OpenCode) {
		t.Error("removing a second time reported success")
	}
}

// A JSONC config must round-trip, or a user's commented file breaks the install.
func TestReadConfigAcceptsJSONC(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "opencode.json")
	src := `{
  // the model we use everywhere
  "model": "anthropic/claude-sonnet-4-6",
  /* block comment */
  "mcp": {
    "s": {"type": "local", "command": ["/x"],},  // trailing comma
  },
}`
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadConfig(p)
	if err != nil {
		t.Fatalf("JSONC config was rejected: %v", err)
	}
	if _, ok := cfg["model"]; !ok {
		t.Error("comments or trailing commas broke the parse")
	}
}

// A "//" inside a string value must not be treated as a comment; getting this
// wrong would silently truncate a value in a real config.
func TestStripJSONCKeepsSlashesInsideStrings(t *testing.T) {
	src := []byte(`{"url": "https://example.test/mcp", "note": "a // b", "glob": "**/*.go"}`)
	out, err := stripJSONC(src)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("stripped output is not valid JSON: %v\n%s", err, out)
	}
	if got["url"] != "https://example.test/mcp" {
		t.Errorf("url = %v, the // was eaten as a comment", got["url"])
	}
	if got["note"] != "a // b" {
		t.Errorf("note = %v", got["note"])
	}
	if got["glob"] != "**/*.go" {
		t.Errorf("glob = %v", got["glob"])
	}
}

func TestReadConfigRejectsMalformedRatherThanGuessing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(p, []byte(`{"mcp": {`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(p); err == nil {
		t.Fatal("a malformed config must be reported, not silently treated as empty")
	}
}

func TestReadConfigEmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(p, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadConfig(p)
	if err != nil {
		t.Fatalf("an empty config should be treated as empty, not invalid: %v", err)
	}
	if len(cfg) != 0 {
		t.Errorf("cfg = %v, want empty", cfg)
	}
}

func TestReadConfigMissingFile(t *testing.T) {
	cfg, err := ReadConfig(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("a missing config is not an error: %v", err)
	}
	if len(cfg) != 0 {
		t.Errorf("cfg = %v, want empty", cfg)
	}
}

func TestWriteBacksUpAndIsAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "opencode.json")
	original := []byte(`{"model":"keep-me"}`)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, original, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := mustParse(t, string(original))
	if err := Apply(cfg, OpenCode, Entry{Command: "/x"}); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, cfg); err != nil {
		t.Fatal(err)
	}

	// The previous content must be recoverable.
	backup, err := os.ReadFile(p + ".sentinel-x.bak")
	if err != nil {
		t.Fatalf("no backup was written: %v", err)
	}
	if !jsonEqual(t, json.RawMessage(original), json.RawMessage(backup)) {
		t.Errorf("backup = %s, want the original %s", backup, original)
	}

	// The new content must be valid and complete.
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("written config is not valid JSON: %v\n%s", err, got)
	}
	if back["model"] != "keep-me" {
		t.Error("the written config lost the pre-existing model")
	}

	// No temporary files may be left behind.
	entries, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".sentinel-x-") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

func TestWriteSetsRestrictivePermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "opencode.json")
	if err := Write(p, mustParse(t, `{}`)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	// An MCP config can hold an NVD key, so it must not be world-readable.
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("mode = %v, want no group/other access", perm)
	}
}

func TestClientPathsAreAbsoluteAndDialectTagged(t *testing.T) {
	for _, c := range Clients {
		p, err := c.Path()
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if !filepath.IsAbs(p) {
			t.Errorf("%s: path %q is not absolute; a GUI client started from / would not find it", c, p)
		}
		// OpenCode may legitimately target opencode.jsonc when that file
		// already exists, so both extensions are valid.
		if !strings.HasSuffix(p, ".json") && !strings.HasSuffix(p, ".jsonc") {
			t.Errorf("%s: path %q ends in neither .json nor .jsonc", c, p)
		}
		if c != OpenCode && strings.HasSuffix(p, ".jsonc") {
			t.Errorf("%s: only OpenCode supports a .jsonc config, got %q", c, p)
		}
		want := "mcpServers"
		if c == OpenCode {
			want = "mcp"
		}
		if c.ConfigKey() != want {
			t.Errorf("%s: ConfigKey() = %q, want %q", c, c.ConfigKey(), want)
		}
	}
}

func assertNoUnknownKeys(t *testing.T, got map[string]any, allowed ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	for k := range got {
		if !set[k] {
			t.Errorf("key %q is not part of the OpenCode schema", k)
		}
	}
}

func mustParse(t *testing.T, src string) Config {
	t.Helper()
	var cfg Config
	if err := json.Unmarshal([]byte(src), &cfg); err != nil {
		t.Fatalf("bad test fixture: %v", err)
	}
	return cfg
}

func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xa) == string(yb)
}

// OpenCode reads both opencode.json and opencode.jsonc. Creating a fresh
// .json beside an existing .jsonc would split the user's configuration across
// two files, so the .jsonc must win.
func TestOpenCodePathPrefersExistingJSONC(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Neither exists yet: default to .json.
	if got, _ := OpenCode.Path(); filepath.Base(got) != "opencode.json" {
		t.Errorf("with no config present, path = %q, want opencode.json", filepath.Base(got))
	}

	// A .jsonc exists: it is the user's file and must be the target.
	jsonc := filepath.Join(dir, "opencode", "opencode.jsonc")
	if err := os.MkdirAll(filepath.Dir(jsonc), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonc, []byte(`{"$schema":"https://opencode.ai/config.json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := OpenCode.Path(); got != jsonc {
		t.Errorf("path = %q, want the existing %q", got, jsonc)
	}

	// Removing it falls back to .json, so uninstall still works afterwards.
	if err := os.Remove(jsonc); err != nil {
		t.Fatal(err)
	}
	if got, _ := OpenCode.Path(); filepath.Base(got) != "opencode.json" {
		t.Errorf("after removal, path = %q, want opencode.json", filepath.Base(got))
	}
}
