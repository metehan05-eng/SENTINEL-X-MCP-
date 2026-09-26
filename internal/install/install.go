// Package install registers the compiled SENTINEL-X binary as an MCP server in
// the configuration of an MCP client.
//
// The three supported clients do not agree on a configuration format, and
// getting that wrong is silent: OpenCode in particular validates its config
// against a schema with additionalProperties:false and refuses to start when a
// field is wrong, so a snippet written for Claude Desktop pasted into
// opencode.json produces a broken installation rather than an error message.
//
// This package therefore writes each client's own shape:
//
//	Claude Desktop / Cursor   {"mcpServers": {"sentinel-x": {command, env}}}
//	OpenCode                  {"mcp": {"sentinel-x": {type, command[], environment}}}
//
// Merging is non-destructive. An existing configuration keeps every other key,
// byte for byte in semantic content: this tool owns exactly one entry and
// refuses to touch anything else. A malformed configuration is reported, never
// overwritten.
package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ServerName is the key SENTINEL-X is registered under in every client.
const ServerName = "sentinel-x"

// Client identifies one supported MCP client.
type Client string

const (
	ClaudeDesktop Client = "claude"
	Cursor        Client = "cursor"
	OpenCode      Client = "opencode"
)

// Clients is the set this package can install into, in display order.
var Clients = []Client{ClaudeDesktop, Cursor, OpenCode}

// opencodeConfigDir resolves the directory holding opencode's global config.
func opencodeConfigDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "opencode"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "opencode"), nil
}

// ConfigKey is the top-level JSON key under which this client keeps its MCP
// server entries.
//
// It is deliberately not the same thing as the file name. Claude Desktop and
// Cursor both use "mcpServers" in a file of a different name; OpenCode uses
// "mcp" inside opencode.json. Conflating the two writes the servers under a
// key the client does not recognise, which for OpenCode is a hard startup
// failure rather than a warning.
func (c Client) ConfigKey() string {
	if c == OpenCode {
		return "mcp"
	}
	return "mcpServers"
}

// Path returns the configuration file this client reads.
//
// Detection is filesystem-based rather than build-tag-based so that one binary
// works on the platforms its host actually runs, and so an install performed
// under WSL or a container still targets the right layout.
func (c Client) Path() (string, error) {
	switch c {
	case OpenCode:
		dir, err := opencodeConfigDir()
		if err != nil {
			return "", err
		}
		// OpenCode accepts both opencode.json and opencode.jsonc. If a
		// .jsonc already exists it is the user's file — writing a fresh
		// opencode.json beside it would split their configuration across two
		// files, with settings silently landing in whichever one opencode
		// happens to read last.
		jsonc := filepath.Join(dir, "opencode.jsonc")
		if _, err := os.Stat(jsonc); err == nil {
			return jsonc, nil
		}
		return filepath.Join(dir, "opencode.json"), nil

	case Cursor:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".cursor", "mcp.json"), nil

	case ClaudeDesktop:
		switch runtime.GOOS {
		case "darwin":
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		case "windows":
			if app := os.Getenv("APPDATA"); app != "" {
				return filepath.Join(app, "Claude", "claude_desktop_config.json"), nil
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			return filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"), nil
		default:
			if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
				return filepath.Join(x, "Claude", "claude_desktop_config.json"), nil
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		}
	}
	return "", fmt.Errorf("unknown client %q", c)
}

// DirHints are directories whose presence indicates the client is installed on
// this machine. Presence is a hint, not a proof of use.
func (c Client) DirHints() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	switch c {
	case Cursor:
		return []string{filepath.Join(home, ".cursor")}
	case OpenCode:
		dirs := []string{filepath.Join(home, ".config", "opencode")}
		if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
			dirs = append(dirs, filepath.Join(x, "opencode"))
		}
		return dirs
	case ClaudeDesktop:
		switch runtime.GOOS {
		case "darwin":
			return []string{
				filepath.Join(home, "Library", "Application Support", "Claude"),
				filepath.Join(home, "Library", "Caches", "Claude"),
			}
		case "windows":
			if app := os.Getenv("APPDATA"); app != "" {
				return []string{filepath.Join(app, "Claude"), filepath.Join(app, "Cursor")}
			}
		default:
			dirs := []string{filepath.Join(home, ".config", "Claude"), filepath.Join(home, ".claude")}
			if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
				dirs = append(dirs, filepath.Join(x, "Claude"), filepath.Join(x, "claude"))
			}
			return dirs
		}
	}
	return nil
}

// Detected reports whether the client looks installed on this machine.
func (c Client) Detected() bool {
	if p, err := c.Path(); err == nil {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	for _, d := range c.DirHints() {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

// Installed reports the current registration state of a client.
type State struct {
	Client    Client
	Path      string
	Exists    bool
	Detected  bool
	Installed bool // this client already has a sentinel-x entry
}

// Inspect gathers the state of every supported client.
func Inspect() []State {
	out := make([]State, 0, len(Clients))
	for _, c := range Clients {
		s := State{Client: c, Detected: c.Detected()}
		p, err := c.Path()
		if err != nil {
			s.Path = "(unresolved: " + err.Error() + ")"
			out = append(out, s)
			continue
		}
		s.Path = p
		if _, err := os.Stat(p); err == nil {
			s.Exists = true
		}
		if s.Exists {
			cfg, err := ReadConfig(p)
			if err == nil {
				_, s.Installed = cfg[ServerName]
			}
		}
		out = append(out, s)
	}
	return out
}

// Config is a parsed client configuration: a decoded JSON object whose nested
// values are left as raw JSON so that merging cannot silently re-encode or
// reformat parts this tool does not own.
type Config map[string]json.RawMessage

// ReadConfig loads a client configuration.
//
// A JSONC file (comments, trailing commas) is accepted for OpenCode, which
// supports that extension. Anything that still does not parse is returned as an
// error: guessing would risk discarding settings the user wrote by hand.
func ReadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return Config{}, nil
	}
	stripped, err := stripJSONC(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(stripped, &cfg); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	if cfg == nil {
		return Config{}, nil
	}
	return cfg, nil
}

// stripJSONC removes // and /* */ comments and trailing commas.
//
// This is a deliberately small scanner rather than a full JSONC parser: it
// tracks string state so that a "//" inside a value is not mistaken for a
// comment, which is the failure mode that would corrupt a real config.
func stripJSONC(in []byte) ([]byte, error) {
	out := make([]byte, 0, len(in))
	inStr, inLine, inBlock := false, false, false
	escaped := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
				out = append(out, c)
			}
			continue
		case inBlock:
			if c == '*' && i+1 < len(in) && in[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		case inStr:
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			inLine = true
			i++
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			inBlock = true
			i++
		default:
			out = append(out, c)
		}
	}
	if inStr {
		return nil, errors.New("unterminated string")
	}
	return removeTrailingCommas(out)
}

func removeTrailingCommas(in []byte) ([]byte, error) {
	out := make([]byte, 0, len(in))
	inStr, escaped := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			// Look ahead past whitespace for a closing bracket.
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue // drop the comma
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// servers returns the map holding this client's server entries, creating it if
// the key is absent.
func servers(cfg Config, c Client) (map[string]json.RawMessage, error) {
	key := c.ConfigKey()
	raw, ok := cfg[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return map[string]json.RawMessage{}, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("the %q key in this config is not an object: %w", key, err)
	}
	return m, nil
}

// Entry is the registration written into a client config.
type Entry struct {
	// Command is the absolute path to the SENTINEL-X binary.
	Command string
	// Env is the environment passed to the server process. Empty values are
	// dropped so that a client's config does not carry placeholder blanks.
	Env map[string]string
}

// Render produces the JSON object this client expects for the entry.
//
// The difference between the dialects is the whole point of this package:
//
//   - Claude Desktop and Cursor use a "command" string plus an "env" object.
//   - OpenCode requires "type":"local", a "command" *array*, and
//     "environment". It sets additionalProperties:false, so an "env" key there
//     is a hard validation failure and the server never starts.
func Render(c Client, e Entry) (json.RawMessage, error) {
	env := map[string]string{}
	for k, v := range e.Env {
		if strings.TrimSpace(v) == "" {
			continue
		}
		env[k] = v
	}
	var entry map[string]any
	switch c {
	case OpenCode:
		entry = map[string]any{
			"type":    "local",
			"command": []string{e.Command},
			"enabled": true,
		}
		if len(env) > 0 {
			entry["environment"] = env
		}
	default:
		entry = map[string]any{
			"command": e.Command,
		}
		if len(env) > 0 {
			entry["env"] = env
		}
	}
	return json.Marshal(entry)
}

// Apply merges the entry into a configuration, leaving every other key intact.
func Apply(cfg Config, c Client, e Entry) error {
	raw, err := Render(c, e)
	if err != nil {
		return err
	}
	m, err := servers(cfg, c)
	if err != nil {
		return err
	}
	m[ServerName] = raw
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	cfg[c.ConfigKey()] = blob

	// Claude Desktop and Cursor have no schema key. OpenCode does, and
	// opencode.json is validated strictly, so point the editor at the schema.
	if c == OpenCode {
		if _, ok := cfg["$schema"]; !ok {
			if sch, err := json.Marshal("https://opencode.ai/config.json"); err == nil {
				cfg["$schema"] = sch
			}
		}
	}
	return nil
}

// Remove deletes the SENTINEL-X entry, reporting whether one was present.
func Remove(cfg Config, c Client) bool {
	m, err := servers(cfg, c)
	if err != nil {
		return false
	}
	if _, ok := m[ServerName]; !ok {
		return false
	}
	delete(m, ServerName)
	blob, err := json.Marshal(m)
	if err != nil {
		return false
	}
	cfg[c.ConfigKey()] = blob
	return true
}

// HasComments reports whether a config file contains JSONC comments.
//
// The file is re-encoded as plain JSON on write, so comments are necessarily
// dropped. Detecting that lets the caller warn instead of silently discarding
// the user's notes.
func HasComments(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	stripped, err := stripJSONC(raw)
	if err != nil {
		return false
	}
	return len(stripped) != len(raw)
}

// Write persists a configuration atomically, after taking a backup of any
// existing file. A half-written config would leave the user with a client that
// cannot start, so the rename is the only way the new content becomes visible.
func Write(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	blob, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')

	// Back up once. Re-running install would otherwise replace the backup with
	// a copy that already contains a sentinel-x entry, leaving no way to recover
	// the configuration as it was before this tool first touched it.
	backup := path + ".sentinel-x.bak"
	if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
		if old, rerr := os.ReadFile(path); rerr == nil {
			if werr := os.WriteFile(backup, old, 0o600); werr != nil {
				return fmt.Errorf("back up %s: %w", path, werr)
			}
		}
	}
	tmp, err := os.CreateTemp(dir, ".sentinel-x-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ServersFor exposes the client-specific server map, so a caller can tell an
// install from an update without duplicating the dialect lookup.
func ServersFor(cfg Config, c Client) (map[string]json.RawMessage, error) {
	return servers(cfg, c)
}
