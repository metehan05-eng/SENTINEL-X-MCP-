// The `sentinel-x install` subcommand family: register the compiled binary as
// an MCP server in Claude Desktop, Cursor and OpenCode.
//
// This is the only part of the program that writes to disk, and it is entirely
// separate from the read-only security tooling. The distinction is deliberate
// and worth stating plainly: the *server* observes and never writes, while this
// *installer* only ever writes an MCP client configuration file, and only the
// one entry it owns.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sentinel-x/sentinel-x/internal/install"
)

const installUsage = `sentinel-x install — register this binary as an MCP server

Usage:
  sentinel-x install [flags] [client...]

Clients: claude, cursor, opencode
  With no client named, every client detected on this machine is configured.

Flags:
  -client string    configure only this client
  -path string      path to the SENTINEL-X binary to register (default: this executable)
  -env KEY=VALUE    set an environment variable in the client config (repeatable)
                    e.g. -env SENTINELX_SCOPE_TARGETS=corp.example.com
  -portable         register the command by name instead of absolute path, so the same config works on every machine (requires the binary on PATH)
  -dry-run          print what would be written and change nothing
  -list             show where each client is configured and its current state

Related:
  sentinel-x uninstall [flags] [client...]   remove the SENTINEL-X entry
  sentinel-x                                 run the MCP server on stdio

After installing, restart the client: none of them hot-reload MCP config.
`

// runInstall dispatches the install/uninstall/list subcommands.
func runInstall(args []string) error {
	if len(args) == 0 {
		fmt.Print(installUsage)
		return nil
	}
	switch args[0] {
	case "install":
		return runInstallCmd(args[1:])
	case "uninstall":
		return runUninstallCmd(args[1:])
	case "list", "-list", "--list":
		printInstallState()
		return nil
	case "help", "-h", "-help", "--help":
		fmt.Print(installUsage)
		return nil
	}
	return fmt.Errorf("unknown install subcommand %q (expected install, uninstall, list or help)", args[0])
}

func printInstallState() {
	fmt.Println("MCP client configuration")
	fmt.Println()
	for _, s := range install.Inspect() {
		status := "not detected"
		switch {
		case s.Installed:
			status = "installed"
		case s.Exists:
			status = "configured, sentinel-x not registered"
		}
		detected := ""
		if !s.Detected {
			detected = "  (no install directory found; safe to configure anyway)"
		}
		fmt.Printf("  %-10s %-9s %s%s\n", s.Client, status, s.Path, detected)
	}
	fmt.Println()
	fmt.Println("  claude    Claude Desktop      mcpServers: {command, env}")
	fmt.Println("  cursor    Cursor              mcpServers: {command, env}")
	fmt.Println("  opencode  OpenCode            mcp: {type:local, command:[...], environment}")
}

// selectClients resolves the requested clients, defaulting to those detected.
func selectClients(requested []string) ([]install.Client, error) {
	if len(requested) == 0 {
		var out []install.Client
		for _, c := range install.Clients {
			if c.Detected() {
				out = append(out, c)
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no MCP client was detected on this machine; name one explicitly, e.g. `sentinel-x install opencode`")
		}
		return out, nil
	}
	var out []install.Client
	for _, name := range requested {
		var found bool
		for _, c := range install.Clients {
			if string(c) == strings.ToLower(name) {
				out = append(out, c)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown client %q (expected claude, cursor or opencode)", name)
		}
	}
	return out, nil
}

// binaryPath resolves the absolute path of the binary to register.
//
// A relative path would break as soon as the client started the server from a
// different working directory, which is the normal case for a GUI app.
// ServerCommandName is the name a portable config expects to find on PATH.
const ServerCommandName = "sentinel-x"

func binaryPath(flagValue string) (string, error) {
	p := flagValue
	if p == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		// Resolve a symlink so a Homebrew-style link does not become the
		// registered command.
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		p = exe
	}
	// A bare name is kept as written so the client resolves it through PATH.
	// This is what makes a config portable: an absolute path records the
	// account and checkout location of the machine that installed it, and stops
	// resolving the moment the same file is used anywhere else.
	if !strings.ContainsRune(p, os.PathSeparator) {
		if p == "" || strings.HasPrefix(p, ".") {
			return "", fmt.Errorf("cannot register %q: it is not on PATH", p)
		}
		if _, err := exec.LookPath(p); err != nil {
			return "", fmt.Errorf("cannot register %q: not found on PATH. Install the binary somewhere on PATH, or pass -path with an absolute path: %w", p, err)
		}
		return p, nil
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("cannot register %s: %w", abs, err)
	}
	if st.IsDir() {
		return "", fmt.Errorf("cannot register %s: it is a directory", abs)
	}
	if runtimeIsWindows() {
		abs = windowsPath(abs)
	}
	return abs, nil
}

func runInstallCmd(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, installUsage) }
	clientFlag := fs.String("client", "", "configure only this client")
	pathFlag := fs.String("path", "", "path to the SENTINEL-X binary to register")
	portableFlag := fs.Bool("portable", false, "register the command by name instead of absolute path, so the same config works on every machine (requires the binary on PATH)")
	dryRun := fs.Bool("dry-run", false, "print what would be written and change nothing")
	listOnly := fs.Bool("list", false, "show client configuration state")
	var envFlags multiFlag
	fs.Var(&envFlags, "env", "set an environment variable in the client config (repeatable)")
	if err := fs.Parse(reorderArgs(args, valueFlagsInstall)); err != nil {
		return err
	}
	if *listOnly {
		printInstallState()
		return nil
	}

	// An unset -client flag must not become an empty positional argument.
	var requested []string
	if *clientFlag != "" {
		requested = append(requested, *clientFlag)
	}
	clients, err := selectClients(append(requested, fs.Args()...))
	if err != nil {
		return err
	}
	// Portable means the config records a command name, not a path. That makes
	// the file independent of the account and checkout location of whoever
	// wrote it, which is the whole point of sharing one config between
	// machines. It also gives up the ability to work from a checkout that is
	// not on PATH, so the name is verified at install time rather than left to
	// fail silently inside the client.
	bin := "sentinel-x"
	if !*portableFlag {
		bin, err = binaryPath(*pathFlag)
		if err != nil {
			return err
		}
	} else if *pathFlag == "" {
		if _, err := exec.LookPath(ServerCommandName); err != nil {
			return fmt.Errorf("cannot register %q portably: it is not on PATH. Put the binary on PATH (for example: sudo install -m 0755 %s /usr/local/bin/%s), or drop --portable to record the current path instead: %w",
				ServerCommandName, filepath.Base(os.Args[0]), ServerCommandName, err)
		}
	} else {
		bin, err = binaryPath(*pathFlag)
		if err != nil {
			return err
		}
	}
	env, err := parseEnvFlags(envFlags)
	if err != nil {
		return err
	}
	entry := install.Entry{Command: bin, Env: env}

	if *dryRun {
		fmt.Println("Dry run — no files were written.")
		fmt.Println()
	}
	var wrote int
	for _, c := range clients {
		path, err := c.Path()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-9s skipped: %v\n", c, err)
			continue
		}
		cfg, err := install.ReadConfig(path)
		if err != nil {
			// Refuse rather than overwrite: a config we cannot parse is a
			// config we cannot preserve.
			return fmt.Errorf("refusing to touch %s: %v\n  fix or move the file, then run this again", path, err)
		}
		action := "install"
		if servers, err := install.ServersFor(cfg, c); err == nil {
			if _, present := servers[install.ServerName]; present {
				action = "update"
			}
		}
		if err := install.Apply(cfg, c, entry); err != nil {
			return err
		}

		if *dryRun {
			preview, _ := install.Render(c, entry)
			fmt.Printf("  %-9s %s -> %s\n", c, action, path)
			fmt.Printf("            would write %s entry %s: %s\n", c.ConfigKey(), install.ServerName, preview)
			continue
		}
		hadComments := install.HasComments(path)
		if err := install.Write(path, cfg); err != nil {
			return err
		}
		wrote++
		fmt.Printf("  %-9s %s -> %s\n", c, action, path)
		if hadComments {
			fmt.Printf("            note: this file used JSONC comments; it is rewritten as plain JSON.\n")
			fmt.Printf("                  the commented original is kept at %s\n", path+".sentinel-x.bak")
		}
		if _, err := os.Stat(path + ".sentinel-x.bak"); err == nil {
			fmt.Printf("            previous file backed up to %s.sentinel-x.bak\n", filepath.Base(path))
		}
	}

	if *dryRun {
		return nil
	}
	fmt.Println()
	if wrote > 0 {
		fmt.Println("Restart the client to pick up the change; none of them reload MCP config automatically.")
	}
	if len(env) == 0 {
		fmt.Println("No environment was set. Scope is unlimited by default — re-run with")
		fmt.Println("  -env SENTINELX_SCOPE_TARGETS=corp.example.com,10.0.0.0/8")
		fmt.Println("to constrain it to the assets you are authorised to test.")
	}
	return nil
}

func runUninstallCmd(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, installUsage) }
	clientFlag := fs.String("client", "", "remove from this client only")
	dryRun := fs.Bool("dry-run", false, "print what would change and remove nothing")
	if err := fs.Parse(reorderArgs(args, valueFlagsUninstall)); err != nil {
		return err
	}
	var requested []string
	if *clientFlag != "" {
		requested = append(requested, *clientFlag)
	}
	clients, err := selectClients(append(requested, fs.Args()...))
	if err != nil {
		return err
	}
	var removed int
	for _, c := range clients {
		path, err := c.Path()
		if err != nil {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			fmt.Printf("  %-9s no config at %s\n", c, path)
			continue
		}
		cfg, err := install.ReadConfig(path)
		if err != nil {
			return fmt.Errorf("refusing to touch %s: %v", path, err)
		}
		if !install.Remove(cfg, c) {
			fmt.Printf("  %-9s nothing to remove\n", c)
			continue
		}
		if *dryRun {
			fmt.Printf("  %-9s would remove %s from %s\n", c, install.ServerName, path)
			continue
		}
		if err := install.Write(path, cfg); err != nil {
			return err
		}
		removed++
		fmt.Printf("  %-9s removed from %s\n", c, path)
	}
	if removed == 0 && !*dryRun {
		fmt.Println("Nothing was removed.")
	}
	return nil
}

func parseEnvFlags(flags multiFlag) (map[string]string, error) {
	if len(flags) == 0 {
		return nil, nil
	}
	env := map[string]string{}
	for _, f := range flags {
		k, v, ok := strings.Cut(f, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("-env expects KEY=VALUE, got %q", f)
		}
		env[k] = v
	}
	return env, nil
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// reorderArgs moves flags ahead of positional arguments so that
// `install opencode -env K=V` behaves the way it reads.
//
// The standard flag package stops parsing at the first non-flag argument, which
// would silently turn `-env K=V` into a client named "-env" and fail with a
// confusing "unknown client" error.
//
// A flag listed in takesValue is known to consume the following argument when it
// is written without "="; every other flag is boolean. That distinction has to be
// known here because the package cannot parse the args to discover it.
// flagKey normalises a flag to the single-dash spelling used in the lookup
// tables. The flag package accepts both "-env" and "--env", so a table keyed
// only on the single-dash form lost track of the value argument under the
// double-dash spelling: the value was then read as a positional argument and
// rejected as an unknown client.
func flagKey(a string) string {
	return "-" + strings.TrimLeft(a, "-")
}

// reorderArgs puts flags ahead of positional arguments so the flag package stops
// parsing at the first non-flag argument, which would silently turn `-env K=V`
// into a client named "-env" and fail with a confusing "unknown client" error.
//
// A flag listed in takesValue is known to consume the following argument when it
// is written without "="; every other flag is boolean. That distinction has to be
// known here because the package cannot parse the args to discover it.
func reorderArgs(args []string, takesValue map[string]bool) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			return append(flags, positional...)
		case len(a) > 1 && a[0] == '-':
			flags = append(flags, a)
			if takesValue[flagKey(a)] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

// valueFlagsInstall and valueFlagsUninstall list the flags that consume the
// following argument when written without "=".
var (
	valueFlagsInstall = map[string]bool{"-client": true, "-path": true, "-env": true}
	// -portable is boolean, so it takes no argument. Listed nowhere else on purpose.
	valueFlagsUninstall = map[string]bool{"-client": true}
)
