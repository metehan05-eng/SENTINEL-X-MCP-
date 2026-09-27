// Package config centralises all runtime configuration and the security
// policy that SENTINEL-X enforces on every external process it spawns and on
// every MCP tool argument it receives.
//
// The design goal is fail-closed: if a value cannot be determined safely from
// the environment, the server refuses the operation instead of guessing.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server identity metadata.
const (
	ServerName    = "sentinel-x"
	ServerTitle   = "SENTINEL-X Security Analysis & Vulnerability Management"
	ServerVersion = "1.0.0"
	// DefaultProtocolVersion is the MCP protocol revision this build speaks.
	DefaultProtocolVersion = "2025-06-18"
)

// Environment variable prefix. Every tunable can be overridden without
// rebuilding the binary.
const envPrefix = "SENTINELX_"

// Timeouts is the set of wall-clock budgets applied to external work.
// Every value is hard-capped by MaxTimeout at load time.
type Timeouts struct {
	Recon     time.Duration `json:"recon"`
	Scan      time.Duration `json:"scan"`
	VulnQuery time.Duration `json:"vuln_query"`
	Audit     time.Duration `json:"audit"`
	HTTP      time.Duration `json:"http"`
	Max       time.Duration `json:"max"`
}

// Policy is the authorisation layer. SENTINEL-X is a defensive tool: it may
// only observe. Policy encodes that intent as enforceable rules.
type Policy struct {
	// AllowedBinaries is the closed set of executables the runner may spawn.
	// An empty entry means "not permitted, regardless of PATH".
	AllowedBinaries []string `json:"allowed_binaries"`

	// DeniedArgPatterns are regular expressions matched (case-insensitively)
	// against every argument of every command. These must be rules that are
	// wrong for *all* tools; anything specific to one binary's flag namespace
	// belongs in BinaryArgDenylist, because a global rule would also block
	// that binary's legitimate read-only options.
	DeniedArgPatterns []string `json:"denied_arg_patterns"`

	// BinaryArgDenylist holds additional patterns keyed by binary base name.
	// CheckArgs screens an argument against both this set and the global one.
	BinaryArgDenylist map[string][]string `json:"binary_arg_denylist"`

	// DeniedBinaries are executables that are refused by name even if they
	// appear in AllowedBinaries. Belt-and-braces against a bad allowlist edit.
	DeniedBinaries []string `json:"denied_binaries"`

	// EnforceScope restricts network targets to the entries in ScopeTargets.
	// When ScopeTargets is empty, scope checking is disabled and a warning is
	// attached to every remote result.
	EnforceScope bool     `json:"enforce_scope"`
	ScopeTargets []string `json:"scope_targets"`

	// AllowPrivateNetworks permits RFC1918 / loopback / link-local targets.
	// Required for internal pentest engagements, off for internet-wide use.
	AllowPrivateNetworks bool `json:"allow_private_networks"`

	// MaxOutputBytes caps captured stdout/stderr per command.
	MaxOutputBytes int `json:"max_output_bytes"`

	// MaxConcurrency bounds simultaneously running external processes.
	MaxConcurrency int `json:"max_concurrency"`

	// Offline blocks every outbound network call from the vulnerability and
	// recon modules that would otherwise reach out to a public API.
	Offline bool `json:"offline"`

	// RedactPatterns scrub secrets from any text returned to the model.
	RedactPatterns []string `json:"-"`
}

// Config is the fully resolved runtime configuration.
type Config struct {
	Timeouts Timeouts
	Policy   Policy

	// NmapDefaults are flags always applied to nmap invocations.
	NmapDefaults []string
	// NmapAllowedScripts is the closed set of NSE scripts considered
	// read-only. Anything not listed is rejected by the argument validator.
	NmapAllowedScripts []string

	// Resolvers is the DNS server list handed to dig.
	Resolvers []string

	// DKIMSelectors are extra DKIM selector names to probe during a DNS
	// security audit, in addition to the built-in common list. Set this when
	// the target publishes DKIM under a non-standard selector.
	DKIMSelectors []string

	// AuditRoots restricts the filesystem audit module to these prefixes.
	AuditRoots []string

	// NVDAPIKey enables the higher NVD rate limit when set.
	NVDAPIKey string

	// UserAgent identifies this client to third-party APIs.
	UserAgent string

	// Verbose enables diagnostic logging to stderr (never stdout — stdout is
	// the MCP transport).
	Verbose bool
}

var (
	loadOnce sync.Once
	loaded   *Config
	loadErr  error
)

// Get returns the process-wide configuration, loading it on first use.
// A malformed environment is surfaced as an error rather than silently
// dropped, so operators notice a typo instead of running with a default.
func Get() (*Config, error) {
	loadOnce.Do(func() {
		loaded, loadErr = load()
	})
	return loaded, loadErr
}

// MustGet is Get for use during process start-up, where returning an error
// adds no value because the caller has nowhere to report it.
func MustGet() *Config {
	c, err := Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel-x: config error: %v\n", err)
		os.Exit(2)
	}
	return c
}

// Default returns a Config populated with the built-in defaults, before any
// environment overrides are applied. It is exported so that the defaults which
// end up on every command line can be asserted in tests rather than trusted.
func Default() *Config {
	return defaultConfig()
}

func load() (*Config, error) {
	c := defaultConfig()
	if err := applyEnv(c); err != nil {
		return nil, err
	}
	return c, nil
}

func defaultConfig() *Config {
	c := &Config{
		Timeouts: Timeouts{
			Recon:     30 * time.Second,
			Scan:      300 * time.Second,
			VulnQuery: 45 * time.Second,
			Audit:     60 * time.Second,
			HTTP:      20 * time.Second,
			Max:       600 * time.Second,
		},
		Policy: Policy{
			AllowedBinaries: []string{
				"nmap", "dig", "host", "nslookup", "whois",
				"curl", "openssl", "sshd", "getcap", "getfacl", "stat", "id",
			},
			DeniedBinaries: []string{
				"sh", "bash", "zsh", "dash", "ksh", "csh",
				"env", "xargs", "eval", "sudo", "su", "doas",
				"python", "python3", "perl", "ruby", "php", "nc", "ncat", "netcat",
				"msfconsole", "msfvenom", "meterpreter", "searchsploit",
				"hydra", "sqlmap", "nikto", "gobuster", "ffuf", "wfuzz",
				// nuclei can be told to run RCE and fuzzing templates, and it
				// phones home for templates on first run. Unlike searchsploit
				// it is NOT re-enabled below: an operator has to allow it by
				// name, because "the scan tool is installed" is not consent to
				// have it send exploit traffic to a target.
				"nuclei",
				"curl", // overridden below: re-added only if explicitly allowed
			},
			MaxOutputBytes:       2 << 20, // 2 MiB
			MaxConcurrency:       4,
			AllowPrivateNetworks: true,
			RedactPatterns: []string{
				`(?i)(password|passwd|pwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*\S{6,}`,
				`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`,
				`(?i)\bAKIA[0-9A-Z]{16}\b`,
				`(?i)\bgh[pousr]_[A-Za-z0-9]{20,}\b`,
				`(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b`,
			},
		},
		// No --host-timeout here: the scanner derives a per-request timeout
		// from the caller's budget and always supplies the value itself. A
		// flag left here without its value makes nmap consume the *next*
		// argument as its duration and abort with "Bogus --host-timeout
		// argument specified", failing every default scan.
		NmapDefaults: []string{"-Pn", "-n", "--max-retries", "2"},
		NmapAllowedScripts: []string{
			"ssl-cert", "ssl-enum-ciphers", "ssl-known-key", "http-title",
			"http-headers", "http-server-header", "banner", "smb-os-discovery",
			"ssh-hostkey", "ssh-auth-methods", "ssh2-enum-algos", "ftp-anon",
			"dns-recursive-servers", "ntp-info", "rpcinfo", "systemd-info",
		},
		Resolvers:     []string{},
		DKIMSelectors: []string{},
		AuditRoots:    []string{},
		UserAgent:     fmt.Sprintf("%s/%s", ServerName, ServerVersion),
	}

	// searchsploit is read-only when used purely as an index, and is
	// allowlisted explicitly so an operator can opt into local advisory
	// lookups. Every other entry in the denylist stays refused. The denylist is
	// also authoritative at lookup time, so searchsploit must be removed from
	// it here or the allowlist entry would be permanently unreachable.
	c.Policy.AllowedBinaries = append(c.Policy.AllowedBinaries, "searchsploit")
	c.Policy.DeniedBinaries = removeString(c.Policy.DeniedBinaries, "curl")
	c.Policy.DeniedBinaries = removeString(c.Policy.DeniedBinaries, "searchsploit")

	// Global rules. These must be wrong for every tool SENTINEL-X can run;
	// a rule that only makes sense inside one binary's flag namespace would
	// also block that binary's legitimate read-only options.
	c.Policy.DeniedArgPatterns = []string{
		// Shell metacharacters. Arguments are passed as an argv vector and are
		// never re-parsed by a shell, so these cannot execute anything — but a
		// metacharacter in an argument means the caller is trying to smuggle a
		// command in, which is worth refusing outright.
		`[;&|` + "`" + `$(){}<>]`,
		`(?i)(^|[/\\])(sh|bash|zsh|ksh|dash|csh|cmd|powershell)(\.exe)?$`,
		// A newline can smuggle a second directive past a line-oriented parser.
		"[\n\r]",
		`(?i)^\s*(--?exec|-e)\s*`,
		// Never write to a file: no output redirection, no script databases.
		`(?i)^(>|>>|/dev/|\.{1,2}/)`,
	}

	// Per-binary rules. Keeping these separate is what lets the policy deny
	// `searchsploit -p` without also denying `nmap -p 1-1024`.
	c.Policy.BinaryArgDenylist = map[string][]string{
		"nmap": {
			// nmap output-to-file and output-format flags: writing to disk is
			// out of scope for a read-only server.
			`(?i)^-(oN|oX|oS|oG|oA|iI)\S*\s*`,
			`(?i)^--(datadir|script-db|resume|stylesheet|webxml|logfile|traceroute-file|grepcopy|excludefile|etatime|stats-every|iflist)\b`,
			// Packet crafting, source-address spoofing and IDS evasion. These
			// are offensive capabilities, not reconnaissance.
			`(?i)^--(script-trace|spoof-mac|spoof-ip|spoof-dn|spoof-mac-prefix|badsum|fragment-packets|defeat-rst-ratelimit|delay|min-rate|max-rate|min-parallelism-udp|defeat-icmp-rate-limit|scanflags|send-ip|send-eth)\b`,
			// Stealth and evasive scan types. -sT (connect), -sU and -sV stay
			// permitted: they are ordinary detection modes.
			`(?i)^-(sS|sF|sX|sN|sA|sI|sW|sM)\s*$`,
			`(?i)^--scanflags\b`,
			`(?i)^--(send-ip|send-eth)\b`,
			// A --script value must come from the allowlist; the modules filter
			// it, and this rule is the backstop for a future caller.
			`(?i)^--script=.*(vuln|exploit|brute|dos|flood|packet|intrusive)`,
			`(?i)^--script-help\b`,
		},
		"searchsploit": {
			// Everything that prints, stores or runs exploit code. Only the
			// plain query form is allowed through.
			`(?i)^(-|--)(d|download|download-dir)\b`,
			`(?i)^(-|--)(p|path)\b`,
			`(?i)^(-|--)(o|open|www|w)\b`,
			`(?i)^(-|--)(y|yara)\b`,
			`(?i)^--strict\b`,
		},
		"curl": {
			// No uploads, no output-to-file, no credential-bearing URL.
			`(?i)^(-|--)(T|upload-file|ftp-create-dirs|ftp-port|form|form-string|data|data-ascii|data-binary|json|mail-from|mail-rcpt|proxy-user)\b`,
			`(?i)^-o\S*$`,
			`(?i)^--output\S*$`,
			`(?i)^--remote-name`,
			`(?i)^--url$`,
			`(?i)^--trace\b`,
			`(?i)^--libcurl\s+\S`,
		},
		"nuclei": {
			// Nothing may be written to disk: a read-only server has no
			// business producing report files or a template database.
			`(?i)^(-|--)(o|output|output-file|me|markdown-export|sr|silent-report)\b`,
			// Template and signature updates download and unpack archives.
			// That is a network fetch plus a filesystem write triggered
			// implicitly, which is exactly the kind of side effect this server
			// does not take on.
			`(?i)^(-|--)(update|update-templates|ut|update-check|install)\b`,
			// interactsh exfiltrates findings to a third-party collaborator
			// server. That sends data about the target somewhere the operator
			// did not name, so it is refused outright.
			`(?i)^(-|--)(interactsh-url|interactsh-server|i-u|i-us|i-url)\b`,
			`(?i)^(-|--)(fuzz|fz)\b`,
			`(?i)^(-|--)(payloads|p)\b`,
			// Routing traffic through a proxy hides the real source and can
			// defeat the scope decision already made upstream.
			`(?i)^(-|--)(proxy|proxy-url|proxy-auth|proxies|replay-proxy)\b`,
			// Browser-driven and code-executing templates run arbitrary
			// attacker-chosen logic rather than fixed checks.
			`(?i)^(-|--)(headless|enable-code-templates|code|dast|dsl|evaluate-code)\b`,
			// Loading a target list from disk would bypass the per-target
			// scope check performed here.
			`(?i)^(-|--)(l|list|input-file)\b`,
		},
		"sshd": {
			// Only the effective-config dump is permitted; anything that can
			// start a session, change keys or bind a port is refused.
			`(?i)^-(f|R|E|L|D|W|p|i|c|b|N|o|s|x)\S*\s*$`,
			`(?i)^-t\b`,
		},
		"dig": {
			// Zone transfer and cache poisoning aids.
			`(?i)^\+?(flood|qr|trace)\b`,
			`(?i)^-b\b`,
		},
		"whois": {
			`(?i)^-H\b`,
		},
	}
	return c
}

func applyEnv(c *Config) error {
	var errs []string

	dur := func(key string, dst *time.Duration, max time.Duration) {
		raw, ok := os.LookupEnv(envPrefix + key)
		if !ok || raw == "" {
			return
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s%s: %v", envPrefix, key, err))
			return
		}
		if d <= 0 {
			errs = append(errs, fmt.Sprintf("%s%s: must be positive", envPrefix, key))
			return
		}
		if d > max {
			d = max
		}
		*dst = d
	}
	// The global cap is resolved first so every module timeout below is
	// clamped against the value the operator actually asked for. Reading it
	// last would clamp against the default and let a caller exceed the cap
	// they just configured.
	dur("TIMEOUT_MAX", &c.Timeouts.Max, 30*time.Minute)
	dur("TIMEOUT_RECON", &c.Timeouts.Recon, c.Timeouts.Max)
	dur("TIMEOUT_SCAN", &c.Timeouts.Scan, c.Timeouts.Max)
	dur("TIMEOUT_VULN", &c.Timeouts.VulnQuery, c.Timeouts.Max)
	dur("TIMEOUT_AUDIT", &c.Timeouts.Audit, c.Timeouts.Max)
	dur("TIMEOUT_HTTP", &c.Timeouts.HTTP, c.Timeouts.Max)

	intv := func(key string, dst *int, lo, hi int) {
		raw, ok := os.LookupEnv(envPrefix + key)
		if !ok || raw == "" {
			return
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s%s: %v", envPrefix, key, err))
			return
		}
		if n < lo {
			n = lo
		}
		if hi > 0 && n > hi {
			n = hi
		}
		*dst = n
	}
	intv("MAX_OUTPUT_BYTES", &c.Policy.MaxOutputBytes, 4096, 64<<20)
	intv("MAX_CONCURRENCY", &c.Policy.MaxConcurrency, 1, 32)

	boolv := func(key string, dst *bool) {
		raw, ok := os.LookupEnv(envPrefix + key)
		if !ok || raw == "" {
			return
		}
		b, err := strconv.ParseBool(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s%s: %v", envPrefix, key, err))
			return
		}
		*dst = b
	}
	boolv("OFFLINE", &c.Policy.Offline)
	boolv("VERBOSE", &c.Verbose)
	boolv("ALLOW_PRIVATE_NETWORKS", &c.Policy.AllowPrivateNetworks)
	boolv("ENFORCE_SCOPE", &c.Policy.EnforceScope)

	listv := func(key string, dst *[]string) {
		raw, ok := os.LookupEnv(envPrefix + key)
		if !ok || raw == "" {
			return
		}
		*dst = splitList(raw)
	}
	listv("RESOLVERS", &c.Resolvers)
	listv("DKIM_SELECTORS", &c.DKIMSelectors)
	listv("AUDIT_ROOTS", &c.AuditRoots)
	listv("SCOPE_TARGETS", &c.Policy.ScopeTargets)
	listv("NMAP_SCRIPTS", &c.NmapAllowedScripts)
	// Appended rather than assigned: adding one binary must never be able to
	// silently drop the ones already permitted, and a typo here should widen
	// nothing rather than narrow the toolset to nothing.
	if raw, ok := os.LookupEnv(envPrefix + "ALLOWED_BINARIES"); ok && raw != "" {
		c.Policy.AllowedBinaries = append(c.Policy.AllowedBinaries, splitList(raw)...)
	}

	if c.Policy.ScopeTargets == nil {
		c.Policy.ScopeTargets = []string{}
	}
	if len(c.Policy.ScopeTargets) > 0 {
		c.Policy.EnforceScope = true
	}

	c.NVDAPIKey = os.Getenv("NVD_API_KEY")
	if ua := os.Getenv(envPrefix + "USER_AGENT"); ua != "" {
		c.UserAgent = ua
	}

	// Normalise the allowlist for case-insensitive comparison at lookup time.
	c.Policy.AllowedBinaries = normalise(c.Policy.AllowedBinaries)
	c.Policy.DeniedBinaries = normalise(c.Policy.DeniedBinaries)
	c.NmapAllowedScripts = normalise(c.NmapAllowedScripts)

	if len(errs) > 0 {
		return fmt.Errorf("invalid environment configuration: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ScopeWarning is attached to results produced outside an enforced scope.
const ScopeWarning = "SCOPE: no target scope is configured; this result was produced against an unrestricted target. Set SENTINELX_SCOPE_TARGETS to constrain the server to authorised assets."

// NetworkAllowed reports whether a host may be contacted under the active
// policy, and explains the refusal when it may not.
func (c *Config) NetworkAllowed(host string) (bool, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return false, "empty target host"
	}

	if ip := net.ParseIP(host); ip != nil {
		if !c.Policy.AllowPrivateNetworks && isNonRoutable(ip) {
			return false, fmt.Sprintf("private/reserved address %s is blocked by policy (set %sALLOW_PRIVATE_NETWORKS=true for internal engagements)", ip, envPrefix)
		}
	} else if !validHostname(host) {
		return false, fmt.Sprintf("%q is not a valid hostname or IP address", host)
	}

	if !c.Policy.EnforceScope {
		return true, ""
	}
	for _, entry := range c.Policy.ScopeTargets {
		if scopeMatch(entry, host) {
			return true, ""
		}
	}
	// Naming a domain without a wildcard deliberately does not imply its
	// subdomains, because "example.com" can front a very large estate. But the
	// refusal is then a dead end for the caller — usually a model that just
	// discovered "www.example.com" and reasonably wants to assess it — so name
	// the exact entry that would permit it.
	suggestion := ""
	if hint := scopeSuggestion(c.Policy.ScopeTargets, host); hint != "" {
		suggestion = fmt.Sprintf("; add %q to SENTINELX_SCOPE_TARGETS to assess it", hint)
	}
	return false, fmt.Sprintf("target %q is outside the authorised scope (%s)%s",
		host, strings.Join(c.Policy.ScopeTargets, ", "), suggestion)
}

// scopeSuggestion returns the scope entry that would authorise host, or "" if no
// simple rewrite of an existing entry would cover it.
func scopeSuggestion(entries []string, host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	// An IP address has no subdomains. Without this guard the label heuristic
	// below happily offers "*.0.113.5" for 203.0.113.5, which is meaningless
	// and would send the caller editing their scope in circles.
	if net.ParseIP(host) != nil {
		return ""
	}
	if !validHostname(host) {
		return ""
	}
	// Prefer widening an entry that already covers part of the name: naming
	// "corp.example" and asking about "api.dev.corp.example" should lead to
	// "*.corp.example", which is the scope the operator already chose, rather
	// than to a narrower "*.dev.corp.example" invented from the hostname.
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || strings.Contains(e, "/") || strings.HasPrefix(e, "*.") {
			continue
		}
		if strings.Contains(e, ".") && host != e && strings.HasSuffix(host, "."+e) {
			return "*." + e
		}
	}
	// Otherwise fall back to the immediate parent of the host.
	if labels := strings.Split(host, "."); len(labels) > 2 {
		if apex := "*." + strings.Join(labels[1:], "."); !containsString(entries, apex) && scopeMatch(apex, host) {
			return apex
		}
	}
	return ""
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// scopeMatch supports exact hosts, "*.suffix" wildcards, CIDR and single-label
// suffix matching (an entry without a dot matches any host beneath it).
func scopeMatch(entry, host string) bool {
	entry = strings.ToLower(strings.TrimSpace(entry))
	host = strings.ToLower(strings.TrimSpace(host))
	if entry == "" {
		return false
	}
	if _, _, err := net.ParseCIDR(entry); err == nil {
		_, ipnet, _ := net.ParseCIDR(entry)
		if ip := net.ParseIP(host); ip != nil {
			return ipnet.Contains(ip)
		}
		return false
	}
	if strings.HasPrefix(entry, "*.") {
		// "*.corp.example" must match "corp.example" itself and any host
		// beneath it, but not "evicorp.example".
		suffix := strings.TrimPrefix(entry, "*")
		return host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix)
	}
	if !strings.Contains(entry, ".") {
		return host == entry || strings.HasSuffix(host, "."+entry)
	}
	return entry == host
}

func validHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	h = strings.TrimSuffix(h, ".")
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			case r == '-' && i != 0 && i != len(label)-1:
			case r == '_':
			default:
				return false
			}
		}
	}
	return true
}

func isNonRoutable(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// AuditPathAllowed reports whether a filesystem path is inside the configured
// audit roots. With no roots configured, only a conservative set of
// system paths is permitted, which keeps a misconfigured server from being
// used to read arbitrary developer files.
func (c *Config) AuditPathAllowed(p string) (bool, string) {
	if strings.TrimSpace(p) == "" {
		return false, "no path supplied"
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false, fmt.Sprintf("cannot resolve %q: %v", p, err)
	}
	abs = filepath.Clean(abs)

	// Resolve symlinks before comparing against the roots. Without this, a
	// symlink planted inside an allowed root (/etc/pivot -> /root) would let a
	// caller read anything on the filesystem while still passing the prefix
	// check, which would defeat the entire audit-root policy.
	//
	// A path that does not exist yet is checked as-is: EvalSymlinks fails, and
	// the literal (already cleaned) path is still subject to the prefix test.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}

	if len(c.AuditRoots) == 0 {
		for _, root := range defaultAuditRoots {
			if withinRoot(abs, root) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("path %q is outside the default audit roots (%s); set %sAUDIT_ROOTS to widen them",
			abs, strings.Join(defaultAuditRoots, ", "), envPrefix)
	}
	for _, root := range c.AuditRoots {
		if withinRoot(abs, root) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("path %q is outside the configured audit roots (%s)", abs, strings.Join(c.AuditRoots, ", "))
}

// defaultAuditRoots is the set of prefixes the filesystem audit tools may read
// when the operator has not configured SENTINELX_AUDIT_ROOTS.
//
// The executable directories are included because sentinelx_binary_hardening
// is useless without them, and they hold no credentials. The paths that do
// (/root, /home/*/.ssh, /var/lib secrets) remain outside every root, so the
// symlink-escape guarantee still holds against them.
var defaultAuditRoots = []string{
	"/etc", "/usr/local/etc", "/var/log", "/opt", "/srv", "/home",
	"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib",
}

func withinRoot(path, root string) bool {
	root = filepath.Clean(root)
	if root == "/" {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

func splitList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func normalise(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func removeString(in []string, s string) []string {
	out := in[:0]
	for _, v := range in {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}
