package tools

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// ---------------------------------------------------------------------------
// scanner — service discovery and transport security review.
//
// Scope: nmap is invoked in version-detection and script modes that only read
// and fingerprint. The argument validator blocks output-to-file flags, packet
// crafting, rate-forcing and any script outside the configured allowlist, so
// the module cannot be steered into an offensive or destructive mode.
// ---------------------------------------------------------------------------

// Scanner returns the network scanning tools.
func Scanner(d Deps) []Tool {
	return []Tool{
		portScanTool(d),
		tlsAuditTool(d),
		httpHeadersTool(d),
	}
}

// ScanResult is the parsed output of a port scan.
type ScanResult struct {
	Target     string       `json:"target"`
	ScanType   string       `json:"scan_type"`
	Hosts      []HostResult `json:"hosts"`
	Stats      string       `json:"stats,omitempty"`
	Findings   []Finding    `json:"findings,omitempty"`
	RawXMLKept bool         `json:"raw_available"`
	Warnings   []string     `json:"warnings,omitempty"`
}

// HostResult is per-host scan output.
type HostResult struct {
	IP        string       `json:"ip"`
	Hostnames []string     `json:"hostnames,omitempty"`
	Status    string       `json:"status"`
	OSMatches []string     `json:"os_matches,omitempty"`
	Ports     []PortResult `json:"ports"`
	Warnings  []string     `json:"warnings,omitempty"`
}

// PortResult is a single open port with its service fingerprint.
type PortResult struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	State    string   `json:"state"`
	Service  string   `json:"service"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Extra    string   `json:"extra_info,omitempty"`
	Conf     float64  `json:"confidence,omitempty"`
	CVEs     []string `json:"candidate_cves,omitempty"`
	TLS      []string `json:"tls,omitempty"`
}

// Finding is a prioritised observation derived from the scan.
type Finding struct {
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Evidence  string `json:"evidence,omitempty"`
	Remediate string `json:"remediation,omitempty"`
}

func portScanTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_port_scan",
		mcp.WithDescription(
			"Enumerate open TCP ports and fingerprint the running service version with nmap -sV. "+
				"This is the primary discovery tool: it tells you what software is exposed so it can be "+
				"correlated against known vulnerabilities. "+
				"SAFETY: SENTINEL-X enforces a read-only nmap profile — output-to-file, packet crafting, "+
				"rate forcing and non-allowlisted NSE scripts are rejected before the process starts. "+
				"Only use it against systems you are authorised to assess.",
		),
		mcp.WithToolTitle("SENTINEL-X Port & Service Scan"),
		mcp.WithString("target",
			mcp.Description("Host, IP or CIDR to scan. Must fall inside the configured scope when one is set."),
			mcp.Required(),
		),
		mcp.WithString("ports",
			mcp.Description(
				"Port selection passed to nmap, e.g. '22,80,443', '1-1024', '80,443,8000-8100', or 'top-100'. "+
					"Omit for a nmap default top-ports scan."),
			mcp.DefaultString(""),
		),
		mcp.WithString("scan_profile",
			mcp.Description(
				"Preset controlling effort and detail. "+
					"'quick' = -sV --top-ports 100; "+
					"'standard' = -sV (default); "+
					"'thorough' = -sV -O and the allowlisted fingerprinting scripts; "+
					"'aggressive' = -sV -O --version-all with the allowlisted script set."),
			mcp.Enum("quick", "standard", "thorough", "aggressive"),
			mcp.DefaultString("standard"),
		),
		mcp.WithBoolean("udp",
			mcp.Description("Also scan the three most common UDP services (53, 161, 162). UDP scanning is far slower than TCP; prefer targeted use."),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("skip_host_discovery",
			mcp.Description("Treat the host as up without pinging (-Pn). Useful when the target filters ICMP, which is common for hardened hosts."),
			mcp.DefaultBool(false),
		),
		mcp.WithNumber("max_parallelism",
			mcp.Description("Value for nmap --min-parallelism. Keep low on fragile targets; high values look like an attack."),
			mcp.DefaultNumber(0),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Seconds for the whole scan. Capped by SENTINELX_TIMEOUT_MAX."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_port_scan"

		target, aerr := requireArg(req, "target")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if target == "" {
			return failf(toolName, target, start, "target is required")
		}
		// A CIDR is only meaningful whole; validate the first entry.
		if err := scopeCheck(d, firstHostOf(target)); err != nil {
			return fail(toolName, target, start, err)
		}

		bin, err := requireBinary(d, "nmap")
		if err != nil {
			return fail(toolName, target, start, err)
		}

		profile := strings.ToLower(strings.TrimSpace(req.GetString("scan_profile", "standard")))
		ports := strings.TrimSpace(req.GetString("ports", ""))
		// The port list is handed to nmap as the value of -p. Validate it
		// against a strict grammar rather than relying on the argument
		// denylist: a value like "-sS --script vuln" is a single argv element
		// that no denylist pattern anchored on a flag would match, and it must
		// never reach the command line.
		if ports != "" && !validPortSpec(ports) {
			return failf(toolName, target, start,
				"invalid port specification %q: use comma-separated ports and ranges only, e.g. '22,80,443' or '1-1024'", ports)
		}

		args := []string{"-sV", "--reason"}
		args = append(args, d.Cfg.NmapDefaults...)

		if ports != "" {
			args = append(args, "-p", ports)
		} else if profile == "quick" {
			args = append(args, "--top-ports", "100")
		}

		switch profile {
		case "thorough", "aggressive":
			args = append(args, "-O", "--osscan-limit")
			if scripts := allowedScripts(d, "smb-os-discovery"); len(scripts) > 0 {
				args = append(args, "--script", strings.Join(scripts, ","))
			}
		case "quick":
			// Version detection only; no scripts.
		default:
			if scripts := allowedScripts(d, "banner", "http-title"); len(scripts) > 0 {
				args = append(args, "--script", strings.Join(scripts, ","))
			}
		}
		if profile == "aggressive" {
			args = append(args, "--version-all")
		}
		if req.GetBool("skip_host_discovery", false) {
			args = append(args, "-Pn")
		}
		if req.GetBool("udp", false) {
			args = append(args, "-sU", "-p", "53,161,162")
		}
		if mp := req.GetInt("max_parallelism", 0); mp > 0 {
			if mp > 256 {
				mp = 256
			}
			args = append(args, "--min-parallelism", strconv.Itoa(mp))
		}

		timeout := argTimeout(d, req, d.Cfg.Timeouts.Scan)
		// Give the nmap process slightly less than our own budget so it gets
		// the chance to flush its summary instead of being killed mid-write.
		// Any operator-supplied --host-timeout is dropped first: a duplicated
		// flag makes nmap consume the second occurrence as a duration and abort.
		args = dropFlag(args, "--host-timeout")
		args = append(args, "--host-timeout", fmt.Sprintf("%d000ms", (timeout-time.Second)/time.Millisecond))

		out, res, err := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    append(args, target),
			Timeout: timeout,
		})
		if err != nil {
			return fail(toolName, target, start, translateExec(err))
		}

		data := parseNmap(target, profile, out)
		data.Findings = append(data.Findings, reviewScan(data)...)
		if len(data.Hosts) == 0 && !res.TimedOut {
			data.Warnings = append(data.Warnings, "no hosts reported; the target may be filtered, down, or the ICMP probe was suppressed")
		}
		return ok(d, toolName, target, start, res, data)
	}
	return Tool{Tool: t, Handler: h}
}

// TLSAuditResult reports transport-layer security posture.
type TLSAuditResult struct {
	Target    string        `json:"target"`
	Ports     []string      `json:"ports"`
	Findings  []Finding     `json:"findings,omitempty"`
	Ciphers   []string      `json:"ciphers,omitempty"`
	Certs     []CertSummary `json:"certificates,omitempty"`
	Protocols []string      `json:"protocols,omitempty"`
	// CipherSuites keeps the per-suite detail nmap already parsed out of the
	// script block, so a reader does not have to re-parse the raw excerpt to
	// answer "which suites are weak, and on which protocol version".
	CipherSuites []CipherSuite     `json:"cipher_suites,omitempty"`
	RawExcerpt   string            `json:"raw_excerpt,omitempty"`
	Meta         map[string]string `json:"meta,omitempty"`
}

// CipherSuite is one cipher suite nmap's ssl-enum-ciphers script reported.
type CipherSuite struct {
	Name        string `json:"name"`
	Protocol    string `json:"protocol,omitempty"`
	KeyExchange string `json:"key_exchange,omitempty"`
	// Grade is nmap's own strength letter, A (strongest) to F (weakest).
	Grade string `json:"grade,omitempty"`
}

// CertSummary is the security-relevant part of a certificate.
type CertSummary struct {
	Subject            string   `json:"subject,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	DaysRemaining      int      `json:"days_remaining,omitempty"`
	AltNames           []string `json:"alt_names,omitempty"`
	SelfSigned         bool     `json:"self_signed,omitempty"`
	Expired            bool     `json:"expired,omitempty"`
	WeakHash           bool     `json:"weak_signature_algorithm,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	PublicKeyBits      int      `json:"public_key_bits,omitempty"`
	PublicKeyType      string   `json:"public_key_type,omitempty"`
	// WeakKey is set for RSA keys below 2048 bits.
	WeakKey bool `json:"weak_key,omitempty"`
}

func tlsAuditTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_tls_audit",
		mcp.WithDescription(
			"Review the TLS configuration of one or more hosts: supported protocol versions, accepted "+
				"ciphers, certificate validity, SAN coverage and expiry. Uses nmap's ssl-cert and "+
				"ssl-enum-ciphers scripts, which only complete a handshake and read the result. "+
				"Read-only and non-intrusive.",
		),
		mcp.WithToolTitle("SENTINEL-X TLS Audit"),
		mcp.WithString("target",
			mcp.Description("Host or IP to audit."),
			mcp.Required(),
		),
		mcp.WithString("ports",
			mcp.Description("TLS ports to test. Defaults to the common set."),
			mcp.DefaultString("443,8443,9443,4433"),
		),
		mcp.WithBoolean("enumerate_ciphers",
			mcp.Description("Also enumerate the full cipher suite. Slower, but it is what finds the deprecated suites that the summary hides."),
			mcp.DefaultBool(true),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Seconds for the audit. Capped by server policy."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_tls_audit"

		target, aerr := requireArg(req, "target")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if target == "" {
			return failf(toolName, target, start, "target is required")
		}
		if err := scopeCheck(d, target); err != nil {
			return fail(toolName, target, start, err)
		}
		bin, err := requireBinary(d, "nmap")
		if err != nil {
			return fail(toolName, target, start, err)
		}

		ports := strings.TrimSpace(req.GetString("ports", "443,8443,9443,4433"))
		if ports == "" {
			ports = "443,8443,9443,4433"
		}

		scripts := []string{"ssl-cert"}
		if req.GetBool("enumerate_ciphers", true) {
			scripts = append(scripts, "ssl-enum-ciphers")
		}
		args := []string{
			"-p", ports,
			"--script", strings.Join(scripts, ","),
			"-Pn",
		}
		args = append(args, d.Cfg.NmapDefaults...)

		// Cipher enumeration completes a full TLS handshake per port and then
		// tries every suite the server offers, so it belongs in the scan budget
		// rather than the recon budget. At the 30s recon default this timed out
		// against any endpoint offering a normal suite list, and the timeout
		// used to surface as an empty result that read like a clean server.
		timeout := argTimeout(d, req, d.Cfg.Timeouts.Scan)
		out, res, err := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    append(args, target),
			Timeout: timeout,
		})
		if err != nil {
			return fail(toolName, target, start, translateExec(err))
		}

		data := parseTLS(out, ports)
		data.Target = target
		// An empty parse means nmap never got a handshake, not that the
		// endpoint is clean. Returning a successful result with no
		// certificates, no protocols and no ciphers is indistinguishable from
		// a well-configured server, and a reader has no way to tell that the
		// scan did not run.
		if len(data.Certs) == 0 && len(data.CipherSuites) == 0 && len(data.Protocols) == 0 {
			return failf(toolName, target, start,
				"the TLS audit returned no data: nmap produced no ssl-cert or ssl-enum-ciphers output for ports %s (%s). "+
					"The port may be closed, filtered, or the handshake may have been refused; this is not a clean result",
				ports, describeUnparsedScan(out, res))
		}
		// A certificate without any cipher data is a partial result and is
		// worth flagging, because the caller would otherwise read the missing
		// protocol versions as "only modern TLS".
		if len(data.Certs) > 0 && len(data.CipherSuites) == 0 {
			data.Findings = append(data.Findings, Finding{
				Severity:  "low",
				Summary:   "the certificate was retrieved but the cipher enumeration returned nothing, so no protocol or cipher conclusion can be drawn",
				Evidence:  describeUnparsedScan(out, res),
				Remediate: "re-run the audit; a partial enumeration must not be read as an absence of weak protocols",
			})
		}
		data.Findings = append(data.Findings, reviewTLS(data)...)
		data.RawExcerpt = utils.Truncate(out, 6000)
		return ok(d, toolName, target, start, res, data)
	}
	return Tool{Tool: t, Handler: h}
}

// describeUnparsedScan explains why a scan produced nothing, using the parts of
// nmap's own output that indicate what happened.
func describeUnparsedScan(out string, res *utils.Result) string {
	lower := strings.ToLower(out)
	var reasons []string
	for _, needle := range []struct {
		text string
		why  string
	}{
		{"closed", "the port reported closed"},
		{"filtered", "the port reported filtered"},
		// nmap words this two ways depending on how the probe failed.
		{"host seems down", "the host did not answer"},
		{"host is down", "the host did not answer"},
		{"connection refused", "the connection was refused"},
		{"timed out", "the connection timed out"},
		{"connection timed out", "the connection timed out"},
		{"ssl handshake failed", "the TLS handshake failed"},
	} {
		if strings.Contains(lower, needle.text) {
			reasons = append(reasons, needle.why)
		}
	}
	if len(reasons) == 0 {
		if res != nil && res.TimedOut {
			return "the command timed out"
		}
		return "nmap reported no open TLS service"
	}
	return strings.Join(dedupe(reasons), "; ")
}

// HTTPResult reports the security headers of a web service.
type HTTPResult struct {
	URL         string            `json:"url"`
	Status      string            `json:"status,omitempty"`
	Server      string            `json:"server,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Missing     []string          `json:"missing_security_headers,omitempty"`
	Present     []string          `json:"present_security_headers,omitempty"`
	Findings    []Finding         `json:"findings,omitempty"`
	BodyExcerpt string            `json:"body_excerpt,omitempty"`
}

func httpHeadersTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_http_headers",
		mcp.WithDescription(
			"Fetch a URL and evaluate its response security posture: HSTS, CSP, X-Content-Type-Options, "+
				"X-Frame-Options, Referrer-Policy, cookie flags and server version disclosure. "+
				"Performs a single GET (headers plus a small body excerpt) and reads nothing else. Read-only.",
		),
		mcp.WithToolTitle("SENTINEL-X HTTP Security Headers"),
		mcp.WithString("url",
			mcp.Description("Absolute URL, e.g. https://example.com or https://example.com/admin/login."),
			mcp.Required(),
		),
		mcp.WithBoolean("follow_redirects",
			mcp.Description("Follow up to 5 redirects and report the final URL."),
			mcp.DefaultBool(true),
		),
		mcp.WithBoolean("include_body",
			mcp.Description("Include the first ~2 KB of the response body, which often carries the stack trace or framework banner."),
			mcp.DefaultBool(true),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Seconds for the request. Capped by server policy."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_http_headers"

		raw, aerr := requireArg(req, "url")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if raw == "" {
			return failf(toolName, raw, start, "url is required")
		}
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			raw = "https://" + raw
		}
		u, err := parseURL(raw)
		if err != nil {
			return fail(toolName, raw, start, fmt.Errorf("invalid URL: %w", err))
		}
		if err := scopeCheck(d, u.host()); err != nil {
			return fail(toolName, raw, start, err)
		}
		if d.Cfg.Policy.Offline {
			return failf(toolName, raw, start, "network access is disabled (SENTINELX_OFFLINE=true)")
		}

		bin, err := requireBinary(d, "curl")
		if err != nil {
			return fail(toolName, raw, start, err)
		}

		timeout := argTimeout(d, req, d.Cfg.Timeouts.HTTP)
		// Deny every non-read-only HTTP method and any body transmission.
		args := []string{
			"--silent", "--show-error",
			"--max-time", fmt.Sprintf("%d", int(timeout.Seconds())),
			"--connect-timeout", "10",
			"--max-redirs", "5",
			"--user-agent", d.Cfg.UserAgent,
			"--proto", "=http,https",
			"--proto-redir", "=http,https",
			"--tlsv1.2",
			"--dump-header", "-",
			"--range", "0-4095",
			"-X", "GET",
		}
		if !req.GetBool("follow_redirects", true) {
			args = append(args, "--head")
		}
		// Strip credentials that may have been pasted into the URL.
		args = append(args, sanitiseURL(u))

		out, res, err := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    args,
			Timeout: timeout + 5*time.Second,
		})
		if err != nil {
			return fail(toolName, raw, start, translateExec(err))
		}

		data := parseHTTPHeaders(out)
		data.URL = u.String()
		if req.GetBool("include_body", true) {
			data.BodyExcerpt = utils.Truncate(data.BodyExcerpt, 2048)
		} else {
			data.BodyExcerpt = ""
		}
		data.Findings = reviewHTTP(data)
		return ok(d, toolName, data.URL, start, res, data)
	}
	return Tool{Tool: t, Handler: h}
}

// ---------------------------------------------------------------------------
// Argument assembly helpers
// ---------------------------------------------------------------------------

// allowedScripts filters the requested NSE scripts through the configured
// allowlist. It never trusts the caller's list, so the scanner cannot be used
// to run an arbitrary script file.
// dropFlag removes every occurrence of a value-taking flag, together with the
// argument that supplies its value. nmap aborts on a duplicated flag, because
// it consumes the second occurrence as the first one's duration.
func dropFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++ // also skip this flag's value
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func allowedScripts(d Deps, requested ...string) []string {
	want := make(map[string]bool, len(requested))
	for _, s := range requested {
		want[strings.ToLower(s)] = true
	}
	var out []string
	for _, s := range d.Cfg.NmapAllowedScripts {
		if want[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func firstHostOf(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return t
	}
	if i := strings.IndexAny(t, "/ "); i > 0 {
		t = t[:i]
	}
	if i := strings.Index(t, ","); i > 0 {
		t = t[:i]
	}
	return t
}
