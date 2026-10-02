package tools

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// NetworkProfile is the deep, single-target view. The individual tools answer
// one question each; this one answers "what is this host, where does it sit in
// the network, what is it running, and what is wrong with it" in a single call,
// because that is the question an assessor actually starts with and the one a
// model otherwise has to orchestrate across six round trips.
type NetworkProfile struct {
	Target     string           `json:"target"`
	Depth      string           `json:"depth"`
	Identity   HostIdentity     `json:"identity"`
	Path       *NetworkPath     `json:"network_path,omitempty"`
	Host       *HostFingerprint `json:"host,omitempty"`
	Services   *ServiceSurface  `json:"services,omitempty"`
	Exposure   ExposureSummary  `json:"exposure"`
	Risk       []Finding        `json:"findings,omitempty"`
	Coverage   []StageReport    `json:"coverage"`
	CheckedAt  string           `json:"checked_at"`
	Conclusion string           `json:"conclusion"`
}

// HostIdentity is who the address belongs to.
type HostIdentity struct {
	IP            string   `json:"ip,omitempty"`
	ReverseDNS    string   `json:"reverse_dns,omitempty"`
	Organisation  string   `json:"organisation,omitempty"`
	NetRange      string   `json:"net_range,omitempty"`
	CIDR          []string `json:"cidr,omitempty"`
	Country       string   `json:"country,omitempty"`
	AbuseContact  string   `json:"abuse_contact,omitempty"`
	Registrar     string   `json:"registrar,omitempty"`
	NameServers   []string `json:"name_servers,omitempty"`
	Source        string   `json:"source,omitempty"`
	NotDetermined string   `json:"not_determined,omitempty"`
}

// NetworkPath is the hop chain to the target.
type NetworkPath struct {
	Hops      []PathHop `json:"hops"`
	Reachable bool      `json:"reachable"`
	Exhausted bool      `json:"ttl_exhausted,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// PathHop is one router on the way.
type PathHop struct {
	TTL   int     `json:"ttl"`
	IP    string  `json:"ip,omitempty"`
	RTTMS float64 `json:"rtt_ms,omitempty"`
	Star  bool    `json:"no_reply,omitempty"`
}

// HostFingerprint is what nmap concluded the machine is.
type HostFingerprint struct {
	Status    string   `json:"status"`
	OSMatches []string `json:"os_matches,omitempty"`
	CPUs      string   `json:"cpus,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// ServiceSurface is the exposed attack surface.
type ServiceSurface struct {
	Ports        []PortResult `json:"ports"`
	OpenCount    int          `json:"open_ports"`
	Versions     int          `json:"versioned_ports"`
	WebPorts     []int        `json:"web_ports,omitempty"`
	TLSPorts     []int        `json:"tls_ports,omitempty"`
	RawAvailable bool         `json:"raw_available"`
}

// ExposureSummary is the single paragraph a reader wants first.
type ExposureSummary struct {
	Reachable      bool     `json:"reachable"`
	OpenPorts      int      `json:"open_ports"`
	InternetFacing bool     `json:"internet_facing"`
	AdminServices  []string `json:"admin_services,omitempty"`
	LegacyProtocol []string `json:"legacy_or_unencrypted,omitempty"`
	UnknownVersion []string `json:"unversioned_services,omitempty"`
	MaxSeverity    string   `json:"max_severity,omitempty"`
	FindingCount   int      `json:"finding_count"`
}

// StageReport records what was actually attempted. A deep profile that silently
// skipped three of its five stages reads exactly like a deep profile that ran
// all five and found nothing, which is the one distinction a security report
// cannot afford to blur.
type StageReport struct {
	Stage      string `json:"stage"`
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
	Command    string `json:"command,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

func networkProfileTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_network_profile",
		mcp.WithDescription(
			"Deep single-target network profile. Answers \"what is this host, where does it sit, what is it "+
				"running, and what is wrong with it\" in one call: who owns the address, the hop path to it, "+
				"the operating system, every exposed service with its version, and the exposures those "+
				"versions imply. Use this to start an assessment instead of orchestrating "+
				"sentinelx_whois_lookup, sentinelx_port_scan and sentinelx_tls_audit by hand. "+
				"Every stage is reported in `coverage`, including the ones that could not run, so a partial "+
				"result is never mistaken for a clean one. "+
				"SAFETY: read-only profile over the same allowlisted nmap/dig/whois binaries the individual "+
				"tools use. Only against systems you are authorised to assess.",
		),
		mcp.WithToolTitle("SENTINEL-X Deep Network Profile"),
		mcp.WithString("target",
			mcp.Description("A single IP address or hostname. One host only — use sentinelx_port_scan for a CIDR."),
			mcp.Required(),
		),
		mcp.WithString("depth",
			mcp.Description(
				"'quick' = identity and a top-100 service scan. "+
					"'standard' (default) = adds the hop path, OS detection and banner scripts. "+
					"'deep' = adds TLS and cipher enumeration, certificate extraction and version-all probes. "+
					"Deep is slow; it is the right choice when the target is yours and the answer matters."),
			mcp.Enum("quick", "standard", "deep"),
			mcp.DefaultString("standard"),
		),
		mcp.WithString("ports",
			mcp.Description("Optional port spec passed to nmap, e.g. '22,80,443' or '1-1024' or 'top-1000'. Omit for the nmap default."),
			mcp.DefaultString(""),
		),
		mcp.WithBoolean("trace_path",
			mcp.Description("Walk the hop path to the target with nmap --traceroute. Slow and occasionally filtered by intermediate routers."),
			mcp.DefaultBool(true),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Seconds for the whole profile. Split across stages. Capped by SENTINELX_TIMEOUT_MAX."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_network_profile"

		target, aerr := requireArg(req, "target")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if strings.TrimSpace(target) == "" {
			return failf(toolName, target, start, "target is required")
		}
		// The profile is explicitly single-host, so the scope check applies to
		// the whole value rather than to a first entry parsed out of a CIDR.
		if err := scopeCheck(d, target); err != nil {
			return fail(toolName, target, start, err)
		}

		depth := strings.ToLower(strings.TrimSpace(req.GetString("depth", "standard")))
		switch depth {
		case "quick", "standard", "deep":
		default:
			depth = "standard"
		}
		ports := strings.TrimSpace(req.GetString("ports", ""))
		if ports != "" && !validPortSpec(ports) {
			return failf(toolName, target, start,
				"invalid port specification %q: use comma-separated ports and ranges only", ports)
		}

		budget := argTimeout(d, req, d.Cfg.Timeouts.Scan)
		prof := &profileRun{d: d, target: target, depth: depth,
			budget: budget, trace: req.GetBool("trace_path", true)}

		// The identity stage goes first: it is the cheapest and it is what
		// tells a reader whether the address is even theirs to be assessing.
		prof.identity(ctx)
		prof.hostAndServices(ctx, ports)
		if depth != "quick" && prof.host != nil {
			prof.path(ctx)
		}

		data := prof.finish()
		var warn []string
		for _, s := range data.Coverage {
			if s.Status != "ok" {
				warn = append(warn, fmt.Sprintf("stage %q did not complete: %s", s.Stage, s.Detail))
			}
		}
		warn = append(warn, execWarnings(prof.lastCmd)...)
		return ok(d, toolName, target, start, prof.lastCmd, data, warn...)
	}

	return Tool{Tool: t, Handler: h, Requires: []string{"nmap"}}
}

// profileRun carries the state for one profile so the stages read as a
// sequence rather than as one long handler.
type profileRun struct {
	d       Deps
	ctx     context.Context
	target  string
	depth   string
	budget  time.Duration
	trace   bool
	lastCmd *utils.Result

	stages []StageReport
	ident  HostIdentity
	route  *NetworkPath
	host   *HostFingerprint
	svc    *ServiceSurface
}

func (p *profileRun) record(stage, status, detail string, took time.Duration, res *utils.Result) {
	if res != nil {
		p.lastCmd = res
	}
	cmd := ""
	if res != nil {
		cmd = res.CommandLine()
	}
	p.stages = append(p.stages, StageReport{
		Stage: stage, Status: status, Detail: detail, Command: cmd,
		DurationMS: took.Milliseconds(),
	})
}

// identity resolves who the address belongs to. whois is optional: its absence
// downgrades the stage rather than failing the profile, because the rest of the
// analysis does not depend on it.
func (p *profileRun) identity(ctx context.Context) {
	took := time.Now()
	p.ident.IP = p.target
	p.ident.Source = "nmap"

	if bin, err := requireBinary(p.d, "dig"); err == nil {
		if out, res, rerr := p.d.Runner.RunCombined(ctx, utils.Spec{
			Binary: bin, Args: []string{"-x", p.target}, Timeout: 25 * time.Second,
		}); rerr == nil && res != nil {
			p.lastCmd = res
			name := strings.TrimSpace(strings.Split(out, "\n")[len(strings.Split(out, "\n"))-1])
			if idx := strings.Index(name, "="); idx >= 0 {
				name = strings.TrimSpace(name[idx+1:])
			}
			if name != "" && !strings.Contains(name, " ") {
				p.ident.ReverseDNS = name
			}
		}
	}

	if bin, err := requireBinary(p.d, "whois"); err == nil {
		out, res, rerr := p.d.Runner.RunCombined(ctx, utils.Spec{
			Binary: bin, Args: []string{p.target}, Timeout: 25 * time.Second,
		})
		if rerr == nil && res != nil {
			p.lastCmd = res
			w := parseWhois(p.target, out)
			p.ident.Organisation = w.Org
			p.ident.NetRange = w.NetRange
			p.ident.CIDR = w.CIDR
			p.ident.Country = w.Country
			p.ident.AbuseContact = w.AbuseContact
			p.ident.Registrar = w.Registrar
			p.ident.NameServers = w.NameServers
			p.ident.Source = "whois"
		}
	}

	detail := "resolved"
	if p.ident.Organisation == "" && p.ident.NetRange == "" {
		detail = "no registration data; the address may be private, reserved, or whois is unavailable"
		p.ident.NotDetermined = "ownership could not be determined from whois"
	}
	p.record("identity", "ok", detail, time.Since(took), p.lastCmd)
}

// hostAndServices runs the single combined nmap pass that answers both "what
// is this machine" and "what is it running". One process instead of two keeps
// the wall-clock cost of a deep profile tolerable.
func (p *profileRun) hostAndServices(ctx context.Context, ports string) {
	took := time.Now()
	bin, err := requireBinary(p.d, "nmap")
	if err != nil {
		p.record("services", "failed", err.Error(), time.Since(took), nil)
		p.record("host", "skipped", "no scanner available", time.Since(took), nil)
		return
	}

	args := []string{"-sV", "--reason"}
	args = append(args, p.d.Cfg.NmapDefaults...)
	if ports != "" {
		args = append(args, "-p", ports)
	} else if p.depth == "quick" {
		args = append(args, "--top-ports", "100")
	} else if p.depth == "deep" {
		args = append(args, "--top-ports", "1000")
	}

	var wantScripts []string
	if p.depth == "deep" {
		args = append(args, "-O", "--osscan-limit", "--version-all")
		wantScripts = []string{"banner", "http-title", "http-headers", "http-server-header",
			"ssl-cert", "ssl-enum-ciphers", "ssh-hostkey", "smb-os-discovery"}
	} else if p.depth == "standard" {
		args = append(args, "-O", "--osscan-limit")
		wantScripts = []string{"banner", "http-title", "http-server-header"}
	}
	if scripts := allowedScripts(p.d, wantScripts...); len(scripts) > 0 {
		args = append(args, "--script", strings.Join(scripts, ","))
	}

	// nmap gets slightly less than our own budget so it can print its summary
	// rather than being killed mid-write.
	args = append(args, "--host-timeout",
		fmt.Sprintf("%d000ms", max(1, (p.budget-time.Second)/time.Millisecond)))

	out, res, rerr := p.d.Runner.RunCombined(ctx, utils.Spec{
		Binary: bin, Args: append(args, p.target), Timeout: p.budget,
	})
	if rerr != nil {
		p.record("services", "failed", translateExec(rerr).Error(), time.Since(took), nil)
		p.record("host", "skipped", "no scanner result", time.Since(took), nil)
		return
	}
	p.lastCmd = res

	scan := parseNmap(p.target, p.depth, out)
	if len(scan.Hosts) == 0 {
		detail := "no host reported; the target may be down, filtered, or the probe was suppressed"
		if res.TimedOut {
			detail = "the scan timed out before completing; the result is partial"
		}
		p.record("services", "failed", detail, time.Since(took), res)
		p.record("host", "failed", detail, time.Since(took), res)
		p.svc = &ServiceSurface{Ports: []PortResult{}, RawAvailable: false}
		return
	}

	h0 := scan.Hosts[0]
	fp := &HostFingerprint{Status: h0.Status, OSMatches: h0.OSMatches, Hostnames: h0.Hostnames}
	p.host = fp
	p.record("host", "ok", hostDetail(fp), time.Since(took), res)

	svc := &ServiceSurface{Ports: h0.Ports, OpenCount: len(h0.Ports), RawAvailable: scan.RawXMLKept}
	for _, pr := range h0.Ports {
		if pr.Version != "" || pr.Product != "" {
			svc.Versions++
		}
		switch pr.Port {
		case 80, 443, 8080, 8000, 8443, 3000, 5000, 8888:
			svc.WebPorts = append(svc.WebPorts, pr.Port)
		case 22, 23, 21, 25, 110, 143, 445, 1433, 1521, 3306, 5432, 6379, 9200, 27017:
			svc.TLSPorts = append(svc.TLSPorts, pr.Port)
		}
	}
	p.svc = svc
	p.record("services", "ok", serviceDetail(svc), time.Since(took), res)
}

// hostDetail summarises what the fingerprint concluded, including the case
// where nmap guessed nothing, which is common on hardened hosts.
func hostDetail(f *HostFingerprint) string {
	if len(f.OSMatches) == 0 {
		return "host reachable; nmap could not fingerprint the OS"
	}
	return "OS: " + strings.Join(f.OSMatches, "; ")
}

func serviceDetail(s *ServiceSurface) string {
	if s.OpenCount == 0 {
		return "no open ports found in the selected range"
	}
	return fmt.Sprintf("%d open port(s), %d with a version", s.OpenCount, s.Versions)
}

// path walks the hop chain. Intermediate routers commonly drop probes, so a
// trailing run of unresponsive hops is reported rather than hidden.
func (p *profileRun) path(ctx context.Context) {
	took := time.Now()
	bin, err := requireBinary(p.d, "nmap")
	if err != nil {
		p.record("network_path", "failed", err.Error(), time.Since(took), nil)
		return
	}
	// Bounded: a full 30-hop walk can outlast the caller's budget, and a
	// truncated path with an explicit note is more honest than a timeout.
	hopBudget := min(p.budget/2, 90*time.Second)
	out, res, rerr := p.d.Runner.RunCombined(ctx, utils.Spec{
		Binary: bin,
		Args: append([]string{"-sn", "--traceroute", "--max-ttl", "24",
			"--host-timeout", fmt.Sprintf("%d000ms", max(1, hopBudget/time.Millisecond))}, p.target),
		Timeout: hopBudget,
	})
	if rerr != nil {
		p.record("network_path", "failed", translateExec(rerr).Error(), time.Since(took), nil)
		return
	}
	p.lastCmd = res
	np := parseTraceroute(out)
	np.Note = "hops marked no_reply did not answer; intermediate routers commonly filter probes"
	p.route = np
	status := "ok"
	detail := fmt.Sprintf("%d hops observed", len(np.Hops))
	if np.Exhausted {
		detail += "; the path is longer than 24 hops or the TTL was exhausted"
	}
	if res.TimedOut {
		status = "partial"
		detail += "; the walk timed out"
	}
	p.record("network_path", status, detail, time.Since(took), res)
}

var hopRe = regexp.MustCompile(`^\s*(\d+)\s+(?:(\S+)\s+)?(?:([\d.]+)\s+ms)?`)

// parseTraceroute reads the TRACEROUTE block nmap prints. It is deliberately
// tolerant: a hop that does not parse still produces an entry, because a
// partial path with a marked gap is more useful than a dropped path.
func parseTraceroute(out string) *NetworkPath {
	np := &NetworkPath{Hops: []PathHop{}}
	inBlock := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Traceroute") {
			inBlock = true
			continue
		}
		if strings.HasPrefix(trimmed, "Nmap done") {
			inBlock = false
			continue
		}
		if !inBlock {
			continue
		}
		m := hopRe.FindStringSubmatch(line)
		if m == nil || len(np.Hops) >= 24 {
			continue
		}
		ttl, err := strconv.Atoi(m[1])
		if err != nil || ttl <= 0 {
			continue
		}
		hop := PathHop{TTL: ttl}
		if m[2] == "*" {
			hop.Star = true
		} else if m[2] != "" {
			hop.IP = strings.TrimSuffix(m[2], ")")
		}
		if m[3] != "" {
			hop.RTTMS, _ = strconv.ParseFloat(m[3], 64)
		}
		np.Hops = append(np.Hops, hop)
	}
	// A hop that answered with an address is what "the path completed" means.
	// The last one answering is the target; a trailing star run means the walk
	// ran out of TTL before the target answered.
	for i := len(np.Hops) - 1; i >= 0; i-- {
		if np.Hops[i].IP != "" {
			np.Reachable = true
			break
		}
	}
	if len(np.Hops) > 0 {
		np.Exhausted = np.Hops[len(np.Hops)-1].Star
	}
	return np
}

// finish assembles the profile and writes the one-paragraph conclusion that a
// reader actually reads first.
func (p *profileRun) finish() NetworkProfile {
	np := NetworkProfile{
		Target: p.target, Depth: p.depth, Identity: p.ident,
		Path: p.route, Host: p.host, Services: p.svc,
		Coverage: p.stages, CheckedAt: now(),
	}

	exposure := ExposureSummary{}
	if p.svc != nil {
		exposure.OpenPorts = p.svc.OpenCount
		exposure.InternetFacing = p.svc.OpenCount > 0
		for _, pr := range p.svc.Ports {
			label := serviceLabel(pr)
			if isAdminService(pr) {
				exposure.AdminServices = append(exposure.AdminServices, label)
			}
			if isLegacyOrCleartext(pr) {
				exposure.LegacyProtocol = append(exposure.LegacyProtocol, label)
			}
			if pr.Version == "" && pr.Product == "" {
				exposure.UnknownVersion = append(exposure.UnknownVersion, label)
			}
			exposure.InternetFacing = true
		}
	}
	if p.host != nil {
		exposure.Reachable = p.host.Status == "up"
	}
	exposure.AdminServices = dedupe(exposure.AdminServices)
	exposure.LegacyProtocol = dedupe(exposure.LegacyProtocol)
	exposure.UnknownVersion = dedupe(exposure.UnknownVersion)

	np.Risk = p.riskFromSurface()
	exposure.FindingCount = len(np.Risk)
	for _, f := range np.Risk {
		if severityRank(f.Severity) > severityRank(exposure.MaxSeverity) {
			exposure.MaxSeverity = f.Severity
		}
	}
	np.Exposure = exposure
	np.Conclusion = profileConclusion(np)
	return np
}

func serviceLabel(p PortResult) string {
	s := fmt.Sprintf("%d/%s %s", p.Port, p.Protocol, p.Service)
	if p.Product != "" {
		s += " " + p.Product
		if p.Version != "" {
			s += " " + p.Version
		}
	}
	return s
}

func isAdminService(p PortResult) bool {
	switch p.Port {
	case 22, 23, 445, 1433, 1521, 3306, 5432, 5985, 6379, 9200, 27017, 11211:
		return true
	}
	return false
}

func isLegacyOrCleartext(p PortResult) bool {
	switch p.Port {
	case 21, 23, 25, 110, 143, 512, 513, 514, 873, 2049:
		return true
	}
	if p.Port == 80 {
		return true
	}
	return false
}

// riskFromSurface turns exposed services into findings. Every finding carries
// the evidence it came from, because a version string taken from a banner is a
// hypothesis and the report has to say so.
func (p *profileRun) riskFromSurface() []Finding {
	if p.svc == nil {
		return nil
	}
	var out []Finding
	for _, pr := range p.svc.Ports {
		if isAdminService(pr) {
			out = append(out, Finding{
				Severity: "medium",
				Summary:  fmt.Sprintf("Administrative or data-store service exposed: %s", serviceLabel(pr)),
				Evidence: fmt.Sprintf("port %d/%s answered with service %q", pr.Port, pr.Protocol, pr.Service),
				Remediate: "Restrict it to a management network or VPN. An exposed database or cache is " +
					"reachable by anyone who finds the address, not only by your administrators.",
			})
		}
		if isLegacyOrCleartext(pr) {
			out = append(out, Finding{
				Severity:  "medium",
				Summary:   fmt.Sprintf("Cleartext or legacy protocol exposed: %s", serviceLabel(pr)),
				Evidence:  fmt.Sprintf("port %d/%s is %s, which carries credentials or data unencrypted", pr.Port, pr.Protocol, pr.Service),
				Remediate: "Move it behind TLS and retire the protocol if nothing still depends on it.",
			})
		}
		if pr.Version == "" && pr.Product == "" && pr.State == "open" {
			out = append(out, Finding{
				Severity: "low",
				Summary:  fmt.Sprintf("Open port with no version fingerprint: %s", serviceLabel(pr)),
				Evidence: fmt.Sprintf("port %d/%s accepted a connection but no banner was returned", pr.Port, pr.Protocol),
				Remediate: "Identify what is listening. An unfingerprinted service cannot be matched against " +
					"known vulnerabilities at all, so it is a blind spot rather than a clean result.",
			})
		}
		if len(pr.CVEs) > 0 {
			out = append(out, Finding{
				Severity:  "high",
				Summary:   fmt.Sprintf("Candidate known vulnerabilities for %s", serviceLabel(pr)),
				Evidence:  strings.Join(pr.CVEs, ", "),
				Remediate: "Confirm each candidate against the running build; a banner version is a hypothesis, not proof.",
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) > severityRank(out[j].Severity) })
	return out
}

func profileConclusion(np NetworkProfile) string {
	var b strings.Builder
	switch {
	case np.Host == nil:
		fmt.Fprintf(&b, "No host fingerprint was obtained for %s, so nothing below is confirmed to be reachable.",
			np.Target)
	case np.Host.Status != "up":
		b.WriteString("The host did not answer discovery. It may be down, filtered, or refusing probes; no service was confirmed.")
	default:
		fmt.Fprintf(&b, "%s is reachable", np.Target)
		if np.Host.OSMatches != nil {
			fmt.Fprintf(&b, " and looks like %s", strings.Join(np.Host.OSMatches, ", "))
		} else {
			b.WriteString("; the OS could not be fingerprinted")
		}
		if np.Services != nil {
			fmt.Fprintf(&b, ", exposing %d open port(s)", np.Services.OpenCount)
		}
		b.WriteString(".")
	}
	if np.Exposure.InternetFacing && np.Exposure.OpenPorts > 0 {
		fmt.Fprintf(&b, " %d finding(s) recorded, highest severity %s.",
			np.Exposure.FindingCount, orNone(np.Exposure.MaxSeverity))
	}
	skipped := 0
	for _, s := range np.Coverage {
		if s.Status != "ok" {
			skipped++
		}
	}
	if skipped > 0 {
		fmt.Fprintf(&b, " %d of %d stages did not complete — see coverage before treating this as clean.", skipped, len(np.Coverage))
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
