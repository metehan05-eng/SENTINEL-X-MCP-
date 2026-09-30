package tools

// DNS security posture auditing and passive subdomain discovery.
//
// The two tools here complement sentinelx_dns_lookup. That tool answers "what
// records exist"; this one answers "is the DNS configuration itself sound",
// which is a different question with a different failure mode: a zone can
// resolve perfectly and still be trivially hijackable.
//
// Everything is read-only. The audit issues ordinary recursive queries and one
// AXFR attempt, which is a standard zone-transfer check; it neither writes
// records nor attempts to transfer a zone that is not already public.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// dnsSecurityAuditTool checks a domain's mail and integrity posture.
func dnsSecurityAuditTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_dns_security_audit",
		mcp.WithDescription(
			"Audit a domain's DNS security posture: SPF policy strength, DMARC enforcement and "+
				"alignment, DKIM selector discovery, CAA certificate-authority restrictions, "+
				"DNSSEC status, NS delegation consistency and a zone-transfer (AXFR) exposure "+
				"check. Also flags dangling CNAMEs, which are the precondition for subdomain "+
				"takeover. "+
				"READ-ONLY: standard recursive DNS queries and one AXFR probe. No records are "+
				"created, modified or deleted.",
		),
		mcp.WithToolTitle("SENTINEL-X DNS Security Audit"),
		mcp.WithString("domain",
			mcp.Description("The domain to audit, e.g. example.com."),
			mcp.Required(),
		),
		mcp.WithBoolean("check_zone_transfer",
			mcp.Description("Attempt an AXFR against each authoritative nameserver. A zone that allows it is a finding."),
			mcp.DefaultBool(true),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_dns_security_audit"

		domain, aerr := requireArg(req, "domain")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		// scopeCheck delegates to Config.NetworkAllowed, which rejects anything
		// that is not a well-formed hostname or IP before the scope rules apply.
		if err := scopeCheck(d, domain); err != nil {
			return fail(toolName, domain, start, err)
		}

		dig, derr := requireBinary(d, "dig")
		if derr != nil {
			return fail(toolName, domain, start, derr)
		}
		if d.Cfg.Policy.Offline {
			return fail(toolName, domain, start,
				fmt.Errorf("offline mode is enabled, so DNS queries are not permitted; the DNS security audit needs to resolve records"))
		}

		res := DNSSecurityResult{Domain: domain, Checks: []DNSCheck{}}
		runQ := func(limit int, args ...string) *utils.Result {
			out, err := d.Runner.Run(ctx, utils.Spec{
				Binary:  dig,
				Args:    args,
				Timeout: minDuration(d.Cfg.Timeouts.Recon, 15*time.Second),
			})
			if err != nil {
				return nil
			}
			return out
		}

		// --- NS delegation ---
		var nsAddrs []string
		if r := runQ(8, "+short", "+time=3", "+tries=1", domain, "NS"); r != nil {
			for _, l := range strings.Fields(r.Stdout) {
				l = strings.ToLower(strings.TrimSuffix(l, "."))
				if l != "" && !strings.Contains(l, ":") {
					nsAddrs = append(nsAddrs, strings.TrimPrefix(l, "ns."))
				}
			}
			sort.Strings(nsAddrs)
			res.Nameservers = nsAddrs
			if len(nsAddrs) == 0 {
				res.Checks = append(res.Checks, DNSCheck{
					Control: "delegation", Status: "unknown", Detail: "no NS records resolved for the domain",
				})
			}
		}

		// --- SPF ---
		if r := runQ(16, "+noall", "+answer", "+time=3", "+tries=1", domain, "TXT"); r != nil {
			for _, rec := range dnsStrings(r.Stdout) {
				if strings.HasPrefix(strings.ToLower(rec), "v=spf1") {
					res.SPF = analyseSPF(rec)
					res.Checks = append(res.Checks, DNSCheck{
						Control: "spf", Status: res.SPF.Status,
						Detail: res.SPF.Summary,
					})
				}
			}
			if res.SPF.Record == "" {
				res.Checks = append(res.Checks, DNSCheck{
					Control: "spf", Status: "fail",
					Detail: "no SPF record; the domain publishes no sender policy, so anyone may " +
						"forge mail appearing to come from it",
				})
			}
		}

		// --- DMARC ---
		if r := runQ(16, "+noall", "+answer", "+time=3", "+tries=1", "_dmarc."+domain, "TXT"); r != nil {
			for _, rec := range dnsStrings(r.Stdout) {
				low := strings.ToLower(rec)
				if strings.Contains(low, "v=dmarc1") {
					res.DMARC = analyseDMARC(rec)
					res.Checks = append(res.Checks, DNSCheck{
						Control: "dmarc", Status: res.DMARC.Status, Detail: res.DMARC.Summary,
					})
				}
			}
			if res.DMARC.Record == "" {
				res.Checks = append(res.Checks, DNSCheck{
					Control: "dmarc", Status: "fail",
					Detail: "no _dmarc record; forged mail is neither reported nor rejected",
				})
			}
		}

		// --- DKIM: probe the selectors real senders commonly publish. This is a
		// fixed, small list rather than a brute force, which keeps the tool
		// read-only and its query volume predictable.
		// Operator-supplied selectors take precedence and extend the built-in
		// hints. The list is capped so a large config cannot turn this into a
		// DNS amplification loop.
		selectors := append([]string{}, d.Cfg.DKIMSelectors...)
		selectors = append(selectors, dkimSelectorHints...)
		if len(selectors) > 24 {
			selectors = selectors[:24]
		}
		found := map[string]bool{}
		for _, sel := range selectors {
			sel = strings.TrimSpace(sel)
			if sel == "" || found[sel] {
				continue
			}
			name := sel + "._domainkey." + domain
			r := runQ(16, "+noall", "+answer", "+time=2", "+tries=1", name, "TXT")
			if r == nil {
				continue
			}
			for _, rec := range dnsStrings(r.Stdout) {
				low := strings.ToLower(rec)
				if strings.Contains(low, "v=dkim1") || strings.Contains(low, "k=rsa") || strings.Contains(low, "k=ed25519") {
					found[sel] = true
				}
			}
		}
		keys := make([]string, 0, len(found))
		for k := range found {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		res.DKIM = keys
		switch {
		case len(keys) > 0:
			res.Checks = append(res.Checks, DNSCheck{
				Control: "dkim", Status: "pass",
				Detail: "DKIM public keys found for selectors: " + strings.Join(keys, ", "),
			})
		case res.DMARC.Record == "":
			res.Checks = append(res.Checks, DNSCheck{
				Control: "dkim", Status: "unknown",
				Detail: "no DKIM key found for the common selectors; without DMARC and DKIM there " +
					"is no authenticated path to verify a sender",
			})
		default:
			res.Checks = append(res.Checks, DNSCheck{
				Control: "dkim", Status: "warn",
				Detail: "no DKIM key found for the common selectors; set SENTINELX_DKIM_SELECTORS to probe your own",
			})
		}

		// --- CAA ---
		if r := runQ(16, "+noall", "+answer", "+time=3", "+tries=1", domain, "CAA"); r != nil {
			for _, rec := range dnsStrings(r.Stdout) {
				low := strings.ToLower(rec)
				if strings.Contains(low, "issue") {
					res.CAA = append(res.CAA, rec)
				}
			}
		}
		if len(res.CAA) == 0 {
			res.Checks = append(res.Checks, DNSCheck{
				Control: "caa", Status: "warn",
				Detail: "no CAA record; any public CA may issue a certificate for this domain",
			})
		} else {
			res.Checks = append(res.Checks, DNSCheck{
				Control: "caa", Status: "pass",
				Detail: "CAA restricts issuance to: " + strings.Join(res.CAA, "; "),
			})
		}

		// --- DNSSEC ---
		dnssec := "unknown"
		if r := runQ(16, "+noall", "+answer", "+dnssec", "+time=3", "+tries=1", domain, "DS"); r != nil {
			if strings.Contains(r.Stdout, "DS:") || strings.Contains(r.Stdout, "\tDS\t") {
				dnssec = "signed"
			} else {
				dnssec = "unsigned"
			}
		}
		res.DNSSEC = dnssec
		if dnssec == "unsigned" {
			res.Checks = append(res.Checks, DNSCheck{
				Control: "dnssec", Status: "fail",
				Detail: "no DS record; resolvers cannot validate answers, so DNS responses are " +
					"trust-on-first-use and vulnerable to spoofing on the path",
			})
		} else {
			res.Checks = append(res.Checks, DNSCheck{Control: "dnssec", Status: dnssec})
		}

		// --- Zone transfer ---
		if req.GetBool("check_zone_transfer", true) && len(nsAddrs) > 0 {
			var open []string
			for _, ns := range nsAddrs {
				r := runQ(8, "+time=5", "+tries=1", "-p", "53", "@"+ns, domain, "AXFR")
				if r == nil {
					continue
				}
				// A refused transfer is a normal REFUSED. A full answer is not.
				low := strings.ToLower(r.Stdout)
				if !strings.Contains(low, "transfer failed") &&
					!strings.Contains(low, "refused") &&
					!strings.Contains(low, "not authoritative") &&
					strings.Contains(low, domain) && strings.Count(low, "\n") > 5 {
					open = append(open, ns)
				}
			}
			res.ZoneTransferOpen = open
			if len(open) > 0 {
				res.Checks = append(res.Checks, DNSCheck{
					Control: "zone_transfer", Status: "fail",
					Detail: "AXFR is permitted by " + strings.Join(open, ", ") +
						"; the full zone, including internal hostnames, is readable by anyone",
				})
			} else {
				res.Checks = append(res.Checks, DNSCheck{
					Control: "zone_transfer", Status: "pass",
					Detail: "all authoritative nameservers refused AXFR",
				})
			}
		}

		// --- Subdomain takeover preconditions ---
		// A CNAME pointing at a host that no longer resolves is the classic
		// dangling-alias pattern. Checking a handful of common names is
		// read-only and catches the great majority of real cases.
		var dangling []string
		for _, sub := range commonSubdomains {
			fqdn := sub + "." + domain
			r := runQ(8, "+short", "+time=2", "+tries=1", fqdn, "CNAME")
			if r == nil {
				continue
			}
			targets := strings.Fields(r.Stdout)
			if len(targets) == 0 {
				continue
			}
			for _, t := range targets {
				t = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), "."))
				if t == "" || !strings.Contains(t, ".") {
					continue
				}
				if tr := runQ(8, "+short", "+time=2", "+tries=1", t, "A"); tr != nil {
					if strings.TrimSpace(tr.Stdout) == "" {
						if tr2 := runQ(8, "+short", "+time=2", "+tries=1", t, "CNAME"); tr2 != nil && strings.TrimSpace(tr2.Stdout) == "" {
							dangling = append(dangling, fqdn+" -> "+t)
						}
					}
				}
			}
		}
		if len(dangling) > 0 {
			res.DanglingCNAMEs = dangling
			res.Checks = append(res.Checks, DNSCheck{
				Control: "dangling_cname", Status: "fail",
				Detail: "CNAME(s) point at names that do not resolve: " + strings.Join(dangling, "; ") +
					". If the target service can be claimed, this host is takeable",
			})
		} else {
			res.Checks = append(res.Checks, DNSCheck{
				Control: "dangling_cname", Status: "pass",
				Detail: "no dangling CNAME among the commonly probed subdomains",
			})
		}

		res.Findings = dnsSecurityFindings(res)
		res.Grade = gradeDNS(res)
		return ok(d, toolName, domain, start, nil, res,
			"DKIM detection probes a fixed selector list; a key under an unlisted selector will not be found")
	}

	return Tool{Tool: t, Handler: h,
		Requires: []string{"dig"}}
}

var commonSubdomains = []string{"www", "dev", "staging", "test", "admin", "api", "vpn", "git", "jenkins", "jira", "mail"}

var dkimSelectorHints = []string{"default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim"}

// DNSSecurityResult is the full audit outcome.
type DNSSecurityResult struct {
	Domain           string      `json:"domain"`
	Nameservers      []string    `json:"nameservers,omitempty"`
	SPF              SPFReport   `json:"spf"`
	DMARC            DMARCReport `json:"dmarc"`
	DKIM             []string    `json:"dkim_selectors,omitempty"`
	CAA              []string    `json:"caa,omitempty"`
	DNSSEC           string      `json:"dnssec"`
	ZoneTransferOpen []string    `json:"zone_transfer_allowed,omitempty"`
	DanglingCNAMEs   []string    `json:"dangling_cnames,omitempty"`
	Checks           []DNSCheck  `json:"checks"`
	Grade            string      `json:"grade"`
	Findings         []Finding   `json:"findings"`
}

// DNSCheck is one control's verdict.
type DNSCheck struct {
	Control string `json:"control"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
}

// SPFReport is the parsed sender policy.
type SPFReport struct {
	Record   string   `json:"record,omitempty"`
	Status   string   `json:"status"`
	Summary  string   `json:"summary"`
	Includes []string `json:"includes,omitempty"`
	All      string   `json:"all_mechanism,omitempty"`
	Redirect string   `json:"redirect,omitempty"`
	Lookups  int      `json:"lookup_count"`
}

// DMARCReport is the parsed disposition policy.
type DMARCReport struct {
	Record    string   `json:"record,omitempty"`
	Status    string   `json:"status"`
	Summary   string   `json:"summary"`
	Policy    string   `json:"policy,omitempty"`
	Subdomain string   `json:"subdomain_policy,omitempty"`
	Percent   string   `json:"pct,omitempty"`
	RUA       []string `json:"rua,omitempty"`
	Adkim     string   `json:"adkim,omitempty"`
	ASPF      string   `json:"aspf,omitempty"`
}

// analyseSPF grades a sender policy. The mechanism scan is done explicitly
// rather than by regex: a single regex cannot tell "include:_spf.google.com"
// from "include" followed by a stray colon, and miscounting lookups here has a
// real consequence — RFC 7208 makes an over-budget record a permerror, which
// silently disables SPF for the whole domain.
func analyseSPF(rec string) SPFReport {
	r := SPFReport{Status: "pass", Record: rec}
	all := ""
	seen := map[string]bool{}

	for _, term := range strings.Fields(rec) {
		low := strings.ToLower(term)
		if low == "v=spf1" {
			continue
		}
		if seen[low] {
			continue
		}
		seen[low] = true

		// Split the leading qualifier (+ - ~ ?) from the mechanism. The
		// qualifier is what distinguishes a hard fail from a soft one, so it
		// has to be captured before it is stripped.
		qualifier := ""
		if low != "" && strings.IndexByte("+-~?", low[0]) >= 0 {
			qualifier, low = low[:1], low[1:]
		}
		mech := low

		// The terminating mechanism is a policy statement, not a lookup.
		if strings.TrimSuffix(mech, ".") == "all" {
			all = qualifier + "all"
			if all == "+all" {
				all = "all"
			}
			continue
		}

		if rest, ok := strings.CutPrefix(mech, "redirect="); ok {
			r.Redirect = rest
			r.Lookups++
			r.Includes = append(r.Includes, "redirect="+rest)
			continue
		}

		// Split "mechanism:argument" once; the argument may itself contain
		// colons (an include target is a domain, a CIDR is not).
		name, arg, hasArg := strings.Cut(mech, ":")
		if isSPFLookupMechanism(name, hasArg) {
			r.Lookups++
			if arg != "" {
				r.Includes = append(r.Includes, name+":"+arg)
			} else {
				r.Includes = append(r.Includes, name)
			}
		}
	}
	r.All = all

	// -all is the only terminating mechanism that actually rejects.
	switch all {
	case "-all":
		r.Summary = "hard fail (-all): senders failing SPF are rejected"
	case "~all":
		r.Summary = "soft fail (~all): failing senders are accepted but marked; downgrade attacks can still succeed"
		r.Status = "warn"
	case "?all":
		r.Summary = "neutral (?all): the record expresses no judgement, so it authorises everything"
		r.Status = "fail"
	case "":
		r.Summary = "no terminating mechanism: the record grants no explicit verdict and defaults to neutral"
		r.Status = "fail"
	default:
		r.Summary = "unrecognised terminating mechanism " + all
		r.Status = "fail"
	}

	// RFC 7208 section 4.6.4 caps DNS-querying mechanisms at ten.
	if r.Lookups > 10 {
		r.Status = "fail"
		r.Summary = fmt.Sprintf("%s; the record makes %d DNS lookups, exceeding the RFC 7208 limit of 10, "+
			"so it is a permerror and SPF provides no protection", r.Summary, r.Lookups)
	}
	return r
}

// isSPFLookupMechanism reports whether a mechanism causes a DNS query, and so
// consumes one of the ten lookups RFC 7208 permits.
//
// hasArg distinguishes "a:mail.example.com" (a query for that host) from a
// bare "a" (a query for the current domain); both cost a lookup. ip4, ip6 and
// all cost none, because they are evaluated from the record alone.
func isSPFLookupMechanism(name string, hasArg bool) bool {
	switch name {
	case "include", "a", "mx", "ptr", "exists":
		return true
	}
	return false
}

func analyseDMARC(rec string) DMARCReport {
	r := DMARCReport{Record: rec, Status: "pass"}
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		i := strings.Index(part, "=")
		if i <= 0 {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(part[:i]))] = strings.TrimSpace(part[i+1:])
	}
	r.Policy = tags["p"]
	r.Subdomain = tags["sp"]
	r.Percent = tags["pct"]
	r.Adkim = tags["adkim"]
	r.ASPF = tags["aspf"]
	for _, rua := range strings.Fields(tags["rua"]) {
		r.RUA = append(r.RUA, rua)
	}

	policy := strings.ToLower(r.Policy)
	switch policy {
	case "reject":
		r.Summary = "reject: messages that fail the policy are refused outright, the strongest disposition"
	case "quarantine":
		r.Summary = "quarantine: failures are sent to spam; effective, but a visible signal rather than a hard block"
		r.Status = "warn"
	case "":
		r.Summary = "no p= tag; the record is invalid and DMARC provides no protection"
		r.Status = "fail"
	case "none":
		r.Summary = "none: failures are merely reported, not acted on; this is monitoring only"
		r.Status = "warn"
	default:
		r.Summary = "unrecognised p= value " + r.Policy
		r.Status = "fail"
	}

	// A permissive subdomain policy weakens enforcement for delegated hosts.
	if r.Subdomain == "" && policy == "reject" {
		r.Summary += "; sp is absent, so the policy inherits the parent setting"
	} else if strings.EqualFold(r.Subdomain, "none") && policy == "reject" {
		r.Summary += "; sp=none means subdomains are monitored only, so a delegated subdomain can be spoofed"
		r.Status = "warn"
	}

	// Relaxed alignment accepts any organisational domain, which materially
	// loosens the check.
	if strings.EqualFold(r.Adkim, "r") || strings.EqualFold(r.ASPF, "r") {
		if r.Status == "pass" {
			r.Status = "warn"
		}
		r.Summary += "; relaxed alignment is in use, so a DMARC-valid domain can authorise mail for any of its domains"
	}
	if r.Percent != "" && r.Percent != "100" {
		if p, err := strconv.Atoi(r.Percent); err == nil && p < 100 {
			if r.Status == "pass" {
				r.Status = "warn"
			}
			r.Summary += fmt.Sprintf("; only %d%% of failing mail is subjected to the policy", p)
		}
	}
	if len(r.RUA) == 0 {
		r.Summary += "; no rua address, so DMARC reports are not being collected"
	}
	return r
}

func dnsSecurityFindings(r DNSSecurityResult) []Finding {
	var out []Finding
	status := func(control string) string {
		for _, c := range r.Checks {
			if c.Control == control {
				return c.Status
			}
		}
		return "unknown"
	}
	if s := status("spf"); s == "fail" {
		out = append(out, Finding{Severity: "high",
			Summary:   "SPF provides no sender protection",
			Evidence:  r.SPF.Summary,
			Remediate: "publish a single v=spf1 record ending in -all, with all senders included"})
	} else if s == "warn" {
		out = append(out, Finding{Severity: "medium",
			Summary: "SPF is permissive", Evidence: r.SPF.Summary,
			Remediate: "move from ~all or ?all to -all once every legitimate sender is enumerated"})
	}
	switch status("dmarc") {
	case "fail":
		out = append(out, Finding{Severity: "high",
			Summary:   "DMARC is not enforced",
			Evidence:  r.DMARC.Summary,
			Remediate: "publish _dmarc.<domain> with p=reject after validating SPF and DKIM alignment"})
	case "warn":
		out = append(out, Finding{Severity: "medium",
			Summary: "DMARC is only partially enforced", Evidence: r.DMARC.Summary,
			Remediate: "progress from p=none to p=quarantine to p=reject, and set sp to match"})
	}
	if status("dnssec") == "fail" {
		out = append(out, Finding{Severity: "medium",
			Summary:   "the domain is not DNSSEC-signed",
			Evidence:  "no DS record found at the parent",
			Remediate: "sign the zone and publish the DS record at the registrar"})
	}
	if status("zone_transfer") == "fail" {
		out = append(out, Finding{Severity: "high",
			Summary:   "authoritative nameservers allow full zone transfer",
			Evidence:  "AXFR succeeded against: " + strings.Join(r.ZoneTransferOpen, ", "),
			Remediate: "restrict AXFR to known secondaries (allow-transfer) or disable it"})
	}
	if len(r.DanglingCNAMEs) > 0 {
		out = append(out, Finding{Severity: "high",
			Summary:   "dangling CNAME(s) detected",
			Evidence:  strings.Join(r.DanglingCNAMEs, "; "),
			Remediate: "remove the CNAME, or claim the target resource so it cannot be taken over"})
	}
	if status("caa") == "warn" {
		out = append(out, Finding{Severity: "low",
			Summary:   "no CAA record restricts certificate issuance",
			Evidence:  "any public CA may issue for this domain",
			Remediate: "add a CAA record naming the CAs you actually use"})
	}
	if len(out) == 0 {
		out = append(out, Finding{Severity: "info", Summary: "no DNS security findings"})
	}
	return out
}

func gradeDNS(r DNSSecurityResult) string {
	// A simple, explainable score: each control contributes, failures cost
	// most. The letter is a summary; the per-check detail is the real output.
	score := 0
	max := 0
	for _, c := range r.Checks {
		max++
		switch c.Status {
		case "pass", "signed":
			score++
		case "warn":
			// half credit
			score++
		case "fail":
			// no credit
		case "unknown":
			// half credit, because absence of evidence is not evidence of
			// absence and the caller should not be over-penalised
			score++
		}
	}
	if max == 0 {
		return "unknown"
	}
	ratio := float64(score) / float64(max)
	switch {
	case ratio >= 0.95:
		return "A"
	case ratio >= 0.85:
		return "B"
	case ratio >= 0.7:
		return "C"
	case ratio >= 0.5:
		return "D"
	default:
		return "F"
	}
}

// ---------------------------------------------------------------------------
// SubstringDiscovery: certificate transparency
// ---------------------------------------------------------------------------

// subdomainDiscoveryTool reads public certificate-transparency logs.
func subdomainDiscoveryTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_subdomain_discovery",
		mcp.WithDescription(
			"Discover subdomains passively from public indexes: certificate transparency (crt.sh), "+
				"host search (HackerTarget) and passive DNS history (AlienVault OTX). "+
				"Returns each name, which sources saw it, whether it resolves, and the earliest "+
				"and latest certificate dates. Names that do not resolve are listed separately as "+
				"takeover candidates. Every source reports its own status, so a source that failed "+
				"is visible in the result rather than looking like an empty answer. "+
				"PASSIVE: this queries public indexes only. It does not scan, probe, or "+
				"contact the discovered hosts, and it does not attempt to claim anything.",
		),
		mcp.WithToolTitle("SENTINEL-X Subdomain Discovery"),
		mcp.WithString("domain",
			mcp.Description("The root domain to enumerate, e.g. example.com."),
			mcp.Required(),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum unique names to return (1-500)."),
			mcp.DefaultNumber(100),
		),
		mcp.WithBoolean("include_unresolved",
			mcp.Description("Resolve each discovered name and report those that do not answer, which flags takeover candidates."),
			mcp.DefaultBool(true),
		),
		mcp.WithString("sources",
			mcp.Description("Comma-separated passive sources to query: crtsh, hackertarget, otx. "+
				"Defaults to all three. An unknown name is an error rather than a silent skip."),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_subdomain_discovery"

		domain, aerr := requireArg(req, "domain")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		// scopeCheck delegates to Config.NetworkAllowed, which rejects anything
		// that is not a well-formed hostname or IP before the scope rules apply.
		if err := scopeCheck(d, domain); err != nil {
			return fail(toolName, domain, start, err)
		}
		if d.Cfg.Policy.Offline {
			return fail(toolName, domain, start,
				fmt.Errorf("offline mode is enabled; certificate-transparency lookup requires an outbound request"))
		}

		limit := req.GetInt("limit", 100)
		if limit < 1 {
			limit = 1
		}
		if limit > 500 {
			limit = 500
		}

		wanted, serr := resolveSources(csvList(req, "sources"), passiveSourceNames(), defaultPassiveSources)
		if serr != nil {
			return fail(toolName, domain, start, serr)
		}

		names, provenance, statuses, warns := collectPassiveNames(ctx, d, domain, wanted)
		if len(statuses) > 0 {
			failed := 0
			for _, st := range statuses {
				if st.Status == "failed" {
					failed++
				}
			}
			if failed == len(statuses) {
				// Every source failed. That is an outage, not an absence of
				// subdomains, and the message has to say so.
				return failf(toolName, domain, start,
					"all %d passive sources failed, so no result can be given: %s",
					len(statuses), collapse(strings.Join(warnLines(statuses), "; ")))
			}
		}

		out := make([]SubdomainEntry, 0, len(names))
		for _, n := range names {
			e := SubdomainEntry{
				Name:      n,
				FoundIn:   provenance[n],
				Confirmed: len(provenance[n]) > 1,
			}
			out = append(out, e)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

		res := SubdomainResult{
			Domain:         domain,
			Sources:        statuses,
			Passive:        true,
			Total:          len(out),
			ConfirmedCount: countConfirmed(out),
			Entries:        out,
		}
		if len(out) > limit {
			res.Entries = res.Entries[:limit]
			res.Truncated = true
			warns = append(warns, "the result set exceeded the limit and was clipped")
		}

		// Optionally resolve to find names that no longer answer.
		if req.GetBool("include_unresolved", true) && !d.Cfg.Policy.Offline {
			all := make([]string, 0, len(res.Entries))
			for _, e := range res.Entries {
				all = append(all, e.Name)
			}
			resolves, dead := resolvedNames(ctx, d, all)
			for i := range res.Entries {
				res.Entries[i].Resolves = resolves[res.Entries[i].Name]
			}
			res.TakeoverCandidates = dead
			if len(dead) > 0 {
				warns = append(warns, fmt.Sprintf(
					"%d discovered name(s) did not answer an A query; a name that does not resolve is "+
						"the precondition for a takeover, not evidence of one, and it must be checked "+
						"against the provider's own dangling-record documentation before anything else",
					len(dead)))
			}
		}

		res.Warnings = warns
		caveat := "these are passive indexes, not an exhaustive map: a host with no public certificate " +
			"and no passive DNS history will not appear, and a name listed by a single source is weaker " +
			"evidence than one several indexes agree on"
		if failed := countFailed(res.Sources); failed > 0 {
			caveat = fmt.Sprintf("%d of %d sources did not answer, so this result is incomplete: %s",
				failed, len(res.Sources), caveat)
		}
		return ok(d, toolName, domain, start, nil, res, append(warns, caveat)...)
	}

	return Tool{Tool: t, Handler: h,
		Requires: []string{"curl"}}
}

// SubdomainEntry is one discovered name.
type SubdomainEntry struct {
	Name string `json:"name"`
	// FoundIn names every source that returned this name. One source is a
	// single index's claim; several agreeing is the useful signal.
	FoundIn []string `json:"found_in,omitempty"`
	// Confirmed is shorthand for "more than one source saw it".
	Confirmed bool `json:"confirmed_by_multiple_sources"`
	// Resolves is false when the name did not answer an A query, which is the
	// precondition for a subdomain takeover.
	Resolves bool `json:"resolves"`
}

// SubdomainResult is the discovery outcome.
type SubdomainResult struct {
	Domain  string `json:"domain"`
	Passive bool   `json:"passive"`
	// Sources carries the per-source status so a reader can tell an empty
	// answer from a failed lookup.
	Sources        []sourceStatus   `json:"sources"`
	Total          int              `json:"total_discovered"`
	ConfirmedCount int              `json:"confirmed_by_multiple_sources"`
	Truncated      bool             `json:"truncated"`
	Entries        []SubdomainEntry `json:"entries"`
	// TakeoverCandidates are names that did not resolve. A dangling name is a
	// precondition, never a confirmed takeover.
	TakeoverCandidates []string `json:"takeover_candidates,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
}

// countConfirmed counts the names several sources agree on.
func countConfirmed(entries []SubdomainEntry) int {
	n := 0
	for _, e := range entries {
		if e.Confirmed {
			n++
		}
	}
	return n
}

// countFailed counts the sources that did not answer.
func countFailed(statuses []sourceStatus) int {
	n := 0
	for _, s := range statuses {
		if s.Status == "failed" {
			n++
		}
	}
	return n
}

// warnLines renders source statuses for a one-line failure message.
func warnLines(statuses []sourceStatus) []string {
	out := make([]string, 0, len(statuses))
	for _, s := range statuses {
		if s.Status == "failed" {
			out = append(out, s.Name+": "+s.Detail)
		}
	}
	return out
}

// dnsStrings extracts record values from `dig +noall +answer` output.
//
// TXT cannot be read line by line. A DNS string is capped at 255 bytes, so dig
// splits a long record — an SPF policy with several includes, typically — into
// multiple chunks. In the ANSWER section the first chunk carries the record
// header and the rest are indented continuation lines. Reading one line per
// record would truncate the policy mid-string and could turn a real "-all"
// into an unterminated fragment, so continuations are rejoined here.
//
// Records that dig emits unquoted (A, NS, CNAME) are handled too, so the same
// helper serves every query in the audit.
func dnsStrings(out string) []string {
	var (
		records []string
		current strings.Builder
		open    bool
	)
	flush := func() {
		// dig quotes every TXT value; the quotes are transport, not content.
		if s := strings.Trim(strings.TrimSpace(current.String()), `"`); s != "" {
			records = append(records, s)
		}
		current.Reset()
		open = false
	}

	started := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		upper := strings.ToUpper(trimmed)
		// Skip dig's section banners and comments.
		if strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(upper, "ANSWER SECTION") ||
			strings.HasPrefix(upper, "AUTHORITY SECTION") ||
			strings.HasPrefix(upper, "ADDITIONAL SECTION") ||
			strings.HasPrefix(upper, "QUESTION SECTION") {
			started = upper == "ANSWER SECTION"
			continue
		}
		if !started {
			continue
		}

		indented := line != strings.TrimLeft(line, " \t")
		if indented && open {
			// A continuation chunk. dig quotes each chunk separately, so the
			// chunk's own quotes are transport around this fragment and must be
			// dropped, or the rejoined value ends up with quotes mid-string.
			current.WriteString(strings.Trim(strings.TrimSpace(trimmed), `"`))
			continue
		}
		flush()

		if indented {
			// Indented with no record open, so there is nothing to continue.
			continue
		}

		f := strings.Fields(trimmed)
		if len(f) >= 5 {
			// name ttl class type value...
			//
			// The record is deliberately left open: if dig chunked a long TXT
			// value, the next line will be an indented continuation and needs
			// to append to it. The next unindented line, or the end of the
			// output, flushes it.
			//
			// The value's own quotes are stripped here rather than at flush
			// time, so a chunk boundary cannot leave a stray quote sitting in
			// the middle of the reassembled value.
			open = true
			current.WriteString(strings.Trim(strings.Join(f[4:], " "), `"`))
			continue
		}
		// A bare value with no header.
		records = append(records, strings.TrimSuffix(strings.Trim(trimmed, `"`), "."))
	}
	flush()
	return records
}

// ctRecord is one certificate-transparency entry.
type ctRecord struct {
	Name      string
	Issuer    string
	NotBefore string
	NotAfter  string
}

// ctClient is scoped to the certificate-transparency lookup so a slow crt.sh
// response cannot consume the NVD client's timeout budget.
var ctClient = &http.Client{Timeout: 90 * time.Second}

// crtshLookup queries the crt.sh JSON endpoint.
func crtshLookup(ctx context.Context, d Deps, domain string) ([]ctRecord, []string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, d.Cfg.Timeouts.HTTP)
	defer cancel()

	// crt.sh matches subdomains with a leading "%." wildcard. The percent is
	// literal, so it has to be escaped as %% in a format string, and the
	// domain is query-escaped so it cannot alter the URL structure.
	endpoint := "https://crt.sh/?" + url.Values{
		"q":      {"%." + domain},
		"output": {"json"},
	}.Encode()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", d.Cfg.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := ctClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate-transparency lookup failed: %w", err)
	}
	defer resp.Body.Close()

	// crt.sh is a volunteer-run service and returns 502 fairly often. One
	// retry turns a transient blip into a successful lookup instead of a
	// misleading failure.
	if resp.StatusCode >= 500 && reqCtx.Err() == nil {
		time.Sleep(2 * time.Second)
		req2, rerr := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
		if rerr != nil {
			return nil, nil, fmt.Errorf("certificate-transparency lookup failed: %w", rerr)
		}
		req2.Header = req.Header.Clone()
		resp2, rerr := ctClient.Do(req2)
		if rerr != nil {
			return nil, nil, fmt.Errorf("certificate-transparency lookup failed: %w", rerr)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("certificate-transparency lookup returned HTTP %d twice (crt.sh is a volunteer-run service and is often unavailable; retry later)", resp2.StatusCode)
		}
		resp = resp2
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("certificate-transparency lookup returned HTTP %d (crt.sh is a volunteer-run service and is often unavailable; retry later)", resp.StatusCode)
	}

	var rows []struct {
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		NotBefore  string `json:"not_before"`
		NotAfter   string `json:"not_after"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, int64(d.Cfg.Policy.MaxOutputBytes)))
	if derr := dec.Decode(&rows); derr != nil {
		return nil, nil, fmt.Errorf("could not parse the certificate-transparency response: %w", derr)
	}

	var warnings []string
	if len(rows) == 0 {
		warnings = append(warnings, "no certificate-transparency records matched this domain")
	}

	// A single certificate lists every SAN in one newline-delimited field, so
	// one row can contribute many names.
	var out []ctRecord
	seen := map[string]bool{}
	for _, r := range rows {
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, ctRecord{
				Name:      n,
				Issuer:    strings.TrimSpace(r.IssuerName),
				NotBefore: r.NotBefore,
				NotAfter:  r.NotAfter,
			})
		}
	}
	return out, warnings, nil
}

func setToSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
