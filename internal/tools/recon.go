package tools

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// ---------------------------------------------------------------------------
// recon — passive and non-intrusive information gathering.
//
// Every tool here issues read-only queries: DNS lookups and RDAP/WHOIS
// registration records. Nothing in this file sends a packet crafted to
// provoke a response or alters remote state.
// ---------------------------------------------------------------------------

// RecordTypes is the closed set of DNS record types the tool will query.
var RecordTypes = []string{
	"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "PTR", "DS", "DNSKEY",
}

// Recon returns the information-gathering tools.
func Recon(d Deps) []Tool {
	return []Tool{
		dnsLookupTool(d),
		whoisTool(d),
		reverseLookupTool(d),
		dnsSecurityAuditTool(d),
		subdomainDiscoveryTool(d),
		networkProfileTool(d),
	}
}

// DNSResult is the structured output of a DNS query.
type DNSResult struct {
	Hostname  string       `json:"hostname"`
	Query     string       `json:"query"`
	Records   []DNSRecord  `json:"records"`
	Status    string       `json:"status"`
	Truncated bool         `json:"truncated"`
	Warnings  []string     `json:"warnings,omitempty"`
	Raw       string       `json:"raw,omitempty"`
	Extra     *ExtraOutput `json:"extra,omitempty"`
}

// DNSRecord is one returned resource record.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	TTL   int    `json:"ttl,omitempty"`
	Value string `json:"value"`
}

// ExtraOutput carries optional, heavier payloads such as a zone transfer.
type ExtraOutput struct {
	SOA  []string `json:"soa,omitempty"`
	MX   []string `json:"mx,omitempty"`
	TXT  []string `json:"txt,omitempty"`
	NS   []string `json:"ns,omitempty"`
	Zone []string `json:"zone_transfer,omitempty"`
}

func dnsLookupTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_dns_lookup",
		mcp.WithDescription(
			"Query public DNS records for a hostname using dig. Read-only: performs standard "+
				"DNS queries only and never modifies any zone. Returns parsed A/AAAA/MX/TXT/NS/SOA "+
				"records as JSON, which is the right first call when mapping an asset's public footprint.",
		),
		mcp.WithToolTitle("SENTINEL-X DNS Lookup"),
		mcp.WithString("hostname",
			mcp.Description("Fully-qualified domain name or IP address to query. e.g. example.com"),
			mcp.Required(),
		),
		mcp.WithString("record_type",
			mcp.Description("Single DNS record type to query."),
			mcp.Enum(RecordTypes...),
			mcp.DefaultString("A"),
		),
		mcp.WithBoolean("include_raw",
			mcp.Description("Include the verbatim dig output. Useful when parsing fails, but it inflates the response."),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("authoritative",
			mcp.Description("Query the authoritative name servers directly instead of the recursive resolver."),
			mcp.DefaultBool(false),
		),
		mcp.WithString("resolver",
			mcp.Description("Optional specific resolver to query, e.g. 1.1.1.1. Must be a permitted resolver."),
			mcp.DefaultString(""),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Seconds to wait for dig. Capped by the server policy."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_dns_lookup"

		// Offline mode must be checked before the query, not after: dig would
		// otherwise resolve the name and the response would carry live answers.
		if d.Cfg.Policy.Offline {
			return failf(toolName, "", start, "network access is disabled (SENTINELX_OFFLINE=true)")
		}

		host, aerr := requireArg(req, "hostname")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		host = strings.ToLower(host)
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			return failf(toolName, host, start, "hostname is required")
		}
		if err := scopeCheck(d, host); err != nil {
			return fail(toolName, host, start, err)
		}

		rtype := strings.ToUpper(strings.TrimSpace(req.GetString("record_type", "A")))
		if rtype == "" {
			rtype = "A"
		}
		if !containsFold(RecordTypes, rtype) {
			return failf(toolName, host, start, "unsupported record type %q; allowed: %s", rtype, strings.Join(RecordTypes, ", "))
		}

		bin, err := requireBinary(d, "dig", "nslookup", "host")
		if err != nil {
			return fail(toolName, host, start, err)
		}

		timeout := argTimeout(d, req, d.Cfg.Timeouts.Recon)
		resolver := strings.TrimSpace(req.GetString("resolver", ""))
		if resolver == "" && len(d.Cfg.Resolvers) > 0 {
			resolver = d.Cfg.Resolvers[0]
		}

		var args []string
		switch bin {
		case "dig":
			if resolver != "" {
				args = append(args, "@"+resolver)
			}
			if req.GetBool("authoritative", false) {
				args = append(args, "+norecurse")
			}
			// +time bounds a single DNS transaction; +tries bounds the UDP
			// retransmissions. Both are needed because a resolver that drops
			// the query never returns on its own.
			//
			// The spelling matters: dig has no --timeout option, and rejects
			// the GNU-style form with "Invalid option", exiting non-zero with
			// an empty answer section. That surfaced as "no records returned",
			// which is indistinguishable from a domain that genuinely has none.
			args = append(args,
				"+noall", "+answer", "+comments",
				"+time="+strconv.Itoa(int(timeout.Seconds())),
				"+tries=2",
				host, rtype,
			)
		case "nslookup":
			if resolver != "" {
				args = append(args, host, rtype, resolver)
			} else {
				args = append(args, host, rtype)
			}
		default: // host(1)
			if resolver != "" {
				args = append(args, resolver)
			}
			args = append(args, host)
		}

		out, res, err := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    args,
			Timeout: timeout,
		})
		if err != nil {
			return fail(toolName, host, start, translateExec(err))
		}

		data := parseDig(bin, host, rtype, out)
		if ferr := digFailure(res, len(data.Records), out); ferr != nil {
			return failf(toolName, host, start, "%v", ferr)
		}
		data.Truncated = res.Truncated
		if req.GetBool("include_raw", false) {
			data.Raw = utils.Truncate(out, 8000)
		}
		if data.Status == "" {
			data.Status = "NOERROR"
		}
		if len(data.Records) == 0 && !res.TimedOut {
			data.Warnings = append(data.Warnings, "no records returned; verify the name exists and is not wildcarded")
		}
		return ok(d, toolName, host, start, res, data)
	}
	return Tool{Tool: t, Handler: h,
		Requires: []string{"dig", "nslookup", "host"}}
}

func whoisTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_whois_lookup",
		mcp.WithDescription(
			"Retrieve domain or IP registration data (WHOIS / RDAP-style record) for an asset. "+
				"Use it to establish ownership, registrar, creation date and netblock before any other "+
				"recon. Read-only: a single registration lookup, no enumeration of related domains.",
		),
		mcp.WithToolTitle("SENTINEL-X WHOIS Lookup"),
		mcp.WithString("target",
			mcp.Description("Domain name or IP address to look up."),
			mcp.Required(),
		),
		mcp.WithBoolean("include_raw",
			mcp.Description("Include the verbatim whois output in addition to the parsed fields."),
			mcp.DefaultBool(false),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Seconds to wait for whois. Capped by the server policy."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_whois_lookup"

		// The guard has to precede the whois invocation. Checking it after the
		// call still let the request leave the host.
		if d.Cfg.Policy.Offline {
			return failf(toolName, "", start, "network access is disabled (SENTINELX_OFFLINE=true)")
		}

		target, aerr := requireArg(req, "target")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		target = strings.ToLower(target)
		if target == "" {
			return failf(toolName, target, start, "target is required")
		}
		if err := scopeCheck(d, target); err != nil {
			return fail(toolName, target, start, err)
		}

		bin, err := requireBinary(d, "whois")
		if err != nil {
			return fail(toolName, target, start, fmt.Errorf(
				"the whois client is not installed. Install the `whois` package (apt install whois / brew install whois); "+
					"an RDAP-based fallback is on the roadmap"))
		}

		timeout := argTimeout(d, req, d.Cfg.Timeouts.Recon)
		out, res, err := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    []string{target},
			Timeout: timeout,
		})
		if err != nil {
			return fail(toolName, target, start, translateExec(err))
		}

		data := parseWhois(target, out)
		if req.GetBool("include_raw", false) {
			data.Raw = utils.Truncate(out, 12000)
		}
		if len(data.Registrar) == 0 && len(data.NameServers) == 0 {
			data.Warnings = append(data.Warnings, "whois returned no parsable registration fields; the registry may be rate-limiting or the TLD may be RDAP-only")
		}
		return ok(d, toolName, target, start, res, data)
	}
	return Tool{Tool: t, Handler: h,
		Requires: []string{"whois"}}
}

// ReverseResult is the output of a PTR / ownership check.
type ReverseResult struct {
	Target    string   `json:"target"`
	PTR       []string `json:"ptr,omitempty"`
	Forward   []string `json:"forward_confirmed,omitempty"`
	RDNS      []string `json:"rDNS_scope,omitempty"`
	Netblocks []string `json:"announced_netblocks,omitempty"`
	OwnerHint string   `json:"ownership_hint,omitempty"`
	Findings  []string `json:"findings,omitempty"`
}

func reverseLookupTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_reverse_lookup",
		mcp.WithDescription(
			"Perform a PTR (reverse DNS) lookup on an IP address and, for every name returned, "+
				"verify the forward mapping. Use it to attribute an address to a host or CDN edge and "+
				"to spot dangling records left behind after a decommissioned service. Read-only.",
		),
		mcp.WithToolTitle("SENTINEL-X Reverse DNS Lookup"),
		mcp.WithString("ip",
			mcp.Description("IPv4 or IPv6 address to reverse-resolve."),
			mcp.Required(),
		),
		mcp.WithBoolean("verify_forward",
			mcp.Description("Resolve each PTR name forward and report mismatches (dangling or spoofed rDNS)."),
			mcp.DefaultBool(true),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Seconds to wait for the lookups. Capped by the server policy."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_reverse_lookup"

		// A PTR lookup is still a DNS query, so it is refused offline too.
		if d.Cfg.Policy.Offline {
			return failf(toolName, "", start, "network access is disabled (SENTINELX_OFFLINE=true)")
		}

		ip, aerr := requireArg(req, "ip")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if net.ParseIP(ip) == nil {
			return failf(toolName, ip, start, "%q is not a valid IP address", ip)
		}
		if err := scopeCheck(d, ip); err != nil {
			return fail(toolName, ip, start, err)
		}

		bin, err := requireBinary(d, "dig", "nslookup", "host")
		if err != nil {
			return fail(toolName, ip, start, err)
		}
		timeout := argTimeout(d, req, d.Cfg.Timeouts.Recon)

		var ptrArgs []string
		switch bin {
		case "dig":
			ptrArgs = []string{"+noall", "+answer", "+time=" + strconv.Itoa(int(timeout.Seconds())), "+tries=2", "-x", ip}
		case "nslookup":
			ptrArgs = []string{ip}
		default:
			ptrArgs = []string{"-W", timeout.String(), ip}
		}
		ptrOut, res, err := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    ptrArgs,
			Timeout: timeout,
		})
		if err != nil {
			return fail(toolName, ip, start, translateExec(err))
		}

		data := ReverseResult{Target: ip}
		for _, line := range strings.Split(ptrOut, "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 && strings.EqualFold(f[3], "PTR") {
				data.PTR = append(data.PTR, strings.TrimSuffix(f[4], "."))
			}
		}
		// A failed query must not be reported as "this address has no PTR".
		if ferr := digFailure(res, len(data.PTR), ptrOut); ferr != nil {
			return failf(toolName, ip, start, "%v", ferr)
		}
		if len(data.PTR) == 0 {
			data.Findings = append(data.Findings,
				"no PTR record: the address is not covered by a forward-confirmed reverse zone, which is normal for cloud and CDN egress")
		}

		if req.GetBool("verify_forward", true) && len(data.PTR) > 0 {
			for _, name := range data.PTR {
				var fwdArgs []string
				switch bin {
				case "dig":
					fwdArgs = []string{"+short", "+time=" + strconv.Itoa(int(timeout.Seconds())), name, "A"}
				case "nslookup":
					fwdArgs = []string{name}
				default:
					fwdArgs = []string{name}
				}
				fwdOut, _, err := d.Runner.RunCombined(ctx, utils.Spec{
					Binary:  bin,
					Args:    fwdArgs,
					Timeout: timeout,
				})
				if err != nil {
					continue
				}
				var ips []string
				for _, l := range strings.Split(fwdOut, "\n") {
					if l = strings.TrimSpace(l); net.ParseIP(l) != nil {
						ips = append(ips, l)
					}
				}
				data.Forward = append(data.Forward, fmt.Sprintf("%s -> %s", name, strings.Join(ips, ", ")))
				if len(ips) > 0 && !containsString(ips, ip) {
					data.Findings = append(data.Findings,
						fmt.Sprintf("rDNS mismatch: %s resolves to %s but not to %s; treat any certificate or service name for this address with suspicion",
							name, strings.Join(ips, ", "), ip))
				}
			}
		}
		data.RDNS = data.PTR
		return ok(d, toolName, ip, start, res, data)
	}
	return Tool{Tool: t, Handler: h,
		Requires: []string{"dig", "nslookup", "host"}}
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// parseDig converts dig output into records. It handles both the `+answer`
// form used above and the `host -t TYPE` fallback.
// digFailure turns a dig invocation that did not answer into a real error.
//
// Without this, a dig that exits non-zero — a bad option, a missing resolver, a
// refused query — yields zero records, which parseDig reports as an empty result
// and the tool presents as "no records returned; verify the name exists". That
// reads exactly like a domain with no records, so a broken resolver or a typo in
// the argument list is indistinguishable from a legitimate negative result. The
// whole point of the tool is to tell those two apart.
func digFailure(res *utils.Result, parsed int, out string) error {
	if parsed > 0 || res.ExitCode == 0 {
		return nil
	}
	// Prefer the first line that carries dig's actual complaint.
	reason := strings.TrimSpace(firstMeaningfulLine(out))
	if reason == "" {
		reason = res.Note
	}
	if reason == "" {
		reason = fmt.Sprintf("the query returned no answer (exit status %d)", res.ExitCode)
	}
	return fmt.Errorf("the DNS query did not complete: %s", reason)
}

// firstMeaningfulLine picks the first non-empty line that is not dig's banner
// or a section separator.
func firstMeaningfulLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		return line
	}
	return ""
}

func parseDig(bin, host, rtype, out string) DNSResult {
	res := DNSResult{Hostname: host, Query: rtype, Records: []DNSRecord{}}
	if bin != "dig" {
		res.Records = nslookupToRecords(out, rtype)
		return res
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		// name ttl class type value...
		if !strings.EqualFold(f[3], rtype) && !strings.EqualFold(f[3], "CNAME") {
			continue
		}
		ttl := 0
		fmt.Sscanf(f[1], "%d", &ttl)
		res.Records = append(res.Records, DNSRecord{
			Type:  strings.ToUpper(f[3]),
			Name:  strings.TrimSuffix(f[0], "."),
			TTL:   ttl,
			Value: strings.Join(f[4:], " "),
		})
	}
	return res
}

func nslookupToRecords(out, rtype string) []DNSRecord {
	var recs []DNSRecord
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Name:") {
			continue
		}
		for _, l := range strings.Split(line, "\n")[1:] {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			recs = append(recs, DNSRecord{Type: rtype, Value: strings.TrimPrefix(l, "Address: ")})
		}
	}
	return recs
}

// WhoisResult carries the registration fields that matter for scoping and
// attribution.
type WhoisResult struct {
	Domain       string   `json:"domain,omitempty"`
	Registrar    string   `json:"registrar,omitempty"`
	Registrant   string   `json:"registrant,omitempty"`
	Org          string   `json:"organisation,omitempty"`
	Country      string   `json:"country,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	Expires      string   `json:"expires,omitempty"`
	NameServers  []string `json:"name_servers,omitempty"`
	Status       []string `json:"status,omitempty"`
	NetRange     string   `json:"net_range,omitempty"`
	CIDR         []string `json:"cidr,omitempty"`
	AbuseContact string   `json:"abuse_contact,omitempty"`
	Findings     []string `json:"findings,omitempty"`
	Raw          string   `json:"raw,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

func parseWhois(target, out string) WhoisResult {
	r := WhoisResult{Domain: target}

	// pick finds the value of the first matching key. WHOIS output is
	// consistently indented and its labels vary by registry, so matching is
	// done on a trimmed, lowercased line. Keys are tried longest-first: a line
	// reading "Registrar Abuse Contact Email:" must yield the abuse mailbox,
	// not be captured by the "registrar" key.
	pick := func(keys ...string) string {
		ordered := append([]string(nil), keys...)
		sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
		for _, raw := range strings.Split(out, "\n") {
			line := strings.TrimSpace(raw)
			lower := strings.ToLower(line)
			for _, k := range ordered {
				kl := strings.ToLower(k)
				i := strings.Index(lower, kl)
				if i < 0 {
					continue
				}
				rest := line[i+len(kl):]
				// The label must be followed by a separator, otherwise a
				// substring of a longer label would match.
				if rest == "" || (rest[0] != ':' && rest[0] != ' ' && rest[0] != '\t') {
					continue
				}
				rest = strings.TrimLeft(rest, " \t")
				rest = strings.TrimPrefix(rest, ":")
				if v := strings.TrimSpace(rest); v != "" {
					return v
				}
			}
		}
		return ""
	}

	r.Registrar = pick("registrar", "registrar name", "sponsoring registrar")
	r.Registrant = pick("registrant name", "org-name", "registrant organization", "registrant organisation")
	r.Org = pick("org-name", "organization", "organisation")
	r.Country = pick("country", "country-code")
	r.Created = pick("creation date", "created", "created on", "registered on", "domain registration date")
	r.Updated = pick("updated date", "last updated", "last-update", "modified")
	r.Expires = pick("registry expiry date", "expiry date", "expiration date", "paid-till", "renewal date")
	r.NetRange = pick("netrange", "inetnum", "netname")
	r.AbuseContact = pick("org-abuse-mailbox", "abuse-mailbox", "abuse contact email")

	for _, raw := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case strings.HasPrefix(l, "name server:"), strings.HasPrefix(l, "nserver:"), strings.HasPrefix(l, "nameserver:"):
			if v := whoisValue(raw); v != "" {
				r.NameServers = append(r.NameServers, strings.ToLower(strings.TrimSuffix(v, ".")))
			}
		case strings.HasPrefix(l, "status:"):
			r.Status = append(r.Status, whoisValue(raw))
		case strings.HasPrefix(l, "cidr:"):
			r.CIDR = append(r.CIDR, whoisValue(raw))
		}
	}
	sort.Strings(r.NameServers)
	r.NameServers = dedupe(r.NameServers)

	if r.Country != "" && isSanctionedOrHighRisk(r.Country) {
		r.Findings = append(r.Findings, fmt.Sprintf(
			"registrant country %q is high-risk for sanctions/export-control screening; escalate to compliance before any engagement",
			r.Country))
	}
	if r.Expires != "" && looksLikeSoon(r.Expires) {
		r.Findings = append(r.Findings, "registration expires soon; a lapsed domain is a common subdomain-takeover precondition")
	}
	return r
}

func whoisValue(line string) string {
	if i := strings.Index(line, ":"); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return ""
}

func looksLikeSoon(date string) bool {
	// Deliberately conservative: only flag the obvious year form.
	return strings.HasPrefix(strings.TrimSpace(date), "202")
}

func isSanctionedOrHighRisk(country string) bool {
	switch strings.ToUpper(strings.TrimSpace(country)) {
	case "KP", "IR", "SY", "CU", "RU", "BY", "MM", "AF", "VE":
		return true
	}
	return false
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
