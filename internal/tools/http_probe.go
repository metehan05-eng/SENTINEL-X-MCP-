package tools

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// ProbeHop is one response in a redirect chain, in order from the first
// request to the last.
//
// The chain is kept rather than collapsed to a final URL because a redirect
// that crosses from https to http, or to a different registrable domain, is a
// finding in its own right and is invisible once flattened.
type ProbeHop struct {
	Status   string `json:"status,omitempty"`
	Location string `json:"location,omitempty"`
	Server   string `json:"server,omitempty"`
}

// ProbedTarget is one target's observed result.
//
// Outcome is a closed vocabulary and the distinction matters more than any
// field below it: refused, timed out, out of scope and never attempted are
// four different facts. Collapsing them into "not responding" is the failure
// mode this type exists to prevent.
type ProbedTarget struct {
	Target    string     `json:"target"`
	FoundIn   []string   `json:"found_in,omitempty"`
	Outcome   string     `json:"outcome"`
	Detail    string     `json:"detail,omitempty"`
	URL       string     `json:"requested_url,omitempty"`
	FinalURL  string     `json:"final_url,omitempty"`
	Scheme    string     `json:"scheme,omitempty"`
	Status    int        `json:"status_code,omitempty"`
	StatusStr string     `json:"status_line,omitempty"`
	Title     string     `json:"title,omitempty"`
	Server    string     `json:"server,omitempty"`
	Tech      string     `json:"web_indicators,omitempty"`
	Bytes     int        `json:"bytes_received,omitempty"`
	Seconds   float64    `json:"elapsed_seconds,omitempty"`
	Redirects int        `json:"redirects,omitempty"`
	Chain     []ProbeHop `json:"redirect_chain,omitempty"`
	Missing   []string   `json:"missing_security_headers,omitempty"`
	Present   []string   `json:"present_security_headers,omitempty"`
	Findings  []Finding  `json:"findings,omitempty"`
}

// ProbedSource records how the target list was assembled, so a name seen only
// in certificate transparency is not presented as if it were enumerated from
// the network.
type ProbedSource struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type ProbeResult struct {
	Domain    string         `json:"domain,omitempty"`
	Sources   []ProbedSource `json:"sources,omitempty"`
	Note      string         `json:"request_note,omitempty"`
	Results   []ProbedTarget `json:"results"`
	Attempted int            `json:"attempted"`
	Responded int            `json:"responded"`
	PlainHTTP int            `json:"responded_over_plain_http"`
	Skipped   int            `json:"skipped_out_of_scope"`
	Failed    int            `json:"did_not_answer"`
	Summary   string         `json:"summary"`
}

var (
	probeTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	probeSpaceRe = regexp.MustCompile(`\s+`)
)

// webIndicators infers the stack from response headers and body markers.
//
// It reports indicators, not confirmed identities. A body marker that is
// absent means the probe did not see that string in a truncated body, which
// is not evidence the technology is missing, so header evidence is listed
// bare and body evidence is labelled as inferred.
func webIndicators(h HTTPResult, body string) string {
	var found []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			found = append(found, s)
		}
	}
	for _, hdr := range []string{"x-powered-by", "x-aspnet-version", "x-generator", "x-rails-version"} {
		if v := h.Headers[hdr]; v != "" {
			add(hdr + ": " + v)
		}
	}
	hay := strings.ToLower(h.Server + " " + body)
	markers := []struct{ needle, label string }{
		{"tornado", "tornado (inferred from body)"},
		{"jinja2", "jinja2 (inferred from body)"},
		{"werkzeug", "werkzeug (inferred from body)"},
		{"express", "express (inferred from body)"},
		{"__next", "next.js (inferred from body)"},
		{"nuxt", "nuxt (inferred from body)"},
		{"wp-content", "wordpress (inferred from body)"},
		{"drupal", "drupal (inferred from body)"},
		{"joomla", "joomla (inferred from body)"},
		{"reactroot", "react (inferred from body)"},
		{"ng-version", "angular (inferred from body)"},
		{"laravel_session", "laravel (inferred from body)"},
		{"csrfmiddleware", "django (inferred from body)"},
	}
	for _, m := range markers {
		if strings.Contains(hay, m.needle) {
			add(m.label)
		}
	}
	sort.Strings(found)
	return strings.Join(found, ", ")
}

// parseProbeChain splits curl's dumped output into one entry per response.
//
// The final result is taken from the last status line rather than the first,
// because with redirects enabled the first block is the 301 and reporting that
// as the outcome would call every redirecting site broken.
//
// curl's --write-out is not used: its %{var} syntax is refused by the argument
// policy, which blocks shell metacharacters in every argv position. Weakening
// that rule to admit one flag would trade a global guarantee for a convenience,
// and the dumped headers already carry everything worth reporting.
func parseProbeChain(out string) (HTTPResult, []ProbeHop) {
	normalised := strings.ReplaceAll(out, "\r\n", "\n")
	blocks := strings.Split(normalised, "\n\n")
	var chain []ProbeHop
	var lastBlock string
	var body strings.Builder

	for _, b := range blocks {
		trimmed := strings.TrimSpace(b)
		if strings.HasPrefix(trimmed, "HTTP/") {
			hop := ProbeHop{}
			for i, line := range strings.Split(b, "\n") {
				line = strings.TrimRight(line, "\r")
				if i == 0 {
					hop.Status = strings.TrimSpace(line)
					continue
				}
				idx := strings.Index(line, ":")
				if idx < 0 {
					continue
				}
				k := strings.ToLower(strings.TrimSpace(line[:idx]))
				v := strings.TrimSpace(line[idx+1:])
				switch k {
				case "location":
					hop.Location = v
				case "server":
					hop.Server = v
				}
			}
			chain = append(chain, hop)
			lastBlock = b
			body.Reset()
			continue
		}
		if lastBlock != "" {
			body.WriteString(b)
		}
	}
	if lastBlock == "" {
		// No status line anywhere: the request never got a response, or curl
		// failed before emitting headers.
		return HTTPResult{Headers: map[string]string{}}, nil
	}

	res := parseHTTPHeaders(lastBlock)
	res.BodyExcerpt = body.String()
	// parseHTTPHeaders kept only the final block's headers, which is what the
	// security review should see, but its Missing list was built from that same
	// block. That is correct, so nothing needs undoing here.
	return res, chain
}

// finalURLFromChain resolves the last hop's Location against the request URL.
func finalURLFromChain(requested string, chain []ProbeHop) string {
	final := requested
	for _, h := range chain {
		if h.Location == "" {
			continue
		}
		base, err := parseURL(final)
		if err != nil {
			continue
		}
		if next, err := base.resolve(h.Location); err == nil {
			final = next
		}
	}
	return final
}

// splitTargetList accepts comma, whitespace or newline separated targets and
// de-duplicates them case-insensitively while preserving order.
func splitTargetList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	var out []string
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		low := strings.ToLower(f)
		if seen[low] {
			continue
		}
		seen[low] = true
		out = append(out, f)
	}
	return out
}

func extractTitle(body string) string {
	m := probeTitleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(probeSpaceRe.ReplaceAllString(m[1], " "))
	if len(t) > 140 {
		t = t[:140] + "…"
	}
	return t
}

func httpProbeTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_http_probe",
		mcp.WithDescription(
			"Probe many web targets at once and report what each one actually served: status, title, "+
				"server, inferred stack, size, latency and redirect count, plus the same security-header "+
				"review used by sentinelx_http_headers. Supply 'domain' to expand it through the passive "+
				"subdomain sources first, and/or 'targets' as a comma-separated list. Concurrency is "+
				"capped and every target is scope-checked individually. A target that refused, timed out, "+
				"was out of scope, or was never attempted is reported distinctly, because those are "+
				"different results. Read-only: one ranged GET per target, no payload, no body upload.",
		),
		mcp.WithToolTitle("SENTINEL-X Bulk HTTP Probe"),
		mcp.WithString("domain",
			mcp.Description("Root domain to expand through passive subdomain discovery and probe, e.g. example.com."),
		),
		mcp.WithString("targets",
			mcp.Description("Comma- or newline-separated hosts or URLs to probe, e.g. 'example.com, a.example.com'."),
		),
		mcp.WithString("schemes",
			mcp.Description("'https', 'http', or 'both' (default) which tries https and falls back to http."),
			mcp.DefaultString("both"),
		),
		mcp.WithNumber("max_targets",
			mcp.Description("Stop after this many targets. Default 50, cap 300."),
			mcp.DefaultNumber(50),
		),
		mcp.WithNumber("concurrency",
			mcp.Description("Concurrent requests. Default 6, cap 16; higher values look like an attack."),
			mcp.DefaultNumber(6),
		),
		mcp.WithBoolean("include_findings",
			mcp.Description("Run the security-header review on each responding target."),
			mcp.DefaultBool(true),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Per-target timeout in seconds. Capped by server policy."),
			mcp.DefaultNumber(0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_http_probe"

		domainRaw := req.GetString("domain", "")
		targetsRaw := req.GetString("targets", "")
		domainRaw = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domainRaw), "."))
		if domainRaw == "" && strings.TrimSpace(targetsRaw) == "" {
			return failf(toolName, "", start, "supply domain, targets, or both")
		}
		if d.Cfg.Policy.Offline {
			return failf(toolName, domainRaw, start, "network access is disabled (SENTINELX_OFFLINE=true)")
		}
		bin, err := requireBinary(d, "curl")
		if err != nil {
			return fail(toolName, domainRaw, start, err)
		}

		// Clamp concurrency. An unbounded fan-out against one domain is how a
		// security tool gets its operator's address blocked.
		conc := clampInt(int(req.GetFloat("concurrency", 6)), 1, 16, 6)
		limit := clampInt(int(req.GetFloat("max_targets", 50)), 1, 300, 50)
		timeout := argTimeout(d, req, d.Cfg.Timeouts.HTTP)
		withFindings := req.GetBool("include_findings", true)

		schemes := splitTargetList(strings.ToLower(req.GetString("schemes", "both")))
		var wantHTTPS, wantHTTP bool
		for _, s := range schemes {
			switch s {
			case "https":
				wantHTTPS = true
			case "http":
				wantHTTP = true
			case "both", "all", "*":
				wantHTTPS, wantHTTP = true, true
			}
		}
		if !wantHTTPS && !wantHTTP {
			wantHTTPS = true
		}

		res := ProbeResult{
			Domain: strings.TrimSpace(domainRaw),
			// A ranged GET is used so a large page cannot be downloaded in
			// full, which means a well-behaved host answers 206 rather than
			// 200. Saying so up front stops a correct 206 from being read as
			// an anomaly, and keeps the bound on response size from looking
			// like an unexplained difference from a browser.
			Note: "each target is fetched with a ranged GET (first 4 KB) to bound " +
				"the response, so a 206 Partial Content status is expected and is " +
				"not itself a finding; the security-header review reads the real " +
				"response headers",
		}
		origin := map[string][]string{}
		var plan []string

		for _, e := range splitTargetList(targetsRaw) {
			plan = append(plan, e)
			origin[e] = []string{"supplied as an explicit target"}
		}

		if res.Domain != "" {
			if err := scopeCheck(d, res.Domain); err != nil {
				return fail(toolName, res.Domain, start, err)
			}
			// The apex is always probed whether or not a passive source
			// mentions it; a source that omits the root is not evidence the
			// root is absent.
			plan = append(plan, res.Domain)
			origin[res.Domain] = []string{"apex domain"}

			names, prov, statuses, _ := collectPassiveNames(ctx, d, res.Domain, nil)
			for _, s := range statuses {
				res.Sources = append(res.Sources, ProbedSource{Source: s.Name, Status: s.Status, Detail: s.Detail})
			}
			for _, n := range names {
				if n == res.Domain {
					continue
				}
				plan = append(plan, n)
				if p := prov[n]; len(p) > 0 {
					origin[n] = p
				} else {
					origin[n] = []string{"passive discovery, source not recorded"}
				}
			}
		}

		if len(plan) == 0 {
			return failf(toolName, res.Domain, start, "no targets to probe")
		}
		if len(plan) > limit {
			plan = plan[:limit]
		}

		// Scope-check every host before any packet leaves, and keep refusals
		// in the output as skipped so "not probed" never reads as "did not
		// answer".
		var runnable []string
		results := make([]ProbedTarget, 0, len(plan))
		for _, t := range plan {
			u, err := parseURL(normaliseTarget(t))
			if err != nil {
				results = append(results, ProbedTarget{Target: t, Outcome: "skipped", Detail: "not a valid host or URL"})
				res.Skipped++
				continue
			}
			if err := scopeCheck(d, u.host()); err != nil {
				results = append(results, ProbedTarget{Target: t, Outcome: "skipped", Detail: "outside the configured scope"})
				res.Skipped++
				continue
			}
			runnable = append(runnable, t)
		}

		if len(runnable) == 0 {
			res.Results = results
			res.Summary = "every target was out of scope or unusable, so no request was sent"
			return ok(d, toolName, res.Domain, start, nil, res)
		}

		sem := make(chan struct{}, conc)
		probed := make([]ProbedTarget, len(runnable))
		var wg sync.WaitGroup
		for i, target := range runnable {
			wg.Add(1)
			go func(idx int, host string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				probed[idx] = probeOne(ctx, d, bin, host, wantHTTPS, wantHTTP, timeout, withFindings)
			}(i, target)
		}
		wg.Wait()

		// Keep caller-supplied order rather than completion order, so the
		// result reads the same way on every run.
		results = append(results, probed...)
		for i := range results {
			if results[i].FoundIn == nil {
				results[i].FoundIn = origin[results[i].Target]
			}
			if results[i].Outcome == "" {
				results[i].Outcome = "not_attempted"
			}
		}
		res.Results = results

		for _, o := range res.Results {
			if o.Outcome == "skipped" {
				res.Skipped++
				continue
			}
			res.Attempted++
			if o.Outcome == "responded" {
				res.Responded++
				if o.Scheme == "http" {
					res.PlainHTTP++
				}
				continue
			}
			res.Failed++
		}
		res.Summary = fmt.Sprintf(
			"%d attempted, %d answered, %d of those over plain http, %d skipped as out of scope, %d did not answer",
			res.Attempted, res.Responded, res.PlainHTTP, res.Skipped, res.Failed)
		if res.Attempted > 0 && res.Responded == 0 {
			res.Summary += "; no target answered, which is an absence of evidence rather than evidence the hosts are down"
		}
		return ok(d, toolName, res.Domain, start, nil, res)
	}

	return Tool{Tool: t, Handler: h}
}

func clampInt(v, lo, hi, def int) int {
	if v == 0 {
		v = def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func normaliseTarget(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "https://" + raw
}

func probeOne(ctx context.Context, d Deps, bin, host string, wantHTTPS, wantHTTP bool, timeout time.Duration, findings bool) ProbedTarget {
	t := ProbedTarget{Target: host}
	attempts := make([]string, 0, 2)
	if wantHTTPS {
		attempts = append(attempts, "https")
	}
	if wantHTTP {
		attempts = append(attempts, "http")
	}

	var detail string
	for _, scheme := range attempts {
		raw := host
		if !strings.Contains(host, "://") {
			raw = scheme + "://" + host
		}
		u, err := parseURL(raw)
		if err != nil {
			t.Outcome, t.Detail = "invalid", err.Error()
			return t
		}
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
		args = append(args, sanitiseURL(u))

		began := time.Now()
		out, _, runErr := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    args,
			Timeout: timeout + 5*time.Second,
		})
		elapsed := time.Since(began).Seconds()
		h, chain := parseProbeChain(out)

		if runErr != nil {
			detail = firstLine(runErr.Error())
			t.Outcome = classifyProbeFailure(detail)
			continue
		}
		if len(chain) == 0 {
			detail = firstLine(out)
			if detail == "" {
				detail = "no HTTP response"
			}
			t.Outcome = "no_response"
			continue
		}

		// A response arrived, including 4xx and 5xx. That is a result, not a
		// failure: a 403 on an admin path is exactly what an assessor wants,
		// and folding it into "unreachable" would hide it.
		t.Outcome = "responded"
		t.URL = raw
		t.FinalURL = finalURLFromChain(raw, chain)
		t.Chain = chain
		t.Redirects = len(chain) - 1
		if t.Redirects < 0 {
			t.Redirects = 0
		}
		if f, err := parseURL(t.FinalURL); err == nil {
			t.Scheme = f.scheme()
		} else {
			t.Scheme = scheme
		}
		t.StatusStr = strings.TrimSpace(h.Status)
		t.Status = statusCodeFromStatusLine(t.StatusStr)
		t.Server = h.Server
		t.Title = extractTitle(h.BodyExcerpt)
		t.Bytes = len(out)
		t.Seconds = elapsed
		if findings {
			// reviewHTTP fills Missing and Present in place, so the copy has
			// to happen after the call, not before.
			t.Findings = reviewHTTP(&h)
			t.Missing = h.Missing
			t.Present = h.Present
		}
		t.Tech = webIndicators(h, h.BodyExcerpt)
		return t
	}

	t.Detail = detail
	if t.Outcome == "" {
		t.Outcome = "no_response"
	}
	return t
}

// classifyProbeFailure names the failure so a refused connection is not
// reported as a timeout. The difference decides whether the operator should
// retry, check the host is up, or fix name resolution.
func classifyProbeFailure(detail string) string {
	l := strings.ToLower(detail)
	switch {
	case strings.Contains(l, "timed out"), strings.Contains(l, "timeout"):
		return "timeout"
	case strings.Contains(l, "could not resolve"), strings.Contains(l, "resolve host"),
		strings.Contains(l, "name or service not known"), strings.Contains(l, "nodename nor servname"),
		strings.Contains(l, "no such host"):
		return "dns_failure"
	case strings.Contains(l, "connection refused"):
		return "connection_refused"
	case strings.Contains(l, "connection reset"):
		return "connection_reset"
	case strings.Contains(l, "no route to host"), strings.Contains(l, "network is unreachable"):
		return "unreachable"
	case strings.Contains(l, "ssl"), strings.Contains(l, "tls"), strings.Contains(l, "certificate"):
		return "tls_failure"
	default:
		return "no_response"
	}
}

// statusCodeFromStatusLine pulls the numeric code out of a status line such as
// "HTTP/2 200" or "HTTP/1.1 301 Moved Permanently".
func statusCodeFromStatusLine(line string) int {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	code := 0
	for _, c := range fields[1] {
		if c < '0' || c > '9' {
			return 0
		}
		code = code*10 + int(c-'0')
	}
	return code
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
