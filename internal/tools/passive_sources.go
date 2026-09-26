package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// This file holds the passive name and URL indexes the reconnaissance tools
// query. They are all read-only HTTP lookups against public archives, so they
// fit the same safety contract as the rest of the server: nothing here sends a
// packet to the target, and nothing here needs the target to be reachable.
//
// The design rule that matters most here is that a source which fails must be
// visibly distinct from a source which found nothing. A tool that quietly
// returns an empty list after a timeout reads as "this domain has no
// subdomains", which is a false statement, and a reader who trusts it stops
// looking. Every source therefore reports its own status and the aggregate
// carries those statuses through to the response.

// sourceStatus is the per-source outcome. Status is one of "ok", "failed" or
// "skipped", and Names is only meaningful when the status is "ok": it is the
// number of candidates the source returned, before domain filtering.
type sourceStatus struct {
	Name   string `json:"source"`
	Status string `json:"status"`
	Names  int    `json:"names_returned,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// passiveSource queries one public index for host names under a domain.
type passiveSource struct {
	// Name is the identifier used in the sources parameter.
	Name string
	// Label is the human-readable service name for the response.
	Label string
	// Query returns raw candidate names. It must not filter by domain; that is
	// applied once, uniformly, by inScopeName.
	Query func(ctx context.Context, d Deps, domain string) ([]string, error)
}

// passiveSources is the registry the sources parameter is validated against.
var passiveSources = map[string]passiveSource{
	"crtsh": {
		Name:  "crtsh",
		Label: "crt.sh certificate transparency",
		Query: crtshNames,
	},
	"hackertarget": {
		Name:  "hackertarget",
		Label: "HackerTarget host search",
		Query: hackertargetNames,
	},
	"otx": {
		Name:  "otx",
		Label: "AlienVault OTX passive DNS",
		Query: otxNames,
	},
}

// passiveSourceNames lists the registry keys for validation.
func passiveSourceNames() []string { return []string{"crtsh", "hackertarget", "otx"} }

// defaultPassiveSources is what runs when the caller does not choose. crt.sh
// leads because it is the only one of the three that sees names which never
// received a publicly trusted certificate.
var defaultPassiveSources = []string{"crtsh", "hackertarget", "otx"}

// resolveSources validates a requested source list. An unknown name is an error
// rather than a silent skip, so a typo cannot quietly narrow coverage and leave
// the caller believing the result is complete.
func resolveSources(requested []string, known []string, def []string) ([]string, error) {
	valid := map[string]bool{}
	for _, k := range known {
		valid[k] = true
	}
	if len(requested) == 0 {
		requested = def
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range requested {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !valid[name] {
			sorted := append([]string(nil), known...)
			sort.Strings(sorted)
			return nil, fmt.Errorf("unknown source %q; available: %s", raw, strings.Join(sorted, ", "))
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		sorted := append([]string(nil), known...)
		sort.Strings(sorted)
		return nil, fmt.Errorf("no usable sources requested; available: %s", strings.Join(sorted, ", "))
	}
	return out, nil
}

// inScopeName normalises a candidate host name and keeps it only when it is
// genuinely beneath the queried domain.
//
// This is the single gate every discovered name passes through, and it is
// deliberately strict. The archives return whatever they were given, including
// names from unrelated domains that share a suffix, so a suffix test that
// forgets the dot would accept "notexample.com" as a subdomain of "example.com".
func inScopeName(domain, raw string) string {
	n := strings.ToLower(strings.TrimSpace(raw))
	// Strip a wildcard label and any stray dots from the edges.
	n = strings.TrimPrefix(n, "*.")
	n = strings.Trim(n, ".")
	if n == "" || n == domain {
		return ""
	}
	if !strings.HasSuffix(n, "."+domain) {
		return ""
	}
	// Reject anything that is not a plausible DNS name. A label longer than 63
	// characters or an empty interior label is not a host, and letting one
	// through would put junk in a report a reader has to check by hand.
	if len(n) > 253 {
		return ""
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !isAlnum {
				return ""
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
	}
	return n
}

// passiveClient is shared by the archive lookups. It is separate from ctClient
// only so a slow archive cannot consume the certificate-transparency budget.
// The client timeout is a backstop above the per-request context deadline.
var passiveClient = &http.Client{Timeout: archiveBudget + 15*time.Second}

// archiveBudget is how long a single web archive gets to answer. The Wayback
// CDX index is frequently slow and routinely needs longer than the ordinary
// HTTP budget, and answering late beats reporting a source as failed when it
// merely took its time. It is still bounded: one dead archive must not hold the
// whole tool hostage, and the sources run concurrently so the cost is paid once.
const archiveBudget = 60 * time.Second

// fetchText performs a bounded GET and returns the body as a string. The
// timeout argument overrides the ordinary HTTP budget for sources that are
// documented to be slow.
func fetchText(ctx context.Context, d Deps, endpoint string, accept string, maxBytes int64, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = d.Cfg.Timeouts.HTTP
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", d.Cfg.UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := passiveClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("service returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// crtshNames reads certificate transparency for names. The heavy lifting is
// already in crtshLookup; this only projects it to names.
func crtshNames(ctx context.Context, d Deps, domain string) ([]string, error) {
	records, _, err := crtshLookup(ctx, d, domain)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Name)
	}
	return out, nil
}

// hackertargetNames reads HackerTarget's host search, which answers in plain
// text with one "host,ip" pair per line.
func hackertargetNames(ctx context.Context, d Deps, domain string) ([]string, error) {
	endpoint := "https://api.hackertarget.com/hostsearch/?" + url.Values{"q": {domain}}.Encode()
	body, err := fetchText(ctx, d, endpoint, "text/plain", 4<<20, 0)
	if err != nil {
		return nil, err
	}
	// The API signals failure with prose on a 200 response, most commonly
	// "API count exceeded" or "No hosts". Treating that as data would put
	// sentences in a list of host names.
	if strings.HasPrefix(strings.TrimSpace(body), "API count exceeded") {
		return nil, fmt.Errorf("rate limited by the service")
	}
	if strings.HasPrefix(strings.TrimSpace(body), "error") {
		return nil, fmt.Errorf("service reported: %s", strings.TrimSpace(collapse(body)))
	}

	var out []string
	for _, line := range strings.Split(body, "\n") {
		// "host,ip" — the name is the first field.
		host, _, _ := strings.Cut(line, ",")
		if host = strings.TrimSpace(host); host != "" {
			out = append(out, host)
		}
	}
	return out, nil
}

// otxNames reads the passive DNS history from AlienVault OTX.
func otxNames(ctx context.Context, d Deps, domain string) ([]string, error) {
	endpoint := "https://otx.alienvault.com/api/v1/indicators/domain/" +
		url.PathEscape(domain) + "/passive_dns"
	body, err := fetchText(ctx, d, endpoint, "application/json", 8<<20, 0)
	if err != nil {
		return nil, err
	}
	var payload struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		// A parse failure is reported rather than treated as an empty result:
		// "the response was not the JSON this expects" and "there were no
		// records" are different facts.
		return nil, fmt.Errorf("response was not valid JSON: %w", err)
	}
	out := make([]string, 0, len(payload.PassiveDNS))
	for _, r := range payload.PassiveDNS {
		out = append(out, r.Hostname)
	}
	return out, nil
}

// collectPassiveNames runs the requested sources concurrently and returns the
// deduplicated in-scope names, the per-source statuses, and one warning per
// source that failed.
//
// The sources are independent, so a single slow or dead service must not decide
// whether the tool answers at all: each runs under the shared context and its
// outcome is recorded either way.
func collectPassiveNames(ctx context.Context, d Deps, domain string, names []string) ([]string, map[string][]string, []sourceStatus, []string) {
	type outcome struct {
		src   passiveSource
		found []string
		err   error
		raw   int
	}
	results := make([]outcome, len(names))
	done := make(chan int, len(names))

	for i, name := range names {
		go func(i int, name string) {
			src := passiveSources[name]
			raw, err := src.Query(ctx, d, domain)
			results[i] = outcome{src: src, found: raw, err: err, raw: len(raw)}
			done <- i
		}(i, name)
	}
	for range names {
		<-done
	}

	agg := map[string]map[string]bool{} // name -> source set
	var statuses []sourceStatus
	var warnings []string
	for _, r := range results {
		if r.err != nil {
			statuses = append(statuses, sourceStatus{
				Name: r.src.Name, Status: "failed", Detail: collapse(r.err.Error()),
			})
			warnings = append(warnings, fmt.Sprintf(
				"source %s did not answer, so its names are absent from this result: %s",
				r.src.Name, collapse(r.err.Error())))
			continue
		}
		statuses = append(statuses, sourceStatus{
			Name: r.src.Name, Status: "ok", Names: r.raw,
		})
		for _, raw := range r.found {
			if n := inScopeName(domain, raw); n != "" {
				if agg[n] == nil {
					agg[n] = map[string]bool{}
				}
				agg[n][r.src.Name] = true
			}
		}
	}

	out := make([]string, 0, len(agg))
	for n := range agg {
		out = append(out, n)
	}
	sort.Strings(out)

	// Provenance: which sources saw each name. Names found by one source are
	// weaker evidence than names several independent indexes agree on.
	provenance := map[string][]string{}
	for n, srcs := range agg {
		list := make([]string, 0, len(srcs))
		for s := range srcs {
			list = append(list, s)
		}
		sort.Strings(list)
		provenance[n] = list
	}
	return out, provenance, statuses, warnings
}

// resolvedNames reports which of the given names answer a DNS query. A name
// that does not resolve is the precondition for a takeover, and separating the
// two is the whole point of asking.
func resolvedNames(ctx context.Context, d Deps, names []string) (map[string]bool, []string) {
	res := map[string]bool{}
	var dead []string
	dig, err := requireBinary(d, "dig")
	if err != nil {
		// Without dig the result must not claim the names are dead. An absent
		// check is reported as absent, not as a clean bill of health.
		for _, n := range names {
			res[n] = true
		}
		return res, []string{"install dig to resolve discovered names; " +
			"takeover candidacy could not be checked and no name should be treated as verified live"}
	}
	for _, n := range names {
		r, rerr := d.Runner.Run(ctx, utils.Spec{
			Binary:  dig,
			Args:    []string{"+short", "+time=2", "+tries=1", n, "A"},
			Timeout: minDuration(d.Cfg.Timeouts.Recon, 8*time.Second),
		})
		// A dig failure and an empty answer are both "did not resolve", but the
		// caller is told to treat the list as candidates, not conclusions, so
		// a transient resolver failure cannot silently promote a live host
		// into the takeover list.
		res[n] = rerr == nil && r != nil && strings.TrimSpace(r.Stdout) != ""
		if !res[n] {
			dead = append(dead, n)
		}
	}
	sort.Strings(dead)
	return res, dead
}
