package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// url_archive is the URL-history equivalent of gau and waybackurls: it asks
// public web archives which URLs were ever observed under a domain.
//
// The important honesty constraint is that these are historical records. An
// archived URL says a path existed at some point; it does not say the path
// exists now, and it certainly does not say it is safe. Every response carries
// that as a standing caveat, because a list of archived paths is exactly the
// input a scanner wants to probe, and a reader who forgets the direction of
// time will treat it as a live route map.

type urlArchiveSource struct {
	Name  string
	Label string
	Query func(ctx context.Context, d Deps, domain string, limit int) ([]string, error)
}

var urlArchiveSources = map[string]urlArchiveSource{
	"wayback": {Name: "wayback", Label: "Internet Archive Wayback Machine", Query: waybackURLs},
	"otx":     {Name: "otx", Label: "AlienVault OTX URL list", Query: otxURLs},
	"cc":      {Name: "cc", Label: "Common Crawl index", Query: commonCrawlURLs},
}

var defaultURLArchiveSources = []string{"wayback", "otx", "cc"}

func urlArchiveSourceNames() []string { return []string{"wayback", "otx", "cc"} }

// ArchivedURL is one recovered path.
type ArchivedURL struct {
	URL string `json:"url"`
	// Path is the path and query, which is what a reader actually scans for.
	Path     string   `json:"path"`
	HasQuery bool     `json:"has_query_string"`
	FoundIn  []string `json:"found_in,omitempty"`
}

// URLArchiveResult is the archive lookup outcome.
type URLArchiveResult struct {
	Domain  string         `json:"domain"`
	Sources []sourceStatus `json:"sources"`
	Total   int            `json:"total_urls"`
	// Unique and WithQueryString are the two numbers worth acting on.
	Unique          int `json:"unique_urls"`
	WithQueryString int `json:"urls_with_query_string"`
	// Endpoint counts reveal the shape of the application: a handful of paths
	// is a small site, thousands under /api/ is not.
	Endpoints       int           `json:"distinct_paths"`
	QueryParamNames []string      `json:"query_parameter_names,omitempty"`
	Truncated       bool          `json:"truncated"`
	URLs            []ArchivedURL `json:"urls"`
	Warnings        []string      `json:"warnings,omitempty"`
}

// waybackURLs reads the Wayback CDX index, collapsing to one row per URL.
func waybackURLs(ctx context.Context, d Deps, domain string, limit int) ([]string, error) {
	// matchType=domain covers the domain and its subdomains. The obvious
	// spelling of this query is a wildcard, url=*.example.com/*, and that form
	// is dramatically slower: measured against the live service it timed out at
	// the gateway after 62s where matchType=domain answered in 37s with the
	// same records. The wildcard is the form every tutorial uses, which is how
	// it ends up in everyone's tooling.
	endpoint := "https://web.archive.org/cdx/search/cdx?" + url.Values{
		"url":       {domain},
		"matchType": {"domain"},
		"output":    {"json"},
		"fl":        {"original"},
		"collapse":  {"urlkey"},
		"limit":     {fmt.Sprint(limit)},
		"filter":    {"statuscode:200"},
	}.Encode()
	body, err := fetchText(ctx, d, endpoint, "application/json", 32<<20, archiveBudget)
	if err != nil {
		return nil, err
	}
	// The first row is the header, and an empty result is a bare "[]".
	var rows [][]string
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, fmt.Errorf("response was not valid JSON: %w", err)
	}
	var out []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue
		}
		out = append(out, row[0])
	}
	return out, nil
}

// otxURLs reads the URL list OTX exposes for a domain.
func otxURLs(ctx context.Context, d Deps, domain string, limit int) ([]string, error) {
	endpoint := "https://otx.alienvault.com/api/v1/indicators/domain/" +
		url.PathEscape(domain) + "/url_list?limit=" + fmt.Sprint(limit) + "&page=1"
	body, err := fetchText(ctx, d, endpoint, "application/json", 32<<20, archiveBudget)
	if err != nil {
		return nil, err
	}
	// url_list is a list of records, not a list of strings: each entry carries
	// the url alongside when it was seen and the status it answered with.
	var payload struct {
		URLList []struct {
			URL      string `json:"url"`
			Hostname string `json:"hostname"`
			Date     string `json:"date"`
		} `json:"url_list"`
		FullSize int `json:"full_size"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil, fmt.Errorf("response was not valid JSON: %w", err)
	}
	out := make([]string, 0, len(payload.URLList))
	for _, r := range payload.URLList {
		if r.URL != "" {
			out = append(out, r.URL)
		}
	}
	return out, nil
}

// currentCrawlIndex asks the collection list which index is live.
//
// Hard-coding an index name looks tidier and is a trap: Common Crawl retires
// them, and a retired index answers 502. The reader then sees a source failure
// that looks like a network problem and has no way to know the cause was a
// constant in our own code.
func currentCrawlIndex(ctx context.Context, d Deps) (string, error) {
	body, err := fetchText(ctx, d, "https://index.commoncrawl.org/collinfo.json",
		"application/json", 1<<20, 0)
	if err != nil {
		return "", err
	}
	var list []struct {
		ID     string `json:"id"`
		API    string `json:"cdx-api"`
		Latest bool   `json:"-"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		return "", fmt.Errorf("collection list was not valid JSON: %w", err)
	}
	if len(list) == 0 {
		return "", fmt.Errorf("collection list was empty")
	}
	// The list is ordered newest first, but a stale entry at the top would
	// silently redirect every lookup, so the id is checked for the shape the
	// collection names actually have.
	if api := list[0].API; api != "" {
		return api, nil
	}
	return "", fmt.Errorf("collection list has no query endpoint")
}

// commonCrawlURLs reads a Common Crawl index, which answers with one JSON
// object per line rather than an array.
func commonCrawlURLs(ctx context.Context, d Deps, domain string, limit int) ([]string, error) {
	api, err := currentCrawlIndex(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("could not determine the current crawl index: %w", err)
	}
	endpoint := api + "?" + url.Values{
		"url":      {"*." + domain},
		"output":   {"json"},
		"filter":   {"status:200"},
		"collapse": {"urlkey"},
		"pageSize": {fmt.Sprint(limit)},
	}.Encode()
	body, err := fetchText(ctx, d, endpoint, "application/x-ndjson", 32<<20, archiveBudget)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			URL string `json:"url"`
		}
		// A malformed line is skipped rather than failing the whole lookup;
		// this index appends non-JSON notices to the stream.
		if json.Unmarshal([]byte(line), &rec) == nil && rec.URL != "" {
			out = append(out, rec.URL)
		}
	}
	return out, nil
}

// inScopeURL keeps a URL only when its host is the domain or beneath it. The
// archives return cross-domain references constantly, and an archived URL on
// someone else's host is not part of this target's surface.
func inScopeURL(domain, raw string) (string, string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", "", false
	}
	host := strings.ToLower(u.Hostname())
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", "", false
	}
	// Collapse to scheme and host so the same path from two archives is one
	// entry, and keep the query, which is often the interesting half.
	clean := "https://" + host + u.Path
	q := u.RawQuery
	if q != "" {
		clean += "?" + q
	}
	return clean, u.RequestURI(), q != ""
}

// collectArchivedURLs runs the sources and merges their results, keeping
// per-source provenance on every URL.
func collectArchivedURLs(ctx context.Context, d Deps, domain string, names []string, limit int) ([]ArchivedURL, []sourceStatus, []string, bool) {
	type outcome struct {
		src   urlArchiveSource
		found []string
		err   error
	}
	results := make([]outcome, len(names))
	done := make(chan int, len(names))
	for i, name := range names {
		go func(i int, name string) {
			src := urlArchiveSources[name]
			found, err := src.Query(ctx, d, domain, limit)
			results[i] = outcome{src: src, found: found, err: err}
			done <- i
		}(i, name)
	}
	for range names {
		<-done
	}

	byURL := map[string]map[string]bool{}
	var statuses []sourceStatus
	var warnings []string
	for _, r := range results {
		if r.err != nil {
			statuses = append(statuses, sourceStatus{
				Name: r.src.Name, Status: "failed", Detail: collapse(r.err.Error()),
			})
			warnings = append(warnings, fmt.Sprintf("source %s did not answer and its URLs are absent: %s",
				r.src.Name, collapse(r.err.Error())))
			continue
		}
		statuses = append(statuses, sourceStatus{Name: r.src.Name, Status: "ok", Names: len(r.found)})
		for _, raw := range r.found {
			clean, _, _ := inScopeURL(domain, raw)
			if clean == "" {
				continue
			}
			if byURL[clean] == nil {
				byURL[clean] = map[string]bool{}
			}
			byURL[clean][r.src.Name] = true
		}
	}

	out := make([]ArchivedURL, 0, len(byURL))
	for u, srcs := range byURL {
		list := make([]string, 0, len(srcs))
		for s := range srcs {
			list = append(list, s)
		}
		sort.Strings(list)
		parsed, err := url.Parse(u)
		path := u
		if err == nil {
			path = parsed.RequestURI()
		}
		out = append(out, ArchivedURL{
			URL:      u,
			Path:     path,
			HasQuery: strings.Contains(path, "?"),
			FoundIn:  list,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, statuses, warnings, false
}

// UrlArchive builds the tool.
func UrlArchive(d Deps) Tool {
	t := mcp.NewTool("sentinelx_url_archive",
		mcp.WithDescription(
			"Recover URLs that web archives have observed under a domain, across the Wayback Machine, "+
				"AlienVault OTX and Common Crawl. Deduplicates across sources, reports which archive saw "+
				"each URL, counts query-string and endpoint shape, and lists any path parameters worth "+
				"reviewing. "+
				"HISTORICAL: an archived URL means the path existed at some point, not that it exists "+
				"now. Nothing here is fetched from the target, and no response is checked for liveness.",
		),
		mcp.WithToolTitle("SENTINEL-X URL Archive"),
		mcp.WithString("domain",
			mcp.Description("The root domain to search archives for, e.g. example.com."),
			mcp.Required(),
		),
		mcp.WithString("sources",
			mcp.Description("Comma-separated archives to query: wayback, otx, cc. Defaults to all three."),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum unique URLs to return (1-2000)."),
			mcp.DefaultNumber(300),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_url_archive"

		domain, aerr := requireArg(req, "domain")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if err := scopeCheck(d, domain); err != nil {
			return fail(toolName, domain, start, err)
		}
		if d.Cfg.Policy.Offline {
			return fail(toolName, domain, start,
				fmt.Errorf("offline mode is enabled; archive lookup requires an outbound request"))
		}

		wanted, serr := resolveSources(csvList(req, "sources"), urlArchiveSourceNames(), defaultURLArchiveSources)
		if serr != nil {
			return fail(toolName, domain, start, serr)
		}

		limit := req.GetInt("limit", 300)
		if limit < 1 {
			limit = 1
		}
		if limit > 2000 {
			limit = 2000
		}

		urls, statuses, warns, _ := collectArchivedURLs(ctx, d, domain, wanted, limit)

		// Shape metrics, computed from what actually survived filtering.
		paths := map[string]bool{}
		params := map[string]bool{}
		withQuery := 0
		for _, u := range urls {
			p := u.Path
			if i := strings.IndexByte(p, '?'); i >= 0 {
				withQuery++
				q, _ := url.ParseQuery(p[i+1:])
				for k := range q {
					params[k] = true
				}
				p = p[:i]
			}
			paths[p] = true
		}

		res := URLArchiveResult{
			Domain:          domain,
			Sources:         statuses,
			Total:           len(urls),
			Unique:          len(urls),
			WithQueryString: withQuery,
			Endpoints:       len(paths),
			QueryParamNames: sortedKeys(params, 40),
			URLs:            urls,
		}
		if len(res.URLs) > limit {
			res.URLs = res.URLs[:limit]
			res.Truncated = true
			warns = append(warns, "the result set exceeded the limit and was clipped")
		}

		caveat := "these are archived observations, not a live route map: a path listed here may be " +
			"gone, may have moved, or may never have existed outside the archive, and no URL in this " +
			"result was checked for reachability or safety"
		if f := countFailed(statuses); f > 0 {
			caveat = fmt.Sprintf("%d of %d archives did not answer, so this result is incomplete: %s",
				f, len(statuses), caveat)
		}
		return ok(d, toolName, domain, start, nil, res, append(warns, caveat)...)
	}

	return Tool{Tool: t, Handler: h}
}

// sortedKeys returns up to max keys, sorted, so the output is deterministic.
func sortedKeys(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}
