package tools

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// xssCanary is the marker injected into each candidate parameter.
//
// It is a unique, inert string. A parameter that returns it in the response
// body echoed the input somewhere it should not have, which is a necessary but
// not sufficient condition for XSS: the context matters (HTML body, attribute,
// script, URL) and this check does not attempt to establish which. What it can
// say precisely is "this parameter is reflected without encoding", which is the
// useful triage signal. Claiming XSS from a reflection alone would be exactly
// the kind of overclaim this server is built not to make.
const xssCanary = "sxq7z4k2v9"

// xssContext classifies where a payload was reflected, because the same
// reflection is benign in one context and exploitable in another.
func xssContext(where string) string {
	w := strings.ToLower(where)
	switch {
	case strings.Contains(w, "attribute"):
		return "html attribute"
	case strings.Contains(w, "javascript:") || strings.Contains(w, "script"):
		return "script or javascript URL context"
	case strings.Contains(w, "css"):
		return "style or css context"
	case strings.Contains(w, "comment"):
		return "html comment"
	case strings.Contains(w, "url") || strings.Contains(w, "href") || strings.Contains(w, "src"):
		return "url context"
	default:
		return "html body or unknown"
	}
}

// XSSCandidate is one parameter that reflected the canary.
type XSSCandidate struct {
	Parameter    string `json:"parameter"`
	Location     string `json:"reflected_in,omitempty"`
	Context      string `json:"context,omitempty"`
	EncodingSeen bool   `json:"output_encoded"`
	Verdict      string `json:"verdict"`
}

type XSSResult struct {
	URL              string         `json:"url"`
	Method           string         `json:"method"`
	Traffic          string         `json:"traffic_class"`
	Note             string         `json:"note"`
	ParametersTested []string       `json:"parameters_tested"`
	Candidates       []XSSCandidate `json:"candidates"`
	Count            int            `json:"candidates_count"`
	Confirmed        int            `json:"execution_confirmed"`
	Elapsed          float64        `json:"elapsed_seconds"`
}

func xssProbeTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_xss_probe",
		mcp.WithDescription(
			"Test URL parameters for reflected injection by injecting a unique inert canary and checking "+
				"whether the response echoes it. This is triage, not confirmation: it reports 'reflected "+
				"without encoding' and never claims XSS is exploitable, because exploitability depends on "+
				"the injection context and on whether a browser executes it, neither of which this tool "+
				"tests. execution_confirmed is always 0 here — dalfox or a headless browser is needed for "+
				"that. Sends the canary string to the target, so it produces traffic a plain GET would not. "+
				"This tool is not read-only and does not advertise the read-only annotation.",
		),
		mcp.WithToolTitle("SENTINEL-X Reflected Injection Triage"),
		mcp.WithString("url",
			mcp.Description("Absolute URL including the query string to test, e.g. https://example.com/search?q=1&page=2."),
			mcp.Required(),
		),
		mcp.WithString("parameters",
			mcp.Description("Parameters to test, comma separated. Defaults to every parameter in the URL's query string."),
		),
		mcp.WithBoolean("test_body",
			mcp.Description("Also test the parameter appearing in a POST form body. Sends a POST rather than a GET."),
			mcp.DefaultBool(false),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Per-request timeout. Capped by server policy."),
			mcp.DefaultNumber(0),
		),
	)

	handler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_xss_probe"

		raw, aerr := requireArg(req, "url")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
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

		parsed, perr := url.Parse(raw)
		if perr != nil {
			return fail(toolName, raw, start, fmt.Errorf("invalid URL: %w", perr))
		}
		query := parsed.Query()

		var params []string
		if given := splitTargetList(req.GetString("parameters", "")); len(given) > 0 {
			for _, p := range given {
				if !query.Has(p) {
					return failf(toolName, raw, start,
						"parameter %q is not present in the URL's query string; pass it in the url so the "+
							"request shape is the one actually being assessed", p)
				}
			}
			params = given
		} else {
			for k := range query {
				params = append(params, k)
			}
			sort.Strings(params)
		}
		if len(params) == 0 {
			return failf(toolName, raw, start, "the URL has no query parameters to test")
		}
		if len(params) > 20 {
			return failf(toolName, raw, start, "%d parameters requested, cap is 20 per call", len(params))
		}

		timeout := argTimeout(d, req, d.Cfg.Timeouts.HTTP)
		postBody := req.GetBool("test_body", false)

		res := XSSResult{
			URL:     sanitiseURL(u),
			Method:  "GET",
			Traffic: "canary injection",
			Note: "A reflected canary means the parameter's value reached the response without output " +
				"encoding. That is the precondition for injection, not proof of it: the same reflection " +
				"inside an HTML comment or a text node may be inert, and only a browser can show whether " +
				"a payload executes. Nothing here is reported as an exploitable vulnerability.",
			ParametersTested: params,
			Candidates:       []XSSCandidate{},
			// Stated explicitly rather than left to inference: this tool has
			// no browser, so it cannot confirm execution.
			Confirmed: 0,
		}
		if postBody {
			res.Method = "GET then POST"
			res.Note += " A POST was also sent for each parameter, so the target saw form submissions " +
				"rather than only reads."
		}

		began := time.Now()
		for _, p := range params {
			// Baseline first: a canary appearing in an unmodified response
			// would otherwise be read as a reflection, and a page that simply
			// echoes the whole query string is exactly the case where that
			// mistake happens.
			baseline, err := xssFetch(ctx, d, bin, raw, p, "", timeout, postBody)
			if err != nil {
				res.Candidates = append(res.Candidates, XSSCandidate{
					Parameter: p,
					Verdict:   "not tested: " + firstLine(err.Error()),
				})
				continue
			}
			if strings.Contains(baseline, xssCanary) {
				// Without this guard a page that reflects the raw query string
				// would make every parameter look injectable.
				res.Candidates = append(res.Candidates, XSSCandidate{
					Parameter: p,
					Verdict: "not tested: the unmodified response already contains the canary string, " +
						"so a reflection could not be attributed to this parameter",
				})
				continue
			}
			body, err := xssFetch(ctx, d, bin, raw, p, xssCanary, timeout, postBody)
			if err != nil {
				res.Candidates = append(res.Candidates, XSSCandidate{
					Parameter: p,
					Verdict:   "not tested: " + firstLine(err.Error()),
				})
				continue
			}
			idx := strings.Index(body, xssCanary)
			if idx < 0 {
				res.Candidates = append(res.Candidates, XSSCandidate{
					Parameter: p,
					Verdict:   "not reflected in the response body",
				})
				continue
			}
			loc, ctxName := xssLocate(body, idx)
			res.Candidates = append(res.Candidates, XSSCandidate{
				Parameter:    p,
				Location:     loc,
				Context:      ctxName,
				EncodingSeen: false,
				Verdict: "reflected without encoding, which is the precondition for injection and not a " +
					"confirmed vulnerability",
			})
		}
		res.Elapsed = time.Since(began).Seconds()
		res.Count = len(res.Candidates)
		return ok(d, toolName, res.URL, start, nil, res)
	}

	return Tool{Tool: t, Handler: handler,
		Requires: []string{"curl"}}
}

// xssFetch requests the URL with one parameter set to value, and returns the
// response body. An empty value means "leave the parameter as it was".
func xssFetch(ctx context.Context, d Deps, bin, rawURL, param, value string, timeout time.Duration, asPost bool) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := parsed.Query()
	if value == "" {
		q.Del(param)
	} else {
		q.Set(param, value)
	}
	parsed.RawQuery = q.Encode()

	args := []string{
		"--silent", "--show-error",
		"--max-time", fmt.Sprintf("%d", int(timeout.Seconds())),
		"--connect-timeout", "10",
		"--max-redirs", "3",
		"--user-agent", d.Cfg.UserAgent,
		"--proto", "=http,https",
		"--proto-redir", "=http,https",
		"--tlsv1.2",
		// A bounded read: this is a reflection check, not a scraper.
		"--range", "0-65535",
		"-X", "GET",
	}
	if asPost {
		args = append(args, "-X", "POST", "--data-urlencode", param+"="+value)
	}
	// The URL goes last and positionally: --url is refused by the curl
	// argument policy.
	args = append(args, sanitiseURLOf(parsed))

	out, _, runErr := d.Runner.RunCombined(ctx, utils.Spec{
		Binary:  bin,
		Args:    args,
		Timeout: timeout + 5*time.Second,
	})
	if runErr != nil {
		return "", runErr
	}
	return out, nil
}

func sanitiseURLOf(u *url.URL) string {
	c := *u
	c.User = nil
	c.Fragment = ""
	return c.String()
}

// xssLocate reports roughly where in the body the canary landed, which is what
// decides whether a reflection is likely to be exploitable.
//
// Every slice is clamped against the actual window length. A body shorter than
// the window, or a canary at either extreme, must classify rather than panic.
func xssLocate(body string, idx int) (string, string) {
	const lead, trail = 120, 80
	if idx < 0 || idx > len(body) {
		return "in the HTML body", xssContext("body")
	}
	start := idx - lead
	if start < 0 {
		start = 0
	}
	end := idx + len(xssCanary) + trail
	if end > len(body) {
		end = len(body)
	}
	window := body[start:end]

	// The portion of the window up to and including the canary, used to look
	// backwards for an enclosing attribute.
	canaryEnd := idx - start + len(xssCanary)
	if canaryEnd > len(window) {
		canaryEnd = len(window)
	}
	prefix := window[:canaryEnd]

	// Attribute context. The test is whether the value is still open when the
	// canary is reached: a =" that opens before it and has no closing quote,
	// slash or tag terminator before it, means the canary sits inside the
	// attribute value. Checking for a terminator only in what precedes the
	// canary is what distinguishes this from a closed attribute earlier in
	// the same tag.
	if open := strings.LastIndex(prefix, "=\""); open >= 0 {
		if !strings.ContainsAny(prefix[open+2:], "\"'>/") {
			return "inside an HTML attribute value", xssContext("attribute")
		}
	}
	if s := strings.LastIndex(prefix, "<script"); s >= 0 {
		return "inside a script element", xssContext("script")
	}
	// Comment context depends only on what precedes the canary: a <!-- that
	// opened before it and no --> before it means the canary is inside the
	// comment, even though the closing marker comes later.
	if s := strings.LastIndex(prefix, "<!--"); s >= 0 && !strings.Contains(prefix[s:], "-->") {
		return "inside an HTML comment", xssContext("comment")
	}
	if s := strings.LastIndex(prefix, "<style"); s >= 0 {
		return "inside a style element", xssContext("css")
	}
	return "in the HTML body", xssContext("body")
}
