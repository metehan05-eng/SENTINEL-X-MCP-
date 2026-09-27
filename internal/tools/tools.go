package tools

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// Definition returns the MCP schema for a registered tool. main uses it to
// look the schema up by name so registration order and handler wiring stay in
// one place.
// toolSets is the single list of tool groups. All and Definition both read it,
// because they used to carry the same list separately and drifted: a tool added
// to one but not the other was registered but invisible, or visible and broken.
func toolSets(d Deps) [][]Tool {
	return [][]Tool{Recon(d), Scanner(d), Vulnerability(d), SupplyChain(d), Platform(d), Audit(d), Active(d), []Tool{UrlArchive(d), xssProbeTool(d)}}
}

func Definition(name string, d Deps) (mcp.Tool, error) {
	for _, set := range toolSets(d) {
		for _, t := range set {
			if t.Tool.Name == name {
				return t.Tool, nil
			}
		}
	}
	return mcp.Tool{}, fmt.Errorf("unknown tool %q", name)
}

// readOnly marks a tool with the MCP annotation hints that tell a model the
// call cannot change the state of anything. Every SENTINEL-X tool carries it:
// the server has no mutating capability at all.
var readOnly = mcp.WithToolAnnotation(mcp.ToolAnnotation{
	Title:           "read-only",
	ReadOnlyHint:    mcp.ToBoolPtr(true),
	DestructiveHint: mcp.ToBoolPtr(false),
	IdempotentHint:  mcp.ToBoolPtr(true),
	// These tools do reach third-party services (DNS, NVD, the target host),
	// so the open-world hint is honest rather than merely tidy.
	OpenWorldHint: mcp.ToBoolPtr(true),
})

// Scrub applies the shared redaction policy to arbitrary text.
func (d Deps) Scrub(s string) string {
	if d.Runner == nil {
		return s
	}
	return d.Runner.Redactor().Scrub(s)
}

// safeURL wraps a parsed URL so a redacted string can never be accidentally
// used as a live one.
type safeURL struct {
	u *url.URL
}

func parseURL(raw string) (safeURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return safeURL{}, err
	}
	if u.Host == "" {
		return safeURL{}, fmt.Errorf("no host in %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return safeURL{}, fmt.Errorf("scheme %q is not permitted; use http or https", u.Scheme)
	}
	if u.Port() != "" && !validPort(u.Port()) {
		return safeURL{}, fmt.Errorf("invalid port %q", u.Port())
	}
	return safeURL{u: u}, nil
}

func validPort(p string) bool {
	if p == "" {
		return false
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return false
		}
	}
	return n > 0
}

func (s safeURL) String() string {
	if s.u == nil {
		return ""
	}
	// Credentials in the URL are never echoed back to the caller.
	c := *s.u
	if c.User != nil {
		c.User = url.UserPassword("redacted", "redacted")
	}
	return c.String()
}

func (s safeURL) host() string {
	if s.u == nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(s.u.Host); err == nil {
		return h
	}
	return s.u.Host
}

// scheme reports the URL's scheme, defaulting to https for a bare host.
func (s safeURL) scheme() string {
	if s.u == nil || s.u.Scheme == "" {
		return "https"
	}
	return strings.ToLower(s.u.Scheme)
}

// resolve follows a Location header value, which may be absolute or relative.
// A malformed header is returned as an error rather than guessed at.
func (s safeURL) resolve(location string) (string, error) {
	if s.u == nil {
		return "", fmt.Errorf("no base URL")
	}
	ref, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", err
	}
	resolved := s.u.ResolveReference(ref)
	resolved.User = nil
	resolved.Fragment = ""
	return resolved.String(), nil
}

// sanitiseURL removes any embedded credentials before the URL reaches argv, so
// they are not exposed in the process table.
func sanitiseURL(s safeURL) string {
	if s.u == nil {
		return ""
	}
	c := *s.u
	c.User = nil
	c.Fragment = ""
	return c.String()
}

// rePortTopPreset matches nmap's named top-N shorthand, which is a port list
// rather than a numeric range and must be exempt from range validation.
var rePortTopPreset = regexp.MustCompile(`(?i)^top-\d{1,5}$`)

// rePortToken matches one element of a port list: a number, an inclusive
// range, or nmap's T/U protocol-prefixed forms. Nothing else is tolerated, so
// a caller cannot smuggle an nmap option through the port field.
var rePortToken = regexp.MustCompile(`^(?i)(?:([TU]?)(\d{1,5})(?:-([TU]?)(\d{1,5}))?)?$`)

// validPortSpec reports whether s is a well-formed nmap port specification.
func validPortSpec(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	if rePortTopPreset.MatchString(s) {
		return true
	}
	for _, tok := range strings.Split(s, ",") {
		if tok == "" {
			return false
		}
		m := rePortToken.FindStringSubmatch(tok)
		if m == nil {
			return false
		}
		// m = [full, loPrefix, lo, hiPrefix, hi]; hi is empty for a single port.
		lo, err := strconv.Atoi(m[2])
		if err != nil || lo < 1 || lo > 65535 {
			return false
		}
		if m[4] == "" {
			continue
		}
		hi, err := strconv.Atoi(m[4])
		if err != nil || hi < 1 || hi > 65535 || lo > hi {
			return false
		}
		// A T-prefixed range must not straddle the TCP/UDP boundary: nmap
		// treats "T1-U1024" as malformed.
		if m[1] != "" && m[3] != "" && m[1] != m[3] {
			return false
		}
	}
	return true
}

// parseHTTPHeaders splits curl's --dump-header output into a header map and a
// body excerpt. With multiple redirects curl emits several header blocks; the
// last one is the final response, which is what matters here.
func parseHTTPHeaders(out string) HTTPResult {
	r := HTTPResult{Headers: map[string]string{}}
	blocks := strings.Split(out, "\r\n\r\n")
	if len(blocks) == 0 {
		blocks = strings.Split(out, "\n\n")
	}

	// Find the last block that actually contains a status line.
	var headerPart string
	var bodyParts []string
	for _, b := range blocks {
		if strings.HasPrefix(strings.TrimSpace(b), "HTTP/") {
			headerPart = b
			bodyParts = bodyParts[:0]
			continue
		}
		if headerPart != "" {
			bodyParts = append(bodyParts, b)
		}
	}
	if headerPart == "" && len(blocks) > 0 {
		headerPart = blocks[0]
		bodyParts = blocks[1:]
	}

	lines := strings.Split(headerPart, "\n")
	for i, l := range lines {
		l = strings.TrimRight(l, "\r")
		if i == 0 {
			r.Status = strings.TrimSpace(l)
			continue
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		idx := strings.Index(l, ":")
		if idx < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(l[:idx]))
		v := strings.TrimSpace(l[idx+1:])
		if k == "" {
			continue
		}
		if _, exists := r.Headers[k]; !exists {
			r.Headers[k] = v
		}
		switch k {
		case "server":
			r.Server = v
		case "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version":
			r.Server = strings.TrimSpace(r.Server + " " + v)
		case "set-cookie":
			lower := strings.ToLower(v)
			switch {
			case !strings.Contains(lower, "secure"):
				r.Missing = append(r.Missing, "Set-Cookie: Secure")
			case !strings.Contains(lower, "httponly"):
				r.Missing = append(r.Missing, "Set-Cookie: HttpOnly")
			case !strings.Contains(lower, "samesite"):
				r.Missing = append(r.Missing, "Set-Cookie: SameSite")
			}
		}
	}
	r.BodyExcerpt = strings.TrimSpace(strings.Join(bodyParts, "\n"))
	return r
}
