package tools

import (
	"strings"
	"testing"
)

func TestSplitTargetList(t *testing.T) {
	got := splitTargetList("example.com, a.example.com\nb.example.com , example.com,  ")
	want := []string{"example.com", "a.example.com", "b.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %d targets %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitTargetListDeduplicatesCaseInsensitively(t *testing.T) {
	got := splitTargetList("Example.com,EXAMPLE.COM,example.com")
	if len(got) != 1 {
		t.Fatalf("got %v, want a single de-duplicated target", got)
	}
}

func TestSplitTargetListEmpty(t *testing.T) {
	if got := splitTargetList("   ,,\n\t "); len(got) != 0 {
		t.Fatalf("got %v, want no targets", got)
	}
}

// Order must survive, because the caller reads results as a list and a
// completion-ordered list makes two runs incomparable.
func TestSplitTargetListPreservesOrder(t *testing.T) {
	got := splitTargetList("z.example.com, a.example.com, m.example.com")
	if got[0] != "z.example.com" || got[2] != "m.example.com" {
		t.Fatalf("order not preserved: %v", got)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"simple", "<html><head><title>Merhaba</title></head>", "Merhaba"},
		{"multiline", "<title>\n  Dashboard\n  Admin\n</title>", "Dashboard Admin"},
		{"absent", "<html><body>no title</body></html>", ""},
		{"empty", "<title></title>", ""},
		{"attributes", `<title data-x="1">Sayfa</title>`, "Sayfa"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractTitle(c.body); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractTitleTruncates(t *testing.T) {
	long := strings.Repeat("a", 400)
	got := extractTitle("<title>" + long + "</title>")
	if len([]rune(got)) > 160 {
		t.Errorf("title was not truncated: %d runes", len([]rune(got)))
	}
}

// A refused connection, a timeout and a DNS failure lead to different operator
// actions, so they must not share a label.
func TestClassifyProbeFailure(t *testing.T) {
	cases := []struct{ detail, want string }{
		{"curl: (28) Operation timed out after 10001 milliseconds", "timeout"},
		{"curl: (6) Could not resolve host: nope.example.com", "dns_failure"},
		{"curl: (7) Failed to connect to 127.0.0.1 port 443: Connection refused", "connection_refused"},
		{"curl: (56) Recv failure: Connection reset by peer", "connection_reset"},
		{"curl: (7) Failed to connect: No route to host", "unreachable"},
		{"curl: (60) SSL certificate problem: unable to get local issuer certificate", "tls_failure"},
		{"something unrecognised", "no_response"},
	}
	for _, c := range cases {
		if got := classifyProbeFailure(c.detail); got != c.want {
			t.Errorf("classifyProbeFailure(%q) = %q, want %q", c.detail, got, c.want)
		}
	}
}

func TestParseProbeChainSingleResponse(t *testing.T) {
	h, chain := parseProbeChain("HTTP/2 200\r\ncontent-type: text/html\r\nserver: nginx\r\n\r\n<h1>hi</h1>")
	if len(chain) != 1 {
		t.Fatalf("got %d hops, want 1", len(chain))
	}
	if h.Headers["content-type"] != "text/html" {
		t.Errorf("content-type = %q", h.Headers["content-type"])
	}
	if !strings.Contains(h.BodyExcerpt, "hi") {
		t.Errorf("body excerpt = %q, want it to carry the body", h.BodyExcerpt)
	}
}

// The first block of a redirect chain is the 301. Reporting that as the
// outcome would call every redirecting site broken.
func TestParseProbeChainReportsFinalResponse(t *testing.T) {
	out := "HTTP/2 301\r\nlocation: https://example.com/new\r\n\r\n" +
		"HTTP/2 200\r\ncontent-type: text/html\r\n\r\n<h1>final</h1>"
	h, chain := parseProbeChain(out)
	if len(chain) != 2 {
		t.Fatalf("got %d hops, want 2", len(chain))
	}
	if got := statusCodeFromStatusLine(h.Status); got != 200 {
		t.Errorf("final status = %d, want 200", got)
	}
	if chain[0].Location != "https://example.com/new" {
		t.Errorf("first hop location = %q", chain[0].Location)
	}
}

func TestFinalURLFromChainFollowsRelativeAndAbsolute(t *testing.T) {
	chain := []ProbeHop{
		{Status: "HTTP/2 301", Location: "/a"},
		{Status: "HTTP/2 301", Location: "https://other.example.net/b"},
	}
	got := finalURLFromChain("https://example.com/start", chain)
	if got != "https://other.example.net/b" {
		t.Errorf("got %q, want the last Location resolved", got)
	}
}

func TestFinalURLFromChainNoLocationKeepsRequest(t *testing.T) {
	got := finalURLFromChain("https://example.com/", []ProbeHop{{Status: "HTTP/2 200"}})
	if got != "https://example.com/" {
		t.Errorf("got %q, want the requested URL", got)
	}
}

func TestStatusCodeFromStatusLine(t *testing.T) {
	cases := map[string]int{
		"HTTP/2 200":                     200,
		"HTTP/1.1 301 Moved Permanently": 301,
		"HTTP/1.1 404 Not Found":         404,
		"garbage":                        0,
		"":                               0,
	}
	for in, want := range cases {
		if got := statusCodeFromStatusLine(in); got != want {
			t.Errorf("statusCodeFromStatusLine(%q) = %d, want %d", in, got, want)
		}
	}
}

// curl can emit headers and then fail; a missing status line must yield no
// hops rather than a fabricated result.
func TestParseProbeChainNoStatusLine(t *testing.T) {
	_, chain := parseProbeChain("curl: (7) Failed to connect")
	if len(chain) != 0 {
		t.Errorf("got %d hops, want none", len(chain))
	}
}

func TestNormaliseTarget(t *testing.T) {
	if got := normaliseTarget("example.com"); got != "https://example.com" {
		t.Errorf("got %q", got)
	}
	if got := normaliseTarget("http://example.com"); got != "http://example.com" {
		t.Errorf("a URL with an explicit scheme must not be rewritten, got %q", got)
	}
}

func TestClampInt(t *testing.T) {
	cases := []struct{ in, lo, hi, def, want int }{
		{0, 1, 16, 6, 6},   // unset falls back to the default
		{4, 1, 16, 6, 4},   // in range
		{99, 1, 16, 6, 16}, // clamped high
		{-3, 1, 16, 6, 1},  // clamped low
	}
	for _, c := range cases {
		if got := clampInt(c.in, c.lo, c.hi, c.def); got != c.want {
			t.Errorf("clampInt(%d,%d,%d,%d) = %d, want %d", c.in, c.lo, c.hi, c.def, got, c.want)
		}
	}
}

// Body-marker evidence must be labelled as inference. Reporting it as a
// detection is the overclaim this project keeps correcting.
func TestWebIndicatorsLabelsBodyEvidence(t *testing.T) {
	h := HTTPResult{Headers: map[string]string{"x-powered-by": "Express"}}
	got := webIndicators(h, "<div>Powered by Tornado</div>")
	if !strings.Contains(got, "x-powered-by: Express") {
		t.Errorf("header evidence missing: %q", got)
	}
	if !strings.Contains(got, "tornado (inferred from body)") {
		t.Errorf("body evidence should be marked inferred: %q", got)
	}
}

func TestWebIndicatorsEmptyBodyIsNotAClaim(t *testing.T) {
	h := HTTPResult{Headers: map[string]string{}}
	if got := webIndicators(h, ""); got != "" {
		t.Errorf("got %q, want empty rather than an unfounded guess", got)
	}
}

func TestSafeURLSchemeAndResolve(t *testing.T) {
	u, err := parseURL("https://example.com/a/b")
	if err != nil {
		t.Fatal(err)
	}
	if got := u.scheme(); got != "https" {
		t.Errorf("scheme = %q", got)
	}
	got, err := u.resolve("../c")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/c" {
		t.Errorf("resolve = %q, want https://example.com/c", got)
	}
}
