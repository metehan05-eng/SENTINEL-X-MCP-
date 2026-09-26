package tools

import (
	"strings"
	"testing"
)

// The archives return whatever they were handed, including names from domains
// that merely share a suffix. A check that forgets the dot accepts
// "notexample.com" as a child of "example.com", which puts a third party's host
// into a scope-limited report.
func TestInScopeName(t *testing.T) {
	cases := []struct {
		domain, raw string
		want        string
	}{
		{"example.com", "www.example.com", "www.example.com"},
		{"example.com", "WWW.Example.COM", "www.example.com"},
		{"example.com", "*.dev.example.com", "dev.example.com"},
		{"example.com", "a.b.c.example.com.", "a.b.c.example.com"},

		// The suffix trap.
		{"example.com", "notexample.com", ""},
		{"example.com", "evilexample.com", ""},
		{"example.com", "example.com.evil.net", ""},
		{"example.com", "xexample.com", ""},

		// The apex is not a subdomain of itself.
		{"example.com", "example.com", ""},

		// Not host names at all.
		{"example.com", "", ""},
		{"example.com", "   ", ""},
		{"example.com", "under_score.example.com", ""},
		{"example.com", "-lead.example.com", ""},
		{"example.com", "trail-.example.com", ""},
		{"example.com", "a..example.com", ""},
		{"example.com", "has space.example.com", ""},
		{"example.com", "http://www.example.com", ""},
		{"example.com", strings.Repeat("a", 64) + ".example.com", ""},
		{"example.com", strings.Repeat("a.", 200) + "example.com", ""},
	}
	for _, c := range cases {
		if got := inScopeName(c.domain, c.raw); got != c.want {
			t.Errorf("inScopeName(%q, %q) = %q, want %q", c.domain, c.raw, got, c.want)
		}
	}
}

// A subdomain of a subdomain is still in scope, and depth is not capped.
func TestInScopeNameAllowsDepth(t *testing.T) {
	got := inScopeName("example.com", "a.b.c.d.e.f.g.example.com")
	if got != "a.b.c.d.e.f.g.example.com" {
		t.Errorf("deep subdomain rejected: %q", got)
	}
}

// Typing a source name that does not exist must fail loudly. Silently dropping
// it would narrow coverage while the result still looked complete.
func TestResolveSourcesRejectsUnknown(t *testing.T) {
	if _, err := resolveSources([]string{"crtsh", "nope"}, passiveSourceNames(), defaultPassiveSources); err == nil {
		t.Error("an unknown source name was accepted")
	} else if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error does not name the offending source: %v", err)
	}
}

func TestResolveSourcesDefaultsAndDedupes(t *testing.T) {
	got, err := resolveSources(nil, passiveSourceNames(), defaultPassiveSources)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("default should query all three sources, got %v", got)
	}
	got, err = resolveSources([]string{"otx", "OTX", " otx "}, passiveSourceNames(), defaultPassiveSources)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "otx" {
		t.Errorf("expected one deduplicated entry, got %v", got)
	}
}

func TestResolveSourcesRejectsEmpty(t *testing.T) {
	if _, err := resolveSources([]string{"", "  "}, passiveSourceNames(), defaultPassiveSources); err == nil {
		t.Error("a request for no sources was accepted")
	}
}

// Archive results are full of cross-domain references. Only URLs on the target
// domain or beneath it belong in the report.
func TestInScopeURL(t *testing.T) {
	cases := []struct {
		domain, raw string
		want        string
	}{
		{"example.com", "https://www.example.com/a", "https://www.example.com/a"},
		{"example.com", "http://example.com/a", "https://example.com/a"},
		{"example.com", "https://example.com/a?b=1", "https://example.com/a?b=1"},
		{"example.com", "https://EXAMPLE.com/a", "https://example.com/a"},
		{"example.com", "https://a.b.example.com/x", "https://a.b.example.com/x"},

		// Cross-domain noise the archives return constantly.
		{"example.com", "https://notexample.com/a", ""},
		{"example.com", "https://example.com.evil.net/a", ""},
		{"example.com", "https://cdn.other.org/x", ""},
		{"example.com", "not a url", ""},
		{"example.com", "", ""},
	}
	for _, c := range cases {
		got, _, _ := inScopeURL(c.domain, c.raw)
		if got != c.want {
			t.Errorf("inScopeURL(%q, %q) = %q, want %q", c.domain, c.raw, got, c.want)
		}
	}
}

// A port in the archive URL is not part of the identity of a path, and leaving
// it in would make the same endpoint look like two.
func TestInScopeURLNormalisesPort(t *testing.T) {
	got, _, _ := inScopeURL("example.com", "https://www.example.com:8443/a")
	if got != "https://www.example.com/a" {
		t.Errorf("port was not normalised: %q", got)
	}
}

func TestSortedKeysIsDeterministicAndCapped(t *testing.T) {
	m := map[string]bool{"c": true, "a": true, "b": true, "d": true, "e": true}
	got := sortedKeys(m, 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 keys, got %v", got)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("keys not sorted: %v", got)
	}
}

func TestCountHelpers(t *testing.T) {
	statuses := []sourceStatus{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "failed"},
		{Name: "c", Status: "failed"},
		{Name: "d", Status: "ok"},
	}
	if got := countFailed(statuses); got != 2 {
		t.Errorf("countFailed = %d, want 2", got)
	}
	entries := []SubdomainEntry{
		{Name: "x", Confirmed: true},
		{Name: "y", Confirmed: false},
		{Name: "z", Confirmed: true},
	}
	if got := countConfirmed(entries); got != 2 {
		t.Errorf("countConfirmed = %d, want 2", got)
	}
	lines := warnLines(statuses)
	if len(lines) != 2 {
		t.Errorf("warnLines = %v, want two entries", lines)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "b: ") && !strings.HasPrefix(l, "c: ") {
			t.Errorf("unexpected warning line %q", l)
		}
	}
}
