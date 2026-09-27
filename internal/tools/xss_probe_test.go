package tools

import (
	"strings"
	"testing"
)

func TestXSSLocateContexts(t *testing.T) {
	cases := []struct {
		name, body, wantLoc string
	}{
		{"body", "<p>hello " + xssCanary + " world</p>", "in the HTML body"},
		{"attribute", `<div title="` + xssCanary + `">x</div>`, "inside an HTML attribute value"},
		{"script", "<script>var a='" + xssCanary + "';</script>", "inside a script element"},
		{"comment", "<!-- " + xssCanary + " -->", "inside an HTML comment"},
		{"style", "<style>a{" + xssCanary + "}</style>", "inside a style element"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := strings.Index(c.body, xssCanary)
			if idx < 0 {
				t.Fatalf("fixture does not contain the canary")
			}
			loc, ctx := xssLocate(c.body, idx)
			if loc != c.wantLoc {
				t.Errorf("location = %q, want %q (context %q)", loc, c.wantLoc, ctx)
			}
			if ctx == "" {
				t.Error("context must never be empty; an unclassified context reads as no context")
			}
		})
	}
}

func TestXSSLocateNearEndOfBody(t *testing.T) {
	// The window clamps at both ends, and a canary at offset 0 or at the very
	// end must not panic or misclassify.
	for _, body := range []string{
		xssCanary,
		"x" + xssCanary,
		xssCanary + "x",
		strings.Repeat("a", 500) + xssCanary,
	} {
		idx := strings.Index(body, xssCanary)
		loc, ctx := xssLocate(body, idx)
		if loc == "" || ctx == "" {
			t.Errorf("xssLocate(%q) returned empty location or context", body)
		}
	}
}

func TestXSSContextNeverEmpty(t *testing.T) {
	for _, in := range []string{"", "body", "attribute", "javascript:", "style", "comment", "url"} {
		if got := xssContext(in); got == "" {
			t.Errorf("xssContext(%q) returned empty", in)
		}
	}
}

// The canary must be inert: no angle brackets, no quotes, nothing a browser
// could parse. It only has to be unique and survive a round trip.
func TestXSSCanaryIsInert(t *testing.T) {
	for _, bad := range []string{"<", ">", "\"", "'", "`", "/", "=", "&", " ", "\\", ";"} {
		if strings.Contains(xssCanary, bad) {
			t.Errorf("canary contains %q, which is not inert", bad)
		}
	}
	if len(xssCanary) < 6 {
		t.Errorf("canary %q is too short to be distinctive", xssCanary)
	}
}
