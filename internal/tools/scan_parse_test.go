package tools

import "testing"

// reviewHTTP used to take HTTPResult by value, so the Missing and Present
// slices it appended to were discarded. The findings still came back correct,
// which is why this went unnoticed: only the two summary fields were always
// null, and a null "missing" reads as "nothing is missing".
func TestReviewHTTPReportsMissingAndPresentOnTheCaller(t *testing.T) {
	r := HTTPResult{Headers: map[string]string{
		"strict-transport-security": "max-age=63072000",
		"content-type":              "text/html",
	}}
	findings := reviewHTTP(&r)

	if len(r.Missing) == 0 {
		t.Fatal("missing_security_headers stayed empty; a bare response is missing five of them")
	}
	for _, want := range []string{"content-security-policy", "x-frame-options", "referrer-policy"} {
		found := false
		for _, got := range r.Missing {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing list %v does not contain %q", r.Missing, want)
		}
	}
	var hasHSTS bool
	for _, got := range r.Present {
		if got == "strict-transport-security" {
			hasHSTS = true
		}
	}
	if !hasHSTS {
		t.Errorf("present list %v does not record the HSTS header that was supplied", r.Present)
	}
	if len(findings) == 0 {
		t.Error("expected findings for the missing headers")
	}
}
