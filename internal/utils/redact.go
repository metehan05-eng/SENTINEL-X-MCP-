package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// RedactorMask is what a detected secret is replaced with.
const RedactorMask = "[REDACTED]"

// Redactor scrubs credentials out of any text bound for the model. Scan output
// routinely contains banners, config dumps and environment fragments, and none
// of that should be echoed into an LLM conversation window verbatim.
type Redactor struct {
	patterns []*regexp.Regexp
	enabled  bool
}

// NewRedactor compiles the configured patterns. Invalid patterns are skipped
// rather than aborting start-up: redaction is a defence-in-depth layer, and a
// bad regex must not take the scanner offline.
func NewRedactor(patterns []string) *Redactor {
	r := &Redactor{enabled: len(patterns) > 0}
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			r.patterns = append(r.patterns, re)
		}
	}
	r.enabled = len(r.patterns) > 0
	return r
}

// Scrub replaces every configured match with RedactorMask.
func (r *Redactor) Scrub(s string) string {
	if r == nil || !r.enabled || s == "" {
		return s
	}
	for _, re := range r.patterns {
		s = re.ReplaceAllString(s, RedactorMask)
	}
	return s
}

// Found reports which patterns matched, without exposing the matched text.
// Useful for flagging that a result contained sensitive material.
func (r *Redactor) Found(s string) []string {
	if r == nil || !r.enabled || s == "" {
		return nil
	}
	var hits []string
	for i, re := range r.patterns {
		if re.MatchString(s) {
			hits = append(hits, re.String())
			_ = i
		}
	}
	return hits
}

// Truncate shortens s to at most n runes, appending an explicit marker so the
// model can tell that it is looking at a clipped view.
func Truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n...[truncated, %d bytes total]", len(s))
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
