package tools

import (
	"strings"
	"testing"

	"github.com/sentinel-x/sentinel-x/internal/config"
	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// Unknown tags must be treated as active. A denylist of dangerous tags would
// quietly start permitting everything nuclei adds in a later release, so an
// upgrade could turn a passive scan into an exploit scan with no config change.
func TestNucleiTagClassificationFailsClosed(t *testing.T) {
	cases := []struct {
		tags        []string
		wantPassive bool
	}{
		{[]string{"exposure", "misconfiguration", "technologies", "ssl", "dns"}, true},
		{[]string{"exposure", "cve"}, false},
		{[]string{"rce"}, false},
		{[]string{"fuzzing"}, false},
		{[]string{"dos"}, false},
		{[]string{"intrusive"}, false},
		{[]string{"headless"}, false},
		{[]string{"default"}, false},
		// A tag that does not exist today must be assumed active.
		{[]string{"something-new-in-v4"}, false},
		{[]string{}, true},
	}
	for _, c := range cases {
		passive, active := nucleiTagIsPassive(c.tags)
		if passive != c.wantPassive {
			t.Errorf("nucleiTagIsPassive(%v) = %v, want %v", c.tags, passive, c.wantPassive)
		}
		if !passive && len(active) == 0 {
			t.Errorf("nucleiTagIsPassive(%v) reported active with an empty active list", c.tags)
		}
	}
}

func TestNucleiPassiveTagsAreReal(t *testing.T) {
	// Guards against inventing a tag that matches nothing, which would make a
	// scan silently cover less ground than the caller asked for.
	known := map[string]bool{
		"exposure": true, "misconfiguration": true, "technologies": true,
		"ssl": true, "dns": true, "cve": true, "rce": true, "fuzzing": true,
		"dos": true, "intrusive": true, "headless": true, "default": true,
		"file": true, "network": true, "code": true, "bruteforce": true,
	}
	for _, tag := range nucleiPassiveTags {
		if !known[tag] {
			t.Errorf("passive tag %q is not a known nuclei tag", tag)
		}
	}
}

func TestNucleiTagClassificationIsCaseInsensitive(t *testing.T) {
	if passive, _ := nucleiTagIsPassive([]string{"EXPOSURE", "Dns"}); !passive {
		t.Error("tag matching must be case-insensitive")
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank("critical") <= severityRank("high") {
		t.Error("critical must outrank high")
	}
	if severityRank("high") <= severityRank("low") {
		t.Error("high must outrank low")
	}
	if severityRank("unknown-value") != 0 {
		t.Error("an unrecognised severity must sort last, not first")
	}
	if severityRank("INFO") != severityRank("informative") {
		t.Error("info and informative should be the same rank")
	}
}

func TestNucleiArgumentPolicy(t *testing.T) {
	// These are refused by policy, independent of what the tool passes in.
	refused := []string{
		"-o", "-output", "-output-file",
		"-update", "-update-templates", "-ut",
		"-interactsh-url", "-i-u",
		"-fuzz", "-payloads", "-p",
		"-proxy", "-proxy-url",
		"-headless", "-code", "-dast",
		"-l", "-list",
	}
	runner, err := utils.NewRunner(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range refused {
		if err := runner.CheckArgs("nuclei", []string{"-silent", arg, "x"}); err == nil {
			t.Errorf("policy accepted %q, which should be refused", arg)
		}
	}
	// The flags the tool actually relies on must still get through.
	for _, arg := range []string{"-silent", "-jsonl", "-duc", "-tags", "-severity", "-rate-limit", "-timeout", "-target"} {
		if err := runner.CheckArgs("nuclei", []string{arg, "x"}); err != nil {
			t.Errorf("policy refused %q, which the tool needs: %v", arg, err)
		}
	}
}

func TestNucleiIsRefusedByDefault(t *testing.T) {
	// Unlike searchsploit, nuclei must not be enabled for everyone: being
	// installed is not consent to send exploit traffic to a target.
	c := config.Default()
	refused := false
	for _, b := range c.Policy.DeniedBinaries {
		if strings.EqualFold(b, "nuclei") {
			refused = true
		}
	}
	if !refused {
		t.Error("nuclei must be in the default deny list")
	}
	allowed := false
	for _, b := range c.Policy.AllowedBinaries {
		if strings.EqualFold(b, "nuclei") {
			allowed = true
		}
	}
	if allowed {
		t.Error("nuclei must not be in the default allow list")
	}
}
