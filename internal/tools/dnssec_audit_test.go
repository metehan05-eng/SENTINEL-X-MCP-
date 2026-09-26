package tools

import (
	"strings"
	"testing"
)

func TestAnalyseSPF(t *testing.T) {
	cases := []struct {
		name       string
		record     string
		wantStatus string
		contains   string
	}{
		{"hard fail", "v=spf1 include:_spf.google.com -all", "pass", "-all"},
		{"soft fail is weak", "v=spf1 -all ~all", "warn", "~all"},
		{"neutral is no protection", "v=spf1 ?all", "fail", "?all"},
		{"missing all is no protection", "v=spf1 include:a.example.com", "fail", "no terminating mechanism"},
	}
	for _, c := range cases {
		got := analyseSPF(c.record)
		if got.Status != c.wantStatus {
			t.Errorf("%s: status = %q, want %q (summary: %s)", c.name, got.Status, c.wantStatus, got.Summary)
		}
		if c.contains != "" && !strings.Contains(got.Summary, c.contains) {
			t.Errorf("%s: summary %q does not mention %q", c.name, got.Summary, c.contains)
		}
	}
}

func TestAnalyseSPFCountsLookups(t *testing.T) {
	// RFC 7208 section 4.6.4 caps DNS-querying mechanisms at 10. Exceeding it
	// makes the record a permerror, meaning SPF silently stops protecting the
	// domain. That failure mode is easy to miss, so it is escalated to "fail".
	rec := "v=spf1"
	for i := 0; i < 11; i++ {
		rec += " include:mx" + string(rune('a'+i)) + ".example.com"
	}
	rec += " -all"
	got := analyseSPF(rec)
	if got.Lookups != 11 {
		t.Fatalf("lookup count = %d, want 11", got.Lookups)
	}
	if got.Status != "fail" {
		t.Errorf("exceeding the RFC 7208 lookup limit must fail, got %q", got.Status)
	}
	if !strings.Contains(got.Summary, "RFC 7208") {
		t.Errorf("summary should cite the RFC limit: %q", got.Summary)
	}
}

func TestAnalyseDMARC(t *testing.T) {
	cases := []struct {
		name       string
		record     string
		wantStatus string
	}{
		{"reject is strongest", "v=DMARC1; p=reject; rua=mailto:a@b.com", "pass"},
		{"quarantine is partial", "v=DMARC1; p=quarantine; rua=mailto:a@b.com", "warn"},
		{"none is monitoring only", "v=DMARC1; p=none; rua=mailto:a@b.com", "warn"},
		{"missing p is invalid", "v=DMARC1; rua=mailto:a@b.com", "fail"},
		{"pct below 100 is partial", "v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com", "warn"},
		{"relaxed alignment is partial", "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:a@b.com", "warn"},
		{"sp=none weakens subdomains", "v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com", "warn"},
	}
	for _, c := range cases {
		got := analyseDMARC(c.record)
		if got.Status != c.wantStatus {
			t.Errorf("%s: status = %q, want %q (summary: %s)", c.name, got.Status, c.wantStatus, got.Summary)
		}
	}
}

func TestDNSGradeScale(t *testing.T) {
	// A zone failing everything must not grade well.
	bad := DNSSecurityResult{Checks: []DNSCheck{
		{Control: "spf", Status: "fail"},
		{Control: "dmarc", Status: "fail"},
		{Control: "dnssec", Status: "fail"},
		{Control: "zone_transfer", Status: "fail"},
	}}
	if g := gradeDNS(bad); g != "F" {
		t.Errorf("all-failing zone graded %q, want F", g)
	}
	good := DNSSecurityResult{Checks: []DNSCheck{
		{Control: "spf", Status: "pass"},
		{Control: "dmarc", Status: "pass"},
		{Control: "dnssec", Status: "signed"},
		{Control: "zone_transfer", Status: "pass"},
	}}
	if g := gradeDNS(good); g != "A" {
		t.Errorf("all-passing zone graded %q, want A", g)
	}
	if g := gradeDNS(DNSSecurityResult{}); g != "unknown" {
		t.Errorf("empty result graded %q, want unknown", g)
	}
}

// A TXT record long enough to wrap across lines is the case a naive
// line-splitting parser gets wrong, and getting it wrong can silently
// downgrade an SPF verdict.
func TestDNSStringsJoinsWrappedTXT(t *testing.T) {
	// dig splits a >255-byte TXT record: the first chunk carries the record
	// header and the rest are indented continuation lines.
	out := "ANSWER SECTION\n"
	out += "example.com.\t300\tIN\tTXT\t\"v=spf1 include:_spf.google.com include:spf.protection.\"\n"
	out += "\t\t\t\t\t\"outlook.com -all\""
	got := dnsStrings(out)
	if len(got) != 1 {
		t.Fatalf("want 1 joined record, got %d: %q", len(got), got)
	}
	if !strings.HasSuffix(got[0], "-all") {
		t.Errorf("joined record lost its tail: %q", got[0])
	}
	if !strings.Contains(got[0], "spf.protection.outlook.com") {
		t.Errorf("joined record lost its middle: %q", got[0])
	}
}

func TestDNSStringsSeparatesRecords(t *testing.T) {
	out := "ANSWER SECTION\n"
	out += "example.com.\t300\tIN\tTXT\t\"v=spf1 -all\"\n"
	out += "example.com.\t300\tIN\tTXT\t\"v=DKIM1; k=rsa; p=AAA\"\n"
	out += "example.com.\t300\tIN\tA\t192.0.2.1"
	got := dnsStrings(out)
	if len(got) != 3 {
		t.Fatalf("want 3 records, got %d: %q", len(got), got)
	}
	if got[0] != "v=spf1 -all" {
		t.Errorf("record 0 = %q", got[0])
	}
	// An unquoted A record keeps its value.
	if got[2] != "192.0.2.1" {
		t.Errorf("record 2 = %q", got[2])
	}
}

func TestDNSStringsStripsTrailingDot(t *testing.T) {
	got := dnsStrings("ANSWER SECTION\nns1.example.com.\t300\tIN\tNS\ta.example.com.\nns2.example.com.\t300\tIN\tNS\tb.example.com.")
	if len(got) != 2 {
		t.Fatalf("want 2, got %q", got)
	}
	// The trailing dot is preserved: dnsStrings must not alter record content,
	// and callers that need a bare hostname trim it themselves.
	if got[0] != "a.example.com." {
		t.Errorf("record value was altered: %q", got[0])
	}
	if len(got) != 2 {
		t.Errorf("want 2 NS records, got %q", got)
	}
}

func TestIsSPFLookup(t *testing.T) {
	for _, m := range []string{"include", "mx", "a", "ptr", "exists"} {
		if !isSPFLookupMechanism(m, false) {
			t.Errorf("%q should count as a DNS lookup", m)
		}
	}
	for _, m := range []string{"ip4:10.0.0.1", "ip6:::1", "-all", "all", "v=spf1"} {
		if isSPFLookupMechanism(strings.SplitN(m, ":", 2)[0], strings.Contains(m, ":")) {
			t.Errorf("%q should not count as a DNS lookup", m)
		}
	}
	// A CIDR-qualified mx still performs an MX query, so it does cost a lookup.
	if !isSPFLookupMechanism("mx/24", true) && !isSPFLookupMechanism("mx", true) {
		t.Error("mx must count as a DNS lookup")
	}
}
