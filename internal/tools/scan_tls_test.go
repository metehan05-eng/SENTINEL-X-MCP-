package tools

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseTLSReadsRealNmapScriptOutput(t *testing.T) {
	r := parseTLS(nmapTLSOutput, "443")

	// The previous parser matched "ciphers:" and read the value from that same
	// line, which is always empty, so Protocols/Ciphers stayed nil. Assert the
	// populated shape against verbatim nmap output.
	for _, want := range []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"} {
		if !containsFold(r.Protocols, want) {
			t.Errorf("Protocols = %v, missing %s", r.Protocols, want)
		}
	}
	if len(r.CipherSuites) == 0 {
		t.Fatal("CipherSuites is empty; the nmap script block was not parsed")
	}
	if got := r.Meta["least_strength"]; got != "C" {
		t.Errorf("least_strength = %q, want C", got)
	}

	// A suite must be attributed to the protocol whose block it appeared
	// under. 3DES is offered on both TLSv1.0 and TLSv1.1 in the captured
	// output, so both have to be attributed correctly.
	protos := map[string]bool{}
	for _, c := range r.CipherSuites {
		if strings.Contains(c.Name, "3DES") {
			protos[c.Protocol] = true
		}
	}
	if !protos["TLSv1.0"] || !protos["TLSv1.1"] {
		t.Errorf("3DES suites attributed to %v, want both TLSv1.0 and TLSv1.1", protos)
	}
	var grade string
	for _, c := range r.CipherSuites {
		if strings.Contains(c.Name, "3DES") {
			grade = c.Grade
		}
	}
	if grade != "C" {
		t.Errorf("3DES grade = %q, want C", grade)
	}
	var kex string
	for _, c := range r.CipherSuites {
		if strings.Contains(c.Name, "3DES") {
			kex = c.KeyExchange
		}
	}
	if kex != "rsa" {
		t.Errorf("3DES key exchange = %q, want rsa", kex)
	}
}

func TestParseTLSCertificateFieldsSurviveScriptPrefixes(t *testing.T) {
	r := parseTLS(nmapTLSOutput, "443")
	if len(r.Certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(r.Certs))
	}
	c := r.Certs[0]

	// "ssl-cert: Subject: commonName=example.com" splits on the first colon if
	// the parser is careless, yielding "Subject: commonName=example.com".
	if c.Subject != "commonName=example.com" {
		t.Errorf("Subject = %q, want commonName=example.com", c.Subject)
	}
	if c.NotBefore != "2026-07-29T22:10:08" {
		t.Errorf("NotBefore = %q", c.NotBefore)
	}
	if c.NotAfter != "2026-10-27T22:17:21" {
		t.Errorf("NotAfter = %q", c.NotAfter)
	}
	if c.SignatureAlgorithm != "ecdsa-with-SHA256" {
		t.Errorf("SignatureAlgorithm = %q", c.SignatureAlgorithm)
	}
	if c.WeakHash {
		t.Error("ecdsa-with-SHA256 must not be flagged as a weak hash")
	}
	if len(c.AltNames) != 2 {
		t.Errorf("AltNames = %v, want 2 entries", c.AltNames)
	}
	if c.Expired {
		t.Error("a cert valid into 2026 must not be reported as expired")
	}
}

func TestParseTLSGradesWeakConfiguration(t *testing.T) {
	r := parseTLS(nmapTLSOutput, "443")
	r.Findings = reviewTLS(r)

	var have struct {
		tls10, threeDES, grade bool
	}
	for _, f := range r.Findings {
		switch {
		case strings.Contains(f.Summary, "TLSv1.0") && strings.Contains(f.Summary, "accepted"):
			have.tls10 = true
		case strings.Contains(f.Summary, "3DES"):
			have.threeDES = true
		case strings.Contains(f.Summary, "weakest accepted cipher suite"):
			have.grade = true
		}
	}
	if !have.tls10 {
		t.Error("no finding for the enabled TLSv1.0")
	}
	if !have.threeDES {
		t.Error("no finding for the accepted 3DES suite")
	}
	if !have.grade {
		t.Error("no finding for the C grade reported by nmap")
	}
}

func TestParseTLSModernEndpointHasNoFindings(t *testing.T) {
	r := parseTLS(nmapTLSOutputModern, "443")
	r.Findings = reviewTLS(r)
	if len(r.Findings) != 0 {
		t.Errorf("a TLS 1.2/1.3 endpoint with only A-grade suites produced findings: %+v", r.Findings)
	}
	if got := r.Meta["least_strength"]; got != "A" {
		t.Errorf("least_strength = %q, want A", got)
	}
	if len(r.CipherSuites) == 0 {
		t.Error("CipherSuites is empty for the modern endpoint")
	}
}

func TestParseTLSExtremeLegacyConfiguration(t *testing.T) {
	r := parseTLS(nmapTLSOutputObsolete, "443")
	r.Findings = reviewTLS(r)

	var sslv2, sslv3, weakHash, expired bool
	for _, f := range r.Findings {
		switch {
		case strings.Contains(f.Summary, "SSLv2"):
			sslv2 = true
		case strings.Contains(f.Summary, "SSLv3"):
			sslv3 = true
		case strings.Contains(f.Summary, "signature algorithm") && strings.Contains(f.Summary, "broken"):
			weakHash = true
		case strings.Contains(f.Summary, "has expired"):
			expired = true
		}
	}
	if !sslv2 {
		t.Error("no finding for SSLv2")
	}
	if !sslv3 {
		t.Error("no finding for SSLv3")
	}
	if !weakHash {
		t.Error("no finding for the MD5 signature")
	}
	if !expired {
		t.Error("no finding for the 2012 expiry")
	}
	if len(r.Certs) != 1 || !r.Certs[0].WeakHash {
		t.Error("Certs[0].WeakHash not set for md5WithRSAEncryption")
	}
}

func TestParseTLSEmptyOutputIsNotAnError(t *testing.T) {
	r := parseTLS("", "443")
	if len(r.Ciphers) != 0 || len(r.CipherSuites) != 0 {
		t.Errorf("empty nmap output produced data: %+v", r)
	}
	// An unparseable result must not invent findings.
	if len(r.Findings) != 0 {
		t.Errorf("empty output produced findings: %+v", r.Findings)
	}
}

// The captured endpoint offers 32 suites, 15 of them CBC. Reporting one
// low-severity line per suite buries the high-severity findings, so the cipher
// findings have to stay aggregated.
func TestParseTLSAggregatesCiphersInsteadOfListingEverySuite(t *testing.T) {
	r := parseTLS(nmapTLSOutput, "443")
	r.Findings = reviewTLS(r)
	if len(r.Ciphers) < 8 {
		t.Fatalf("fixture should exercise several suites, got %d", len(r.Ciphers))
	}

	// Count the CBC suites independently, the way the finding should have.
	var wantCBC int
	for _, c := range r.Ciphers {
		cl := strings.ToUpper(c)
		if strings.Contains(cl, "CBC") && !strings.Contains(cl, "3DES") {
			wantCBC++
		}
	}
	if wantCBC < 2 {
		t.Fatalf("fixture should offer several CBC suites, got %d of %v", wantCBC, r.Ciphers)
	}

	var cbcFindings int
	for _, f := range r.Findings {
		if strings.Contains(f.Summary, "CBC-mode") {
			cbcFindings++
			if !strings.Contains(f.Summary, strconv.Itoa(wantCBC)) {
				t.Errorf("CBC finding should report %d suites, got %q", wantCBC, f.Summary)
			}
		}
	}
	if cbcFindings != 1 {
		t.Errorf("got %d CBC findings, want exactly 1 aggregated finding", cbcFindings)
	}
	// The whole point is that the signal is not drowned out.
	if len(r.Findings) > 6 {
		t.Errorf("got %d findings for one endpoint; expected an aggregated set: %+v", len(r.Findings), r.Findings)
	}
}
