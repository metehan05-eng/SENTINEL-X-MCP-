package tools

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// parseNmap turns human-readable nmap output into structured data. Parsing the
// text form (rather than XML) keeps the module free of an nmap binary
// dependency and is sufficient for the fields a triage workflow needs.
func parseNmap(target, profile, out string) ScanResult {
	res := ScanResult{Target: target, ScanType: profile, Hosts: []HostResult{}}
	if strings.TrimSpace(out) == "" {
		return res
	}

	var cur *HostResult
	flush := func() {
		if cur != nil {
			sort.Slice(cur.Ports, func(i, j int) bool { return cur.Ports[i].Port < cur.Ports[j].Port })
			res.Hosts = append(res.Hosts, *cur)
			cur = nil
		}
	}

	inStats := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "Nmap scan report") {
			flush()
			cur = &HostResult{Ports: []PortResult{}, Status: "unknown"}
			cur.IP = parseNmapReportIP(trimmed)
			continue
		}
		if inStats {
			if strings.Contains(trimmed, "Nmap done") {
				res.Stats = trimmed
				inStats = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Host is up") {
			if cur != nil {
				cur.Status = "up"
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Nmap ") {
			inStats = true
			continue
		}
		if strings.HasPrefix(trimmed, "OS details:") || strings.HasPrefix(trimmed, "OS matches|") {
			if cur != nil && !strings.HasPrefix(trimmed, "OS matches|") {
				cur.OSMatches = append(cur.OSMatches, strings.TrimSpace(strings.TrimPrefix(trimmed, "OS details:")))
			}
			continue
		}
		if strings.HasPrefix(trimmed, "OS matches|") || strings.HasPrefix(trimmed, "|") && cur != nil && cur.IP != "" {
			// OS fingerprint row; ignore the trailing detail block.
			if cur != nil && len(cur.OSMatches) == 0 {
				cur.OSMatches = append(cur.OSMatches, "nmap OS fingerprint matched (details suppressed)")
			}
			continue
		}

		if p, ok := parseNmapPortLine(trimmed); ok {
			if cur == nil {
				cur = &HostResult{Status: "unknown", Ports: []PortResult{}}
			}
			cur.Ports = append(cur.Ports, p)
		}
		if cur != nil {
			if h := extractHostname(trimmed); h != "" {
				cur.Hostnames = append(cur.Hostnames, h)
			}
		}
	}
	flush()
	return res
}

// parseNmapPortLine decodes a single port line:
//
//	22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (protocol 2.0)
//
// Some lines carry a reason (`open syn-ack`) and some carry extra NSE output
// glued on after the version (`| ssh-hostkey: ...`).
func parseNmapPortLine(line string) (PortResult, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return PortResult{}, false
	}
	pf := fields[0]
	slash := strings.Index(pf, "/")
	if slash <= 0 {
		return PortResult{}, false
	}
	portNum, err := strconv.Atoi(pf[:slash])
	if err != nil {
		return PortResult{}, false
	}
	proto := pf[slash+1:]
	if proto != "tcp" && proto != "udp" {
		return PortResult{}, false
	}
	state := fields[1]
	switch state {
	case "open", "closed", "filtered", "unfiltered", "open|filtered":
	default:
		return PortResult{}, false
	}

	p := PortResult{Port: portNum, Protocol: proto, State: state}
	if len(fields) >= 3 {
		p.Service = fields[2]
	}
	rest := fields[3:]

	// Drop an NSE pipe section: everything from the first standalone "|".
	pipeAt := -1
	for i, f := range rest {
		if f == "|" {
			pipeAt = i
			break
		}
	}
	if pipeAt >= 0 {
		rest = rest[:pipeAt]
	}
	if len(rest) == 0 {
		return p, true
	}

	// Everything from the first parenthesised token onward is nmap commentary
	// ("(protocol 2.0)", "(Ubuntu)", "(unconfirmed)"), not part of the version.
	cut := len(rest)
	for i, f := range rest {
		if strings.Contains(f, "(") || strings.Contains(f, ")") {
			cut = i
			break
		}
	}
	versionTokens := make([]string, 0, cut)
	for _, f := range rest[:cut] {
		if f = strings.Trim(f, "(),"); f == "" {
			continue
		}
		versionTokens = append(versionTokens, f)
	}
	if len(versionTokens) > 0 {
		p.Product = versionTokens[0]
	}
	if len(versionTokens) > 1 {
		p.Version = strings.Join(versionTokens[1:], " ")
	}
	// "extra info" arrives in the trailing parenthetical group.
	if i := strings.Index(line, "("); i >= 0 && strings.HasSuffix(strings.TrimSpace(line), ")") {
		extra := strings.TrimSpace(line[i+1 : len(line)-1])
		if extra != "" {
			p.Extra = extra
		}
	}
	p.Conf = nmapConfidence(line)
	return p, true
}

func nmapConfidence(line string) float64 {
	i := strings.Index(strings.ToLower(line), "confidence")
	if i < 0 {
		return 0
	}
	rest := line[i+len("confidence"):]
	var f float64
	if _, err := fmt.Sscanf(strings.TrimSpace(rest), "%f", &f); err == nil {
		return f
	}
	return 0
}

// parseNmapReportIP extracts the address from an "Nmap scan report for ..." line.
// The hostname is either bare ("for 192.168.1.10") or followed by the address in
// parentheses ("for gateway (192.168.1.1)"), and it is the address — not the
// name — that a later CPE correlation needs.
func parseNmapReportIP(line string) string {
	if i := strings.LastIndex(line, "("); i >= 0 {
		if j := strings.LastIndex(line, ")"); j > i {
			if v := strings.TrimSpace(line[i+1 : j]); v != "" {
				return v
			}
		}
	}
	if f := strings.Fields(line); len(f) > 0 {
		return strings.Trim(f[len(f)-1], "()")
	}
	return ""
}

func extractHostname(line string) string {
	if !strings.HasPrefix(line, "Hostname:") {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Hostname:")))
}

// reviewScan applies the triage rules that turn a port list into actionable
// findings. The rules are intentionally conservative: they flag conditions
// worth confirming, not confirmed vulnerabilities.
func reviewScan(r ScanResult) []Finding {
	var out []Finding
	for _, h := range r.Hosts {
		if h.Status != "up" {
			continue
		}
		open := make([]int, 0, len(h.Ports))
		closed := 0
		for _, p := range h.Ports {
			switch p.State {
			case "open":
				open = append(open, p.Port)
			case "closed":
				closed++
			}
		}
		if len(open) == 0 {
			out = append(out, Finding{
				Severity: "info",
				Summary:  fmt.Sprintf("%s: no open ports observed (%d closed)", h.IP, closed),
				Evidence: "nmap port table contains only closed ports",
			})
			continue
		}

		for _, p := range h.Ports {
			if p.State != "open" {
				continue
			}
			notes := checkService(p)
			for _, n := range notes {
				out = append(out, Finding{
					Severity:  n.severity,
					Summary:   fmt.Sprintf("%s:%d %s — %s", h.IP, p.Port, p.Service, n.summary),
					Evidence:  strings.TrimSpace(p.Product + " " + p.Version),
					Remediate: n.remediate,
				})
			}
		}
		if len(open) > 15 {
			out = append(out, Finding{
				Severity:  "medium",
				Summary:   fmt.Sprintf("%s: %d open ports — broad exposure increases the attack surface", h.IP, len(open)),
				Remediate: "close unused ports and restrict the remainder to the networks that need them",
			})
		}
	}
	return out
}

type note struct {
	severity  string
	summary   string
	remediate string
}

// checkService flags service-specific conditions that are worth a closer look.
// These are heuristics derived from banner information, not exploit logic.
func checkService(p PortResult) []note {
	var out []note
	sv := strings.ToLower(p.Service)
	ver := strings.ToLower(p.Version)

	switch {
	case p.Port == 23:
		out = append(out, note{"high", "telnet transmits credentials in cleartext", "disable telnet; use SSH with key-based authentication"})
	case p.Port == 21 && (strings.Contains(ver, "vsftpd 2.3") || strings.Contains(ver, "3.0.3")):
		out = append(out, note{"high", "FTP banner indicates a release with publicly documented backdoor code paths; verify the patch level manually", "upgrade to a current release and re-verify the banner"})
	case p.Port == 69:
		out = append(out, note{"medium", "TFTP has no authentication", "restrict the source address or replace with an authenticated transfer protocol"})
	case p.Port == 512 || p.Port == 513 || p.Port == 514:
		out = append(out, note{"high", "rlogin/rsh/regex services rely on host-based trust", "disable rsh-family services"})
	case p.Port == 2049:
		out = append(out, note{"medium", "NFS export is reachable; exports may be world-writable", "review exports with showmount -e and remove any '*' entries"})
	case p.Port == 3389:
		out = append(out, note{"info", "RDP exposure — confirm it is required and that NLA/CredSSP is enforced", "require network-level authentication; restrict source ranges"})
	case p.Port == 5900 || p.Port == 5901:
		out = append(out, note{"high", "VNC often runs without encryption or with a weak desktop password", "tunnel VNC over SSH and enforce strong authentication"})
	case sv == "smtp" && p.Port == 25:
		if strings.Contains(ver, "exim") && !strings.Contains(ver, "4.9") {
			out = append(out, note{"info", "SMTP service detected; verify that it does not act as an open relay", "test relay behaviour from an external host and enforce authenticated submission"})
		}
	case sv == "http" || sv == "https":
		if strings.Contains(ver, "apache httpd 1.") || strings.Contains(ver, "apache httpd 2.2") ||
			strings.Contains(ver, "nginx 1.0") || strings.Contains(ver, "nginx 1.2") ||
			strings.Contains(strings.ToLower(p.Extra), "eol") {
			out = append(out, note{"high", "web server reports an end-of-life version", "upgrade to a currently supported release"})
		}
		if strings.Contains(ver, "openssl 1.0") || strings.Contains(ver, "openssl 1.1.0") {
			out = append(out, note{"medium", "server reports an end-of-life OpenSSL version", "upgrade the TLS library"})
		}
	case sv == "ssh":
		if strings.Contains(ver, "openssh 1.") || strings.Contains(ver, "openssh 2.") || strings.Contains(ver, "openssh 3.") || strings.Contains(ver, "openssh 4.") {
			out = append(out, note{"high", "SSH reports a legacy release with known weaknesses", "upgrade to a maintained OpenSSH release"})
		}
	case sv == "http-proxy" || sv == "squid":
		out = append(out, note{"medium", "an HTTP proxy is exposed; it may permit an open relay or proxy to internal resources", "restrict ACLs to the intended client ranges"})
	case p.Port == 1080 || p.Port == 3128 || p.Port == 8080:
		if sv == "" || strings.Contains(sv, "proxy") {
			out = append(out, note{"low", "commonly used as a local proxy port; confirm it is intended to be reachable", "bind to loopback if it is only for local use"})
		}
	}

	if p.Product != "" && p.Conf > 0 && p.Conf < 0.75 {
		out = append(out, note{
			"low",
			fmt.Sprintf("version fingerprint confidence is %.0f%%; treat the detected version as unconfirmed", p.Conf*100),
			"confirm the version from a vendor response or an authenticated channel before acting on it",
		})
	}
	if p.Version == "" && p.Product == "" && p.Service != "" {
		out = append(out, note{
			"low",
			fmt.Sprintf("service %q identified but no version detected; it may still be end-of-life", p.Service),
			"identify the exact build from the application owner",
		})
	}
	return out
}

// parseTLS extracts certificates, protocols and ciphers from nmap's script
// output.
// stripScriptLine removes the nmap script-output decoration from a line.
//
// nmap prefixes every line the script emits with "| ", terminates a block with
// "|_ ", and leaves trailing whitespace behind. A parser that forgets this sees
// a line beginning with "|" and every field-prefix test below fails, which is how
// the previous parser returned an empty result for a perfectly healthy endpoint.
func stripScriptLine(l string) string {
	l = strings.TrimSpace(l)
	if l == "" {
		return ""
	}
	if strings.HasPrefix(l, "|_") {
		l = strings.TrimSpace(l[2:])
	} else if strings.HasPrefix(l, "|") {
		l = strings.TrimSpace(l[1:])
	}
	return strings.TrimSpace(l)
}

func parseTLS(out, ports string) TLSAuditResult {
	r := TLSAuditResult{Ports: strings.Split(ports, ",")}
	if r.Ports == nil {
		r.Ports = []string{}
	}
	r.Meta = map[string]string{}

	cur := CertSummary{AltNames: []string{}}
	flushCert := func() {
		if cur.Subject != "" || cur.Issuer != "" || len(cur.AltNames) > 0 {
			applyCertDates(&cur)
			r.Certs = append(r.Certs, cur)
		}
		cur = CertSummary{AltNames: []string{}}
	}

	// The ssl-enum-ciphers block is a tree, not a flat list:
	//
	//     TLSv1.0:
	//       ciphers:
	//         TLS_ECDHE_..._SHA (ecdh_x25519) - A
	//       compressors:
	//         NULL
	//
	// Cipher names live on their own indented lines beneath "ciphers:", so they
	// are collected by position within the block. Matching a single flat
	// "ciphers:" line, as an earlier version did, reads the value from a line
	// that is always empty and therefore finds no suites at all.
	inCiphers := false
	var protocol string

	for _, line := range strings.Split(out, "\n") {
		l := scriptLine(line)
		if l == "" {
			continue
		}
		lower := strings.ToLower(l)

		// A protocol header closes the previous cipher list. nmap writes these
		// as a bare name with a trailing colon.
		if isTLSVersionHeader(lower) {
			protocol = normalizeProtocolName(strings.TrimSuffix(l, ":"))
			r.Protocols = append(r.Protocols, protocol)
			inCiphers = false
			continue
		}

		switch {
		case strings.HasPrefix(lower, "ciphers:"):
			inCiphers = true
			continue
		case strings.HasPrefix(lower, "compressors:"),
			strings.HasPrefix(lower, "cipher preference:"),
			strings.HasPrefix(lower, "least strength:"):
			inCiphers = false
			if strings.HasPrefix(lower, "least strength:") {
				r.Meta["least_strength"] = afterColon(l)
			}
			continue
		}

		if inCiphers {
			if suite, ok := parseCipherSuite(l); ok {
				suite.Protocol = protocol
				r.CipherSuites = append(r.CipherSuites, suite)
				r.Ciphers = append(r.Ciphers, suite.Name)
			}
			continue
		}

		// nmap decorates the first line of the cert block with the script name,
		// so what actually arrives is "ssl-cert: Subject: commonName=x". Match
		// the label by position in the line rather than at its start.
		//
		// A new "Subject:" is the only reliable signal that a new certificate has
		// begun. Splitting on "Issuer:" instead tore one certificate in half,
		// because the subject alternative names had already been attached to
		// the first half by the time the issuer arrived.
		switch {
		case certHas(l, "subject alternative name:"):
			for _, n := range strings.Split(afterColon(l), ",") {
				if n = strings.TrimSpace(n); n != "" {
					cur.AltNames = append(cur.AltNames, n)
				}
			}
		case certHas(l, "subject:"):
			flushCert()
			cur.Subject = certFieldValue(l, "subject:")
		case certHas(l, "issuer:"):
			cur.Issuer = certFieldValue(l, "issuer:")
		case certHas(l, "not valid before:"), certHas(l, "not before:"):
			cur.NotBefore = afterColon(l)
		case certHas(l, "not valid after:"), certHas(l, "not after:"):
			cur.NotAfter = afterColon(l)
		case certHas(l, "signature algorithm:"):
			cur.SignatureAlgorithm = afterColon(l)
			cur.WeakHash = isWeakHash(cur.SignatureAlgorithm)
		case certHas(l, "public key type:"):
			cur.PublicKeyType = afterColon(l)
		case certHas(l, "public key bits:"):
			// The 2048-bit floor applies to RSA only. ECDSA P-256 and Ed25519
			// are 256-bit keys and are entirely standard, so thresholding the
			// bare bit count would report every modern elliptic-curve
			// certificate as weak.
			cur.PublicKeyBits, _ = strconv.Atoi(strings.TrimSpace(afterColon(l)))
			cur.WeakKey = isWeakKey(cur.PublicKeyType, cur.PublicKeyBits)
		case certHas(l, "self-signed"):
			cur.SelfSigned = true
		}
	}
	flushCert()
	r.Ciphers = dedupe(r.Ciphers)
	r.Protocols = dedupe(r.Protocols)
	return r
}

// isTLSVersionHeader matches "TLSv1.0:", "SSLv3:" and their spaced variants.
func isTLSVersionHeader(lower string) bool {
	if !strings.HasSuffix(lower, ":") {
		return false
	}
	body := strings.TrimSuffix(lower, ":")
	return body == "sslv2" || body == "sslv3" ||
		strings.HasPrefix(body, "tlsv") || strings.HasPrefix(body, "tls 1")
}

func normalizeProtocolName(s string) string {
	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	switch {
	case lower == "sslv2":
		return "SSLv2"
	case lower == "sslv3":
		return "SSLv3"
	// "TLSv1.0": drop "TLSv", drop the separating dot, keep "1.0".
	case strings.HasPrefix(lower, "tlsv"):
		return "TLSv" + strings.TrimPrefix(s[4:], ".")
	// "TLS 1.0": drop "TLS ", keep "1.0".
	case strings.HasPrefix(lower, "tls "):
		return "TLSv" + strings.TrimSpace(s[4:])
	}
	return s
}

// scriptLine returns the line only if it came from a script block, so nmap's own
// prose ("Nmap scan report for ...") is never mistaken for script data.
func scriptLine(l string) string {
	t := strings.TrimSpace(l)
	if !strings.HasPrefix(t, "|") {
		return ""
	}
	return stripScriptLine(l)
}

// certHas reports whether the cert field label appears anywhere in the line.
func certHas(l, label string) bool {
	return strings.Contains(strings.ToLower(l), label)
}

// certFieldValue pulls the value out of a "Label: value" line using the full
// label, because nmap writes "ssl-cert: Subject: commonName=x" and splitting on
// the first colon would return the text "Subject: commonName=x".
func certFieldValue(l, label string) string {
	lower := strings.ToLower(l)
	i := strings.Index(lower, label)
	if i < 0 {
		return afterColon(l)
	}
	return strings.TrimSpace(l[i+len(label):])
}

// parseCipherSuite reads a single line such as
//
//	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
//
// The trailing "- A" is nmap's own strength grade, kept because it is the
// cheapest way to see which suites are weak.
func parseCipherSuite(l string) (CipherSuite, bool) {
	fields := strings.Fields(l)
	if len(fields) < 2 {
		return CipherSuite{}, false
	}
	if !strings.HasPrefix(fields[0], "SSL_") && !strings.HasPrefix(fields[0], "TLS_") {
		return CipherSuite{}, false
	}
	cs := CipherSuite{Name: fields[0]}
	if i := strings.Index(l, "("); i >= 0 {
		cs.KeyExchange = strings.Trim(strings.TrimSpace(l[i:]), "()")
		if j := strings.Index(cs.KeyExchange, " "); j > 0 {
			cs.KeyExchange = cs.KeyExchange[:j]
		}
	}
	if last := fields[len(fields)-1]; len(last) == 1 && last[0] >= 'A' && last[0] <= 'F' {
		cs.Grade = last
	}
	return cs, true
}

// isWeakKey applies the minimum key size for the key's family.
func isWeakKey(keyType string, bits int) bool {
	if bits <= 0 {
		return false
	}
	switch {
	case strings.Contains(keyType, "ec"), strings.Contains(keyType, "eddsa"):
		return bits < 256
	case strings.Contains(keyType, "rsa"):
		return bits < 2048
	}
	// Unknown family: only flag a key that is implausibly small.
	return bits < 1024
}

func isWeakHash(sig string) bool {
	l := strings.ToLower(sig)
	return strings.Contains(l, "md2") || strings.Contains(l, "md4") ||
		strings.Contains(l, "md5") || strings.Contains(l, "sha1")
}

// tlsPostureFindings grades what the structured fields revealed. Every finding
// is derived from a parsed field, so a field the parser failed to read can never
// be reported as a clean result.
// applyCertDates fills in the derived expiry fields from the parsed dates.
//
// nmap prints cert dates as RFC 3339 without a zone designator, e.g.
// "2026-10-27T22:17:21", so a layout list containing only time.RFC3339 never
// matched and every certificate came back with no expiry information at all.
func applyCertDates(c *CertSummary) {
	parse := func(s string) time.Time {
		s = strings.TrimSpace(s)
		if s == "" {
			return time.Time{}
		}
		for _, layout := range []string{
			"Jan 02 15:04:05 2006 GMT",
			time.RFC3339,
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05 MST",
			"2006-01-02",
		} {
			if t, err := time.Parse(layout, s); err == nil {
				return t
			}
		}
		return time.Time{}
	}
	na := parse(c.NotAfter)
	if !na.IsZero() {
		c.DaysRemaining = int(time.Until(na).Hours() / 24)
		c.Expired = time.Now().After(na)
	}
}

func reviewTLS(r TLSAuditResult) []Finding {
	var out []Finding
	if len(r.Certs) == 0 {
		return out
	}

	for _, c := range r.Certs {
		if c.Expired {
			out = append(out, Finding{Severity: "high", Summary: "certificate has expired", Evidence: c.NotAfter, Remediate: "renew and deploy the certificate"})
		} else if c.DaysRemaining > 0 && c.DaysRemaining < 15 {
			out = append(out, Finding{Severity: "medium", Summary: fmt.Sprintf("certificate expires in %d days", c.DaysRemaining), Evidence: c.NotAfter, Remediate: "schedule renewal now to avoid an outage"})
		} else if c.DaysRemaining > 0 && c.DaysRemaining < 30 {
			out = append(out, Finding{Severity: "low", Summary: fmt.Sprintf("certificate expires in %d days", c.DaysRemaining), Evidence: c.NotAfter, Remediate: "confirm automated renewal is working"})
		}
		if c.SelfSigned {
			out = append(out, Finding{Severity: "medium", Summary: "certificate is self-signed and will not be trusted by clients", Evidence: c.Subject, Remediate: "deploy a certificate from a trusted CA"})
		}
		if c.WeakHash {
			out = append(out, Finding{
				Severity:  "high",
				Summary:   fmt.Sprintf("certificate signature algorithm %s is broken", c.SignatureAlgorithm),
				Evidence:  c.Subject,
				Remediate: "reissue with SHA-256 or stronger; MD5 and SHA-1 are collision-broken and rejected by modern clients",
			})
		}
		if c.WeakKey {
			out = append(out, Finding{
				Severity:  "high",
				Summary:   fmt.Sprintf("certificate public key is only %d bits", c.PublicKeyBits),
				Evidence:  c.Subject,
				Remediate: "reissue with at least a 2048-bit RSA key or a P-256/Ed25519 key",
			})
		}
		if c.Subject != "" && c.Issuer != "" && !c.SelfSigned && c.Subject == c.Issuer {
			out = append(out, Finding{Severity: "medium", Summary: "subject and issuer are identical but the certificate was not flagged as self-signed; inspect the chain", Evidence: c.Subject})
		}
		if len(c.AltNames) == 0 && c.Subject != "" {
			out = append(out, Finding{Severity: "low", Summary: "certificate has no subjectAltName entries; modern clients require SANs", Evidence: c.Subject, Remediate: "reissue with the full SAN list"})
		}
	}

	for _, p := range r.Protocols {
		// Compare case-insensitively. The literals are mixed case ("SSLv3",
		// "TLSv1.0") while the subject is upper-cased, so an exact match never
		// fired and no protocol finding was ever produced.
		switch {
		case strings.EqualFold(p, "SSLv2"), strings.EqualFold(p, "SSLv3"):
			out = append(out, Finding{Severity: "high", Summary: fmt.Sprintf("%s is still accepted; it is broken by design", p), Remediate: "disable everything below TLS 1.2"})
		case strings.EqualFold(p, "TLSv1"), strings.EqualFold(p, "TLSv1.0"), strings.EqualFold(p, "TLSv1.1"):
			out = append(out, Finding{Severity: "medium", Summary: fmt.Sprintf("%s is still accepted and is deprecated", p), Remediate: "require TLS 1.2 or higher"})
		}
	}

	// A modern endpoint negotiates 20-40 suites, so emitting one finding per
	// suite buries the two or three findings that actually matter under a wall
	// of low-severity noise. Broken ciphers are named individually because
	// they must be removed by name; merely outdated ones are aggregated.
	var broken, cbc, md5 int
	var brokenNames []string
	for _, c := range r.Ciphers {
		cl := strings.ToUpper(c)
		switch {
		case strings.Contains(cl, "NULL"), strings.Contains(cl, "EXPORT"), strings.Contains(cl, "ANON"),
			strings.HasPrefix(cl, "RC4"), strings.Contains(cl, "3DES"), strings.Contains(cl, "DES-"),
			strings.Contains(cl, "IDEA"), strings.Contains(cl, "SEED"):
			broken++
			brokenNames = append(brokenNames, c)
		case strings.Contains(cl, "MD5"):
			md5++
		case strings.Contains(cl, "CBC"):
			cbc++
		}
	}
	if broken > 0 {
		out = append(out, Finding{
			Severity:  "high",
			Summary:   fmt.Sprintf("%d broken cipher suite(s) accepted (NULL, EXPORT, anonymous, RC4, 3DES/DES, IDEA or SEED)", broken),
			Evidence:  strings.Join(brokenNames, ", "),
			Remediate: "restrict the cipher list to ECDHE suites with AES-GCM or ChaCha20-Poly1305",
		})
	}
	if md5 > 0 {
		out = append(out, Finding{
			Severity:  "high",
			Summary:   fmt.Sprintf("%d cipher suite(s) use an MD5-based MAC", md5),
			Remediate: "remove every MD5 suite from the cipher list",
		})
	}
	if cbc > 0 {
		sev := "low"
		summary := fmt.Sprintf("%d CBC-mode suite(s) accepted; these remain vulnerable to padding-oracle timing attacks", cbc)
		if len(r.Protocols) == 1 && r.Protocols[0] == "TLSv1.2" {
			// CBC is the only mode TLS 1.2 can offer, so its presence alone is
			// not a defect there.
			summary += " (expected on TLS 1.2, which has no AEAD-before-1.3 negotiation)"
		}
		out = append(out, Finding{
			Severity:  sev,
			Summary:   summary,
			Remediate: "offer AEAD suites (AES-GCM, ChaCha20-Poly1305) ahead of CBC and prefer TLS 1.3, which drops CBC entirely",
		})
	}
	if ls := r.Meta["least_strength"]; ls != "" && ls > "A" {
		out = append(out, Finding{
			Severity:  "medium",
			Summary:   fmt.Sprintf("nmap grades the weakest accepted cipher suite as %s", ls),
			Evidence:  "least strength: " + ls,
			Remediate: "drop every suite weaker than A so negotiation cannot land on a C-grade suite",
		})
	}
	return dedupeFindings(out)
}

func reviewHTTP(r HTTPResult) []Finding {
	var out []Finding
	required := map[string]string{
		"strict-transport-security": "hsts",
		"content-security-policy":   "csp",
		"x-content-type-options":    "no-sniff",
		"x-frame-options":           "frame-ancestors",
		"referrer-policy":           "referrer-leakage",
	}
	present := map[string]bool{}
	for k := range r.Headers {
		present[strings.ToLower(k)] = true
	}
	for hdr, label := range required {
		if !present[hdr] {
			r.Missing = append(r.Missing, hdr)
			sev := "medium"
			if hdr == "strict-transport-security" {
				sev = "low"
			}
			out = append(out, Finding{
				Severity:  sev,
				Summary:   fmt.Sprintf("missing %s header (%s)", hdr, label),
				Remediate: "Set the header at the edge; for CSP start with a report-only policy and tighten from there.",
			})
		} else {
			r.Present = append(r.Present, hdr)
		}
	}
	sort.Strings(r.Missing)
	sort.Strings(r.Present)

	if r.Server != "" {
		out = append(out, Finding{
			Severity:  "low",
			Summary:   fmt.Sprintf("server discloses its product and version: %q", r.Server),
			Remediate: "suppress or normalise the Server and X-Powered-By headers",
		})
	}
	if csp, found := r.Headers["content-security-policy"]; found {
		switch {
		case strings.Contains(strings.ToLower(csp), "unsafe-inline"):
			out = append(out, Finding{Severity: "medium", Summary: "CSP permits unsafe-inline, which largely defeats XSS mitigation", Evidence: csp})
		case strings.Contains(strings.ToLower(csp), "unsafe-eval"):
			out = append(out, Finding{Severity: "low", Summary: "CSP permits unsafe-eval", Evidence: csp})
		case strings.Contains(strings.ToLower(csp), "unsafe-hashes"):
			out = append(out, Finding{Severity: "low", Summary: "CSP permits unsafe-hashes", Evidence: csp})
		case !strings.Contains(strings.ToLower(csp), "default-src"):
			out = append(out, Finding{Severity: "low", Summary: "CSP has no default-src directive, so unspecified resource types are unrestricted", Evidence: csp})
		}
	}
	if sc, found := r.Headers["strict-transport-security"]; found && !strings.Contains(strings.ToLower(sc), "max-age") {
		out = append(out, Finding{Severity: "low", Summary: "HSTS header has no max-age directive", Evidence: sc})
	}
	if r.Status != "" && (strings.HasPrefix(r.Status, "500") || strings.HasPrefix(r.Status, "502") || strings.HasPrefix(r.Status, "503")) {
		out = append(out, Finding{Severity: "low", Summary: fmt.Sprintf("origin returned %s", r.Status), Remediate: "confirm the error page does not disclose a stack trace"})
	}
	return dedupeFindings(out)
}

func dedupeFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	out := in[:0]
	for _, f := range in {
		k := f.Severity + "|" + f.Summary
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func afterColon(l string) string {
	if i := strings.Index(l, ":"); i >= 0 {
		return strings.TrimSpace(l[i+1:])
	}
	return strings.TrimSpace(l)
}
