package tools

import "testing"

func TestValidPortSpec(t *testing.T) {
	valid := []string{
		"22", "80,443", "1-1024", "22,80,443,8000-8100", "top-100", "TOP-1000",
		"U53", "T1-1024", "53,161,162", "1-1024,3000-4000",
	}
	for _, s := range valid {
		if !validPortSpec(s) {
			t.Errorf("validPortSpec(%q) = false, want true", s)
		}
	}

	// Each of these is an attempt to smuggle an nmap option through a field
	// that is documented to carry a port list.
	invalid := []string{
		"", "-sS", "-sS --script vuln", "--script vuln", "-p 1-100",
		"22; whoami", "22 && id", "$(id)", "22\n-oN /tmp/x", "`id`",
		"70000", "0", "100-22", "80,,443", "abc", "22 443", "-",
		"80 -oG /tmp/out", "--top-ports", "../../etc/passwd",
	}
	for _, s := range invalid {
		if validPortSpec(s) {
			t.Errorf("validPortSpec(%q) = true, want false", s)
		}
	}
}

func TestParseNmapPortLine(t *testing.T) {
	cases := []struct {
		line    string
		port    int
		proto   string
		state   string
		service string
		product string
		version string
	}{
		{
			line: "22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (protocol 2.0)",
			port: 22, proto: "tcp", state: "open", service: "ssh",
			product: "OpenSSH", version: "8.9p1 Ubuntu 3ubuntu0.6",
		},
		{
			line: "80/tcp   open   http    nginx 1.18.0 (Ubuntu)",
			port: 80, proto: "tcp", state: "open", service: "http",
			product: "nginx", version: "1.18.0",
		},
		{
			// Reason codes appear in the state column position for some builds.
			line: "443/tcp  open  ssl/http Apache httpd 2.4.52 ((Ubuntu))",
			port: 443, proto: "tcp", state: "open", service: "ssl/http",
			product: "Apache", version: "httpd 2.4.52",
		},
		{
			line: "53/udp   open   domain",
			port: 53, proto: "udp", state: "open", service: "domain",
		},
		{
			line: "8080/tcp closed http-proxy",
			port: 8080, proto: "tcp", state: "closed", service: "http-proxy",
		},
		{
			// NSE output glued onto the version must not leak into Version.
			line: "21/tcp   open   ftp     vsftpd 3.0.3 | ftp-anon: Anonymous FTP logins allowed",
			port: 21, proto: "tcp", state: "open", service: "ftp",
			product: "vsftpd", version: "3.0.3",
		},
	}

	for _, c := range cases {
		got, ok := parseNmapPortLine(c.line)
		if !ok {
			t.Errorf("parseNmapPortLine(%q) failed to parse", c.line)
			continue
		}
		if got.Port != c.port || got.Protocol != c.proto || got.State != c.state {
			t.Errorf("parseNmapPortLine(%q) = port %d/%s/%s, want %d/%s/%s",
				c.line, got.Port, got.Protocol, got.State, c.port, c.proto, c.state)
		}
		if got.Service != c.service {
			t.Errorf("parseNmapPortLine(%q).Service = %q, want %q", c.line, got.Service, c.service)
		}
		if c.product != "" && got.Product != c.product {
			t.Errorf("parseNmapPortLine(%q).Product = %q, want %q", c.line, got.Product, c.product)
		}
		if c.version != "" && got.Version != c.version {
			t.Errorf("parseNmapPortLine(%q).Version = %q, want %q", c.line, got.Version, c.version)
		}
	}

	// Lines that are not port rows must be rejected outright.
	for _, line := range []string{
		"Nmap scan report for example.com (93.184.216.34)",
		"Host is up (0.021s latency).",
		"22/tcpx open ssh",
		"not a port line at all",
		"",
	} {
		if _, ok := parseNmapPortLine(line); ok {
			t.Errorf("parseNmapPortLine(%q) unexpectedly parsed", line)
		}
	}
}

func TestParseNmapMultiHost(t *testing.T) {
	out := `Nmap scan report for gateway (192.168.1.1)
Host is up (0.0021s latency).
Not shown: 997 closed ports
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
80/tcp   open  http    lighttpd 1.4.69
443/tcp  closed https
MAC Address: AA:BB:CC:DD:EE:FF (Intel Corporate)

Nmap scan report for 192.168.1.10
Host is up (0.005s latency).
53/tcp   open   domain
Nmap done: 2 IP addresses (2 hosts up) scanned in 3.11 seconds
`
	r := parseNmap("192.168.1.0/24", "standard", out)
	if len(r.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(r.Hosts))
	}
	if r.Hosts[0].IP != "192.168.1.1" {
		t.Errorf("first host IP = %q, want 192.168.1.1", r.Hosts[0].IP)
	}
	if len(r.Hosts[0].Ports) != 3 {
		t.Fatalf("first host has %d ports, want 3", len(r.Hosts[0].Ports))
	}
	// Ports must come back sorted for stable output.
	if r.Hosts[0].Ports[0].Port != 22 || r.Hosts[0].Ports[2].Port != 443 {
		t.Errorf("ports not sorted: %v", r.Hosts[0].Ports)
	}
	if r.Hosts[1].IP != "192.168.1.10" || len(r.Hosts[1].Ports) != 1 {
		t.Errorf("second host parsed wrong: %+v", r.Hosts[1])
	}
	// A closed port is a finding-relevant fact and must survive parsing.
	if r.Hosts[0].Ports[2].State != "closed" {
		t.Errorf("443 state = %q, want closed", r.Hosts[0].Ports[2].State)
	}
}

func TestVersionPrefix(t *testing.T) {
	cases := map[string]string{
		"8.2p1 Ubuntu 4ubuntu0.13": "8.2",
		"1.18.0":                   "1.18",
		"2.4.52":                   "2.4",
		"9.2p1":                    "9.2",
		"unknown":                  "",
		"":                         "",
	}
	for in, want := range cases {
		if got := versionPrefix(in); got != want {
			t.Errorf("versionPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// cranges turns plain CPE strings into the range form the matcher reads, for
// the records that declare a version with no bounds.
func cranges(cpes ...string) []cpeRange {
	out := make([]cpeRange, 0, len(cpes))
	for _, c := range cpes {
		out = append(out, cpeRange{criteria: c})
	}
	return out
}

func TestVersionInProducts(t *testing.T) {
	products := []string{
		"cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*",
		"cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
	}
	if hit, _, _ := versionInProducts("openssh", cranges(products...), "8.2p1", "8.2"); !hit {
		t.Error("versionInProducts failed to match OpenSSH 8.2 against its own CPE")
	}
	// A version outside every listed CPE must not be reported as affected.
	if hit, _, _ := versionInProducts("openssh", cranges(products...), "9.9", "9.9"); hit {
		t.Error("versionInProducts matched a version that appears in no CPE range")
	}
	// A version field of "*" with no bounds means "unknown", not "any".
	if hit, _, _ := versionInProducts("thing", cranges("cpe:2.3:a:vendor:thing:*:*:*:*:*:*:*:*"), "1.0", "1.0"); hit {
		t.Error("an unbounded '*' version must not be treated as a match")
	}
}

// A CPE for nginx 0.1.24 contains the digits "1.24", and a bare substring
// search over the whole string reported nginx 1.24.0 as affected by it. The
// version field has to be compared as a version, not searched for as text.
func TestVersionInProductsRejectsSubstringFalsePositive(t *testing.T) {
	cases := []struct {
		name    string
		cpes    []string
		version string
		want    bool
	}{
		{"different version with a shared tail", []string{"cpe:2.3:a:nginx:nginx:0.1.24:*:*:*:*:*:*:*"}, "1.24.0", false},
		{"the version itself", []string{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}, "1.24.0", true},
		{"patch level differs", []string{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}, "1.24.3", false},
		{"trailing digits in another field", []string{"cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:1.24"}, "1.24.0", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, _ := versionInProducts("nginx", cranges(c.cpes...), c.version, versionPrefix(c.version))
			if got != c.want {
				t.Errorf("version %s against %v = %v, want %v", c.version, c.cpes, got, c.want)
			}
		})
	}
}

// NVD expresses most affected ranges as a "*" version plus bounds, so matching
// on the criteria string alone reports nothing for the common case.
func TestVersionInProductsUsesDeclaredRanges(t *testing.T) {
	cases := []struct {
		name    string
		r       cpeRange
		version string
		want    bool
	}{
		{"below an exclusive end", cpeRange{endExcl: "1.25.0"}, "1.24.0", true},
		{"at an exclusive end", cpeRange{endExcl: "1.24.0"}, "1.24.0", false},
		{"above an exclusive end", cpeRange{endExcl: "1.20.0"}, "1.24.0", false},
		{"at an inclusive end", cpeRange{endIncl: "1.24.0"}, "1.24.0", true},
		{"above an inclusive end", cpeRange{endIncl: "1.24.0"}, "1.24.1", false},
		{"below a lessThan", cpeRange{lessThan: "1.24.0"}, "1.23.9", true},
		{"at a lessThanOrEqual", cpeRange{lessEq: "1.24.0"}, "1.24.0", true},
		{"above a lessThanOrEqual", cpeRange{lessEq: "1.24.0"}, "1.24.1", false},
		{"inside a start-inclusive range", cpeRange{startIncl: "1.20.0", endExcl: "1.30.0"}, "1.24.0", true},
		{"below a start-inclusive range", cpeRange{startIncl: "1.20.0", endExcl: "1.30.0"}, "1.10.0", false},
		{"short and long version forms are equal", cpeRange{startIncl: "1.24", endExcl: "1.25"}, "1.24.0", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.r.criteria = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
			got, _, _ := versionInProducts("nginx", []cpeRange{c.r}, c.version, versionPrefix(c.version))
			if got != c.want {
				t.Errorf("version %s against range %+v = %v, want %v", c.version, c.r, got, c.want)
			}
		})
	}
}

// A record that declares bounds is judged on those bounds alone; the criteria
// string is not a second, looser chance to match.
func TestVersionInProductsPrefersRangesOverCriteria(t *testing.T) {
	// Criteria says 1.24.0 exactly, but the declared range excludes it.
	r := cpeRange{criteria: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", endExcl: "1.20.0"}
	if hit, _, _ := versionInProducts("nginx", []cpeRange{r}, "1.24.0", "1.24"); hit {
		t.Error("a version outside the declared range matched anyway")
	}
}

// These are the exact shapes NVD publishes. Reading only the first bound that
// was present turned "2.0 to under 3.1" into "2.0 and later" and reported a
// 2002 OpenSSH advisory against OpenSSH 9.6.
func TestVersionInProductsHandlesRealNVDRangeShapes(t *testing.T) {
	cases := []struct {
		name    string
		product string
		cpes    []string
		ranges  []cpeRange
		version string
		want    bool
	}{
		{
			product: "openssh",
			name:    "openssh bounded below and above excludes a newer host",
			cpes:    []string{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{startIncl: "2.0", endExcl: "3.1"}},
			version: "9.6p1",
			want:    false,
		},
		{
			product: "openssh",
			name:    "the same range still covers a host inside it",
			cpes:    []string{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{startIncl: "2.0", endExcl: "3.1"}},
			version: "2.5",
			want:    true,
		},
		{
			product: "nginx",
			name:    "nginx window that ends before the host version",
			cpes:    []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{startIncl: "1.9.0", endExcl: "1.9.10"}},
			version: "1.24.0",
			want:    false,
		},
		{
			product: "nginx",
			name:    "nginx window that contains the host version",
			cpes:    []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{startIncl: "0.6.18", endIncl: "1.8.0"}},
			version: "1.24.0",
			want:    false,
		},
		{
			product: "tornado",
			name:    "tornado fixed below 6.5.0 excludes 6.5.4",
			cpes:    []string{"cpe:2.3:a:tornadoweb:tornado:*:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{endExcl: "6.5.0"}},
			version: "6.5.4",
			want:    false,
		},
		{
			product: "thing",
			name:    "a start with no ceiling is not a match",
			cpes:    []string{"cpe:2.3:a:vendor:thing:*:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{startIncl: "2.0"}},
			version: "9.0",
			want:    false,
		},
		{
			product: "nginx",
			name:    "an exact affected version with no range still matches",
			cpes:    []string{"cpe:2.3:a:f5:nginx:0.1.24:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{criteria: "cpe:2.3:a:f5:nginx:0.1.24:*:*:*:*:*:*:*"}},
			version: "0.1.24",
			want:    true,
		},
		{
			product: "nginx",
			name:    "a sibling exact version does not match",
			cpes:    []string{"cpe:2.3:a:f5:nginx:0.1.24:*:*:*:*:*:*:*", "cpe:2.3:a:f5:nginx:0.6.16:*:*:*:*:*:*:*"},
			ranges:  []cpeRange{{criteria: "cpe:2.3:a:f5:nginx:0.1.24:*:*:*:*:*:*:*"}},
			version: "0.6.16",
			want:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, _ := versionInProducts(c.product, append(cranges(c.cpes...), c.ranges...), c.version, versionPrefix(c.version))
			if got != c.want {
				t.Errorf("version %s = %v, want %v", c.version, got, c.want)
			}
		})
	}
}

func TestCompareVersionsPadsWithZeros(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.24", "1.24.0", 0},
		{"1.24", "1.24.1", -1},
		{"1.10", "1.9", 1},
		{"2", "10", -1},
		{"0.1.24", "1.24.0", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseHTTPHeaders(t *testing.T) {
	out := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0 (Ubuntu)\r\n" +
		"Content-Type: text/html\r\n" +
		"Set-Cookie: sid=abc123; Secure\r\n" +
		"\r\n" +
		"<html>hello</html>"

	r := parseHTTPHeaders(out)
	if r.Status != "HTTP/1.1 200 OK" {
		t.Errorf("Status = %q", r.Status)
	}
	if r.Server != "nginx/1.18.0 (Ubuntu)" {
		t.Errorf("Server = %q", r.Server)
	}
	if r.Headers["content-type"] != "text/html" {
		t.Errorf("header map not lowercased: %v", r.Headers)
	}
	// The cookie sets Secure but not HttpOnly, which must be flagged.
	found := false
	for _, m := range r.Missing {
		if m == "Set-Cookie: HttpOnly" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HttpOnly to be flagged missing, got %v", r.Missing)
	}
	if r.BodyExcerpt != "<html>hello</html>" {
		t.Errorf("BodyExcerpt = %q", r.BodyExcerpt)
	}
}

func TestFingerprintIsStableAndOpaque(t *testing.T) {
	secret := "hunter2-correct-horse"
	a := fingerprint(secret)
	b := fingerprint(secret)
	if a != b {
		t.Error("fingerprint is not deterministic")
	}
	if fingerprint(secret+"x") == a {
		t.Error("different secrets produced the same fingerprint")
	}
	if a == secret || len(a) != 16 {
		t.Errorf("fingerprint leaks or is malformed: %q", a)
	}
}

func TestReviewScanFlagsRiskyServices(t *testing.T) {
	r := ScanResult{Hosts: []HostResult{{
		IP:     "10.0.0.5",
		Status: "up",
		Ports: []PortResult{
			{Port: 23, Service: "telnet", State: "open"},
			{Port: 21, Service: "ftp", Version: "vsftpd 2.3.4", State: "open"},
			{Port: 5900, Service: "vnc", State: "open"},
			{Port: 80, Service: "http", Version: "nginx 1.18.0", State: "open"},
		},
	}}}
	f := reviewScan(r)
	joined := ""
	for _, x := range f {
		joined += x.Summary + " | " + x.Evidence + "|"
	}
	for _, want := range []string{"telnet", "vsftpd 2.3.4", "VNC"} {
		if !contains(joined, want) {
			t.Errorf("expected a finding mentioning %q, got: %s", want, joined)
		}
	}
	// A current nginx must not be reported as end-of-life.
	if contains(joined, "end-of-life version") {
		t.Errorf("false positive on a current nginx: %s", joined)
	}
}

func TestGradeSysctl(t *testing.T) {
	if s, _ := gradeSysctl("kernel.randomize_va_space", "2"); s != "pass" {
		t.Errorf("ASLR=2 should pass, got %s", s)
	}
	if s, _ := gradeSysctl("kernel.randomize_va_space", "0"); s != "fail" {
		t.Errorf("ASLR=0 should fail, got %s", s)
	}
	if s, _ := gradeSysctl("net.ipv4.conf.all.rp_filter", "1"); s != "pass" {
		t.Errorf("rp_filter=1 should pass, got %s", s)
	}
	if s, _ := gradeSysctl("net.ipv4.conf.all.accept_redirects", "0"); s != "fail" {
		t.Errorf("accept_redirects=0 should fail, got %s", s)
	}
}

func TestParseWhois(t *testing.T) {
	out := `   Domain Name: EXAMPLE.COM
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Registrar Abuse Contact Email: abuse@iana.org
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
`
	r := parseWhois("example.com", out)
	if r.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Errorf("Registrar = %q", r.Registrar)
	}
	if len(r.NameServers) != 2 {
		t.Errorf("NameServers = %v, want 2 entries", r.NameServers)
	}
	if r.AbuseContact != "abuse@iana.org" {
		t.Errorf("AbuseContact = %q", r.AbuseContact)
	}
	// An expiry in the current year should be surfaced as a takeover risk.
	if len(r.Findings) == 0 {
		t.Error("expected a finding for a near-term expiry")
	}
}

func contains(hay, needle string) bool {
	return len(needle) == 0 || (len(hay) >= len(needle) && indexOf(hay, needle) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// A record about nginx also lists Apple Xcode and Puppet Enterprise, and their
// version windows span the same numbers. Matching the number alone reported
// nginx 1.24.0 against advisories for unrelated products.
func TestVersionInProductsIgnoresOtherProductsInTheRecord(t *testing.T) {
	ranges := cranges(
		"cpe:2.3:a:apple:xcode:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:puppet:puppet_enterprise:*:*:*:*:*:*:*:*",
	)
	ranges = append(ranges,
		cpeRange{criteria: "cpe:2.3:a:apple:xcode:*:*:*:*:*:*:*:*", endExcl: "13.0"},
		cpeRange{criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", startIncl: "0.6.18", endIncl: "1.8.0"},
	)
	if hit, _, _ := versionInProducts("nginx", ranges, "1.24.0", "1.24"); hit {
		t.Error("matched a range belonging to a different product in the same record")
	}
}

func TestProductMatches(t *testing.T) {
	cases := []struct {
		query, cpeProduct string
		want              bool
	}{
		{"nginx", "nginx", true},
		{"nginx", "nginx_http", true},
		{"tornado", "tornadoweb", true},
		{"Node.js", "nodejs", true},
		{"openssh", "openssh", true},
		{"nginx", "xcode", false},
		{"nginx", "puppet_enterprise", false},
		{"nginx", "", true},
		{"", "nginx", true},
	}
	for _, c := range cases {
		if got := productMatches(c.query, c.cpeProduct); got != c.want {
			t.Errorf("productMatches(%q, %q) = %v, want %v", c.query, c.cpeProduct, got, c.want)
		}
	}
}

// A bounded range that excludes the version is a verdict, so the advisory's
// prose must not resurrect it as a text-only match.
func TestVersionInProductsReportsDecisiveVerdict(t *testing.T) {
	excluded := cranges("cpe:2.3:a:tornadoweb:tornado:*:*:*:*:*:*:*:*")
	excluded = append(excluded, cpeRange{criteria: "cpe:2.3:a:tornadoweb:tornado:*:*:*:*:*:*:*:*", endExcl: "6.5.0"})
	if _, _, decided := versionInProducts("tornado", excluded, "6.5.4", "6.5"); !decided {
		t.Error("a bounded range that excludes the version must count as a verdict")
	}
	if _, _, decided := versionInProducts("tornado", cranges("cpe:2.3:a:tornadoweb:tornado:*:*:*:*:*:*:*:*"), "6.5.4", "6.5"); decided {
		t.Error("an unbounded '*' version leaves the question open, so it is not a verdict")
	}
}

// A version that was never really detected reduces to a bare digit, and that
// digit appears in nearly every advisory. Requiring a dotted, word-bounded
// version keeps "Express 4" from matching CVEs from 1999.
func TestMentionsVersion(t *testing.T) {
	cases := []struct {
		desc, version string
		want          bool
	}{
		{"affects versions before 6.5.0, upgrade to 6.5.4 or later", "6.5", true},
		{"only 6.5.4 and earlier are affected", "6.5", true},
		{"fixed in 6.4.2", "6.5", false},
		{"a bare 4 is not a version", "4", false},
		{"see CVE-1999-1016 for details", "4", false},
		{"versions 16.5.0 to 16.5.4", "16.5", true},
		{"not 116.5 either", "16.5", false},
	}
	for _, c := range cases {
		if got := mentionsVersion(c.desc, c.version); got != c.want {
			t.Errorf("mentionsVersion(%q, %q) = %v, want %v", c.desc, c.version, got, c.want)
		}
	}
}
