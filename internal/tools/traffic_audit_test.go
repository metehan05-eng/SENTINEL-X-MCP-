package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The kernel writes IPv4 in host byte order inside one 32-bit word, so the
// bytes have to be reversed. Getting this backwards yields 127.0.0.1 for every
// address on the box, which would make every finding wrong in a way that still
// looks plausible.
func TestDecodeHexAddrIPv4(t *testing.T) {
	cases := []struct {
		in, ip string
		port   int
	}{
		{"0100007F:1F90", "127.0.0.1", 8080},
		{"00000000:0016", "0.0.0.0", 22},
		{"0A000005:0050", "5.0.0.10", 80},
		{"FFFFFFFF:1F90", "255.255.255.255", 8080},
	}
	for _, c := range cases {
		ip, port, ok := decodeHexAddr(c.in)
		if !ok {
			t.Errorf("%s did not parse", c.in)
			continue
		}
		if ip != c.ip || port != c.port {
			t.Errorf("%s -> %s:%d, want %s:%d", c.in, ip, port, c.ip, c.port)
		}
	}
}

func TestDecodeHexAddrIPv6(t *testing.T) {
	// ::1 in the kernel's four little-endian words.
	ip, port, ok := decodeHexAddr("00000000000000000000000001000000:1F90")
	if !ok {
		t.Fatal("did not parse")
	}
	if ip != "::1" {
		t.Errorf("got %q, want ::1", ip)
	}
	if port != 8080 {
		t.Errorf("port %d", port)
	}
}

func TestDecodeHexAddrRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "nocolon", "ZZZZ:0016", "0100007F:", ":1F90",
		"0100007F:ZZZZ", "0100:1F90"} {
		if _, _, ok := decodeHexAddr(in); ok {
			t.Errorf("%q parsed; a malformed row must be skipped, not guessed at", in)
		}
	}
}

func TestParseProcNetSkipsMalformedRows(t *testing.T) {
	// One bad row in the middle must not cost the rows around it.
	body := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000 100 0 0 10 0
this line is garbage and has no columns at all
   1: 0200007F:0277 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000 100 0 0 10 0
   2: badrow
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := parseProcNet(path, "tcp", map[string]socketOwner{}, false)
	if len(got) != 2 {
		t.Fatalf("parsed %d sockets, want 2", len(got))
	}
	if got[0].Established {
		t.Error("state 0A (LISTEN) was parsed as an established connection")
	}
	if got[0].Listener.Port != 8080 {
		t.Errorf("listener port %d", got[0].Listener.Port)
	}
	if !got[1].Established {
		t.Error("state 01 should be established")
	}
}

func TestParseProcNetMissingFileIsEmptyNotFatal(t *testing.T) {
	// A container with /proc/net masked must not take the whole tool down.
	if got := parseProcNet(filepath.Join(t.TempDir(), "nope"), "tcp", nil, false); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestParseProcNetResolvesOwner(t *testing.T) {
	body := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000 100 0 0 10 0
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	owners := map[string]socketOwner{"4242": {Name: "sshd", PID: 812}}
	got := parseProcNet(path, "tcp", owners, true)
	if len(got) != 1 {
		t.Fatalf("parsed %d", len(got))
	}
	if got[0].Listener.Process != "sshd" || got[0].Listener.PID != 812 {
		t.Errorf("owner not resolved: %+v", got[0].Listener)
	}
}

func TestWildcardBindDetection(t *testing.T) {
	if !isWildcard("0.0.0.0") || !isWildcard("::") {
		t.Error("wildcard not detected")
	}
	if isWildcard("127.0.0.1") || isWildcard("10.0.0.5") {
		t.Error("a bound address was called a wildcard")
	}
}

func TestExposureFindings(t *testing.T) {
	listen := []ListenSocket{
		{Port: 6379, Proto: "tcp", Local: "0.0.0.0", Wildcard: true, Exposed: true,
			Sensitive: true, Process: "redis-server"},
		// The same port bound to loopback is fine.
		{Port: 6379, Proto: "tcp", Local: "127.0.0.1", Wildcard: false, Exposed: false,
			Sensitive: true, Process: "redis-server"},
		{Port: 22, Proto: "tcp", Local: "0.0.0.0", Wildcard: true, Exposed: true, Process: "sshd"},
	}
	got := exposureFindings(listen)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: a loopback-bound service is not exposed", len(got))
	}
	if !strings.Contains(got[0].Summary, "redis") {
		t.Errorf("finding does not name the service: %q", got[0].Summary)
	}
	if !strings.Contains(got[0].Evidence, "6379") {
		t.Errorf("finding carries no evidence: %q", got[0].Evidence)
	}
}

func TestPlaintextFindingsDedupe(t *testing.T) {
	peers := []RemotePeer{
		{Remote: "1.2.3.4", Port: 21, Plaintext: true, Note: "FTP sends credentials in the clear", Process: "ftp"},
		{Remote: "1.2.3.4", Port: 21, Plaintext: true, Note: "FTP sends credentials in the clear", Process: "ftp"},
		{Remote: "5.6.7.8", Port: 443},
	}
	got := plaintextFindings(nil, peers)
	if len(got) != 1 {
		t.Fatalf("got %d findings; the same peer should collapse to one", len(got))
	}
	if got[0].Severity == "" || got[0].Remediate == "" {
		t.Errorf("incomplete finding: %+v", got[0])
	}
}

func TestHexToIPv4(t *testing.T) {
	if got := hexToIPv4("0101A8C0"); got != "192.168.1.1" {
		t.Errorf("got %q", got)
	}
	if got := hexToIPv4("nope"); got != "" {
		t.Errorf("garbage returned %q", got)
	}
}

func TestParseProcRouteSkipsHeader(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "route")
	body := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t000000FF\n" +
		"\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := parseProcRouteFrom(p)
	if len(got) != 1 {
		t.Fatalf("got %d routes, want 1", len(got))
	}
	if got[0].Destination != "192.168.1.0" || got[0].Interface != "eth0" {
		t.Errorf("wrong route: %+v", got[0])
	}
}
