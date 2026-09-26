package tools

import "testing"

// A scan that returned nothing must not be reported as a clean endpoint. This
// is the same class of bug as dig rejecting an unsupported option: an operation
// that failed and an operation that legitimately found nothing produced
// identical output.
func TestParseTLSEmptyScanIsNotAConfiguration(t *testing.T) {
	if got := parseTLS("", "443"); len(got.Certs)+len(got.CipherSuites)+len(got.Protocols) != 0 {
		t.Fatalf("empty output should parse to nothing, got %+v", got)
	}
	if findings := reviewTLS(parseTLS("", "443")); len(findings) != 0 {
		t.Errorf("an unrun scan must not produce findings, got %+v", findings)
	}
}

func TestDescribeUnparsedScanNamesTheCause(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"closed port", "443/tcp closed  https", "the port reported closed"},
		{"filtered port", "443/tcp filtered  https", "the port reported filtered"},
		{"handshake refused", "SSL handshake failed: no supported cipher", "the TLS handshake failed"},
		{"host down", "Note: Host seems down.", "the host did not answer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeUnparsedScan(tc.out, nil)
			if got != tc.want {
				t.Errorf("describeUnparsedScan = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDescribeUnparsedScanFallsBackWhenNmapSaysNothingUseful(t *testing.T) {
	// A port that is open but does not speak TLS leaves no script output and no
	// conclusive marker, so the explanation has to be generic but present.
	if got := describeUnparsedScan("Nmap done: 1 IP address scanned", nil); got != "nmap reported no open TLS service" {
		t.Errorf("fallback = %q", got)
	}
}
