package config

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestDefaultConfigIsSelfConsistent(t *testing.T) {
	c, err := Get()
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	// Every allowed binary that is also denied would be permanently
	// unreachable, which is a configuration bug rather than a policy.
	denied := map[string]bool{}
	for _, d := range c.Policy.DeniedBinaries {
		denied[d] = true
	}
	for _, a := range c.Policy.AllowedBinaries {
		if denied[a] {
			t.Errorf("binary %q is both allowed and denied", a)
		}
	}
	if c.Policy.MaxOutputBytes <= 0 {
		t.Error("MaxOutputBytes must be positive")
	}
	if c.Policy.MaxConcurrency <= 0 {
		t.Error("MaxConcurrency must be positive")
	}
	// No module timeout may exceed the global ceiling, or a caller could
	// select a module that outlives the hard cap.
	for name, d := range map[string]time.Duration{
		"recon": c.Timeouts.Recon, "scan": c.Timeouts.Scan,
		"vuln": c.Timeouts.VulnQuery, "audit": c.Timeouts.Audit,
		"http": c.Timeouts.HTTP,
	} {
		if d > c.Timeouts.Max {
			t.Errorf("timeout %s (%s) exceeds the global cap %s", name, d, c.Timeouts.Max)
		}
	}
}

func TestNetworkAllowed(t *testing.T) {
	c := &Config{Policy: Policy{AllowPrivateNetworks: true}}

	if ok, why := c.NetworkAllowed("example.com"); !ok {
		t.Errorf("a public hostname should be allowed: %s", why)
	}
	if ok, _ := c.NetworkAllowed("10.0.0.1"); !ok {
		t.Error("a private address should be allowed when AllowPrivateNetworks is set")
	}
	if ok, _ := c.NetworkAllowed(""); ok {
		t.Error("an empty host must be refused")
	}
	if ok, _ := c.NetworkAllowed("bad host"); ok {
		t.Error("a malformed hostname must be refused")
	}
	if ok, _ := c.NetworkAllowed("-oN"); ok {
		t.Error("a flag-like string must not pass as a hostname")
	}

	// With private networks disabled, internal targets must be refused.
	strict := &Config{Policy: Policy{AllowPrivateNetworks: false}}
	if ok, _ := strict.NetworkAllowed("192.168.1.1"); ok {
		t.Error("a private address should be refused when AllowPrivateNetworks is false")
	}
	if ok, _ := strict.NetworkAllowed("127.0.0.1"); ok {
		t.Error("loopback should be refused when AllowPrivateNetworks is false")
	}
	if ok, why := strict.NetworkAllowed("93.184.216.34"); !ok {
		t.Errorf("a public address must still be allowed: %s", why)
	}
}

func TestNetworkAllowedWithScope(t *testing.T) {
	c := &Config{Policy: Policy{
		AllowPrivateNetworks: true,
		EnforceScope:         true,
		ScopeTargets:         []string{"example.com", "*.corp.example", "10.0.0.0/8", "lab"},
	}}

	allowed := []string{"example.com", "api.corp.example", "deep.nested.corp.example", "10.1.2.3", "build.lab", "10.255.255.254"}
	for _, h := range allowed {
		if ok, why := c.NetworkAllowed(h); !ok {
			t.Errorf("%s should be in scope: %s", h, why)
		}
	}
	refused := []string{"evil.com", "example.com.evil.net", "example.org", "11.0.0.1", "lab.example.com"}
	for _, h := range refused {
		if ok, _ := c.NetworkAllowed(h); ok {
			t.Errorf("%s should be out of scope", h)
		}
	}
}

func TestAuditPathAllowed(t *testing.T) {
	c := &Config{}
	if ok, _ := c.AuditPathAllowed("/etc/passwd"); !ok {
		t.Error("/etc/passwd should be inside the default audit roots")
	}
	// Traversal must be resolved before the check, not after.
	if ok, _ := c.AuditPathAllowed("/etc/passwd/../../root/.ssh/id_rsa"); ok {
		t.Error("a traversal out of /etc must be refused")
	}
	if ok, _ := c.AuditPathAllowed("/etc/../etc/shadow"); !ok {
		t.Error("a traversal that stays inside /etc should be allowed")
	}
	if ok, _ := c.AuditPathAllowed("/root/.ssh/id_rsa"); ok {
		t.Error("/root must not be readable under the default roots")
	}
	if ok, _ := c.AuditPathAllowed(""); ok {
		t.Error("an empty path must be refused")
	}

	widened := &Config{AuditRoots: []string{"/srv"}}
	if ok, _ := widened.AuditPathAllowed("/srv/app/config.yml"); !ok {
		t.Error("an explicitly configured root should be honoured")
	}
	if ok, _ := widened.AuditPathAllowed("/etc/passwd"); ok {
		t.Error("configuring roots must replace, not extend, the defaults")
	}
}

func TestEnvOverridesAreValidated(t *testing.T) {
	// A malformed duration must be reported, not silently defaulted: a typo in
	// a timeout is exactly the kind of thing an operator needs to see.
	t.Setenv("SENTINELX_TIMEOUT_SCAN", "not-a-duration")
	reset()
	if _, err := Get(); err == nil {
		t.Error("an invalid SENTINELX_TIMEOUT_SCAN should produce an error")
	}

	t.Setenv("SENTINELX_TIMEOUT_SCAN", "90s")
	reset()
	c, err := Get()
	if err != nil {
		t.Fatalf("valid duration rejected: %v", err)
	}
	if c.Timeouts.Scan != 90*time.Second {
		t.Errorf("Scan timeout = %s, want 90s", c.Timeouts.Scan)
	}

	// A module timeout may be shortened but never raised above the cap.
	t.Setenv("SENTINELX_TIMEOUT_MAX", "10s")
	t.Setenv("SENTINELX_TIMEOUT_SCAN", "600s")
	reset()
	c, err = Get()
	if err != nil {
		t.Fatalf("valid duration rejected: %v", err)
	}
	if c.Timeouts.Scan > c.Timeouts.Max {
		t.Errorf("Scan (%s) exceeded the cap (%s) after override", c.Timeouts.Scan, c.Timeouts.Max)
	}

	// Setting a scope must switch enforcement on automatically.
	t.Setenv("SENTINELX_SCOPE_TARGETS", "example.com, 10.0.0.0/8")
	reset()
	c, err = Get()
	if err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	if !c.Policy.EnforceScope || len(c.Policy.ScopeTargets) != 2 {
		t.Errorf("scope was not applied: enforce=%v targets=%v", c.Policy.EnforceScope, c.Policy.ScopeTargets)
	}
}

// reset clears the package-level load cache so a test can re-read the
// environment. The production code loads configuration exactly once.
func reset() {
	loadOnce = sync.Once{}
	loaded = nil
	loadErr = nil
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
