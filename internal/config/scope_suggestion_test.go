package config

import (
	"strings"
	"testing"
)

func TestNetworkAllowedAcceptsWhatTheScopeAlreadyCovers(t *testing.T) {
	cases := []struct {
		name    string
		scope   []string
		host    string
		private bool
	}{
		{name: "exact host", scope: []string{"example.com"}, host: "example.com"},
		{name: "wildcard covers its own apex", scope: []string{"*.example.com"}, host: "example.com"},
		{name: "wildcard covers a subdomain", scope: []string{"*.example.com"}, host: "www.example.com"},
		{name: "single label covers everything beneath it", scope: []string{"corp"}, host: "a.b.corp"},
		{name: "cidr covers an address inside it", scope: []string{"10.0.0.0/8"}, host: "10.1.2.3", private: true},
		{name: "single address", scope: []string{"203.0.113.5"}, host: "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Policy: Policy{EnforceScope: true, ScopeTargets: tc.scope, AllowPrivateNetworks: tc.private}}
			allowed, why := c.NetworkAllowed(tc.host)
			if !allowed {
				t.Errorf("%s should be allowed by %v, got refusal: %s", tc.host, tc.scope, why)
			}
		})
	}
}

// A refusal that does not say what to do about it is a dead end, and the caller
// is usually a model that has just discovered the host and cannot widen scope
// itself.
func TestNetworkAllowedRefusalNamesTheEntryThatWouldAllowIt(t *testing.T) {
	cases := []struct {
		name  string
		scope []string
		host  string
		want  string
	}{
		{"subdomain of an exactly scoped apex", []string{"example.com"}, "www.example.com", `add "*.example.com"`},
		{"deep subdomain widens the entry the operator chose", []string{"corp.example"}, "api.dev.corp.example", `add "*.corp.example"`},
		{"third level with no related entry", []string{"other.test"}, "a.b.example", `add "*.b.example"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Policy: Policy{EnforceScope: true, ScopeTargets: tc.scope}}
			allowed, why := c.NetworkAllowed(tc.host)
			if allowed {
				t.Fatalf("%s should be refused by %v", tc.host, tc.scope)
			}
			if !strings.Contains(why, tc.want) {
				t.Errorf("refusal %q does not suggest %s", why, tc.want)
			}
		})
	}
}

func TestNetworkAllowedRefusalInventsNoSuggestion(t *testing.T) {
	cases := []struct {
		name  string
		scope []string
		host  string
	}{
		// An IP is not a hierarchy; offering "*.0.113.5" would be nonsense.
		{"ip address", []string{"example.com"}, "203.0.113.5"},
		{"unrelated domain", []string{"example.com"}, "unrelated.test"},
		{"cidr does not cover this address", []string{"10.0.0.0/8"}, "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Policy: Policy{EnforceScope: true, ScopeTargets: tc.scope}}
			allowed, why := c.NetworkAllowed(tc.host)
			if allowed {
				t.Fatalf("%s should be refused by %v", tc.host, tc.scope)
			}
			if strings.Contains(why, "SENTINELX_SCOPE_TARGETS to assess it") {
				t.Errorf("refusal offered a meaningless suggestion: %s", why)
			}
		})
	}
}
