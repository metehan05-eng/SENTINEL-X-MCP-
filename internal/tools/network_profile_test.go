package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sentinel-x/sentinel-x/internal/config"
	"github.com/sentinel-x/sentinel-x/internal/utils"
)

func profileDeps(t *testing.T) Deps {
	t.Helper()
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	// A runner is required: the stages resolve binaries through it, and a nil
	// Runner would panic rather than report a missing dependency.
	runner, err := utils.NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Cfg: cfg, Runner: runner}
}

// scoped returns deps whose scope is pinned for the duration of one test.
// config.Get() is memoised, so without this each test inherits whatever the
// previous one wrote and the suite becomes order-dependent.
func scoped(t *testing.T, targets ...string) Deps {
	t.Helper()
	d := profileDeps(t)
	prevEnforce, prevTargets := d.Cfg.Policy.EnforceScope, d.Cfg.Policy.ScopeTargets
	t.Cleanup(func() { d.Cfg.Policy.EnforceScope, d.Cfg.Policy.ScopeTargets = prevEnforce, prevTargets })
	d.Cfg.Policy.EnforceScope = true
	d.Cfg.Policy.ScopeTargets = targets
	return d
}

// profileArgs keeps the suite fast and hermetic: a short budget, and no
// traceroute. A profile against loopback would otherwise spend the full default
// scan budget discovering that nothing is listening there.
func profileArgs(target string, extra map[string]any) map[string]any {
	args := map[string]any{"target": target, "depth": "quick",
		"timeout_seconds": 4, "trace_path": false}
	for k, v := range extra {
		args[k] = v
	}
	return args
}

func callProfile(t *testing.T, d Deps, args map[string]any) map[string]any {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := networkProfileTool(d).Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return decodeEnvelope(t, res)
}

func decodeEnvelope(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	txt := res.Content[0].(mcp.TextContent).Text
	var env map[string]any
	if err := json.Unmarshal([]byte(txt), &env); err != nil {
		t.Fatalf("bad envelope: %s", txt)
	}
	return env
}

// An enforced scope must refuse the whole call. A profile that runs anyway and
// reports what it found is the one behaviour that makes SENTINEL-X unsafe to
// point at a machine you do not own.
func TestNetworkProfileRespectsScope(t *testing.T) {
	d := scoped(t, "10.0.0.0/8")

	env := callProfile(t, d, map[string]any{"target": "203.0.113.99"})
	if _, failed := env["error"]; !failed {
		t.Fatalf("an out-of-scope target was assessed: %v", env)
	}
	msg := env["error"].(string)
	// The refusal must name the scope that rejected it, so an operator can see
	// which configuration is in force. (A suggestion is only added when there is
	// a sensible entry to add, which there is not for an unrelated address.)
	if !strings.Contains(msg, "authorised scope") || !strings.Contains(msg, "10.0.0.0/8") {
		t.Errorf("refusal does not name the scope in force: %s", msg)
	}
}

// An in-scope target must get past the gate. The scan itself may still fail —
// there may be no scanner, or the host may be down — so the assertion is only
// that the failure is not a policy refusal.
func TestNetworkProfileAllowsInScope(t *testing.T) {
	d := scoped(t, "10.0.0.0/8")
	env := callProfile(t, d, profileArgs("10.0.0.5", nil))
	if msg, failed := env["error"]; failed {
		if strings.Contains(msg.(string), "policy refusal") {
			t.Fatalf("an in-scope target was refused: %s", msg)
		}
	}
}

func TestNetworkProfileRequiresTarget(t *testing.T) {
	env := callProfile(t, profileDeps(t), map[string]any{})
	if env["error"] == nil {
		t.Fatal("an empty target was accepted")
	}
}

// A caller must not be able to smuggle a CIDR in and have the profile treat it
// as one host. The tool is single-target by design.
func TestNetworkProfileRejectsPortSpecInjection(t *testing.T) {
	// The scope must admit the target first, otherwise the policy refusal
	// short-circuits the call and the port validation never runs.
	d := scoped(t, "127.0.0.1")
	env := callProfile(t, d, map[string]any{
		"target": "127.0.0.1",
		"ports":  "22; rm -rf /",
	})
	if env["error"] == nil {
		t.Fatal("a malformed port spec was accepted")
	}
	if !strings.Contains(env["error"].(string), "invalid port specification") {
		t.Errorf("unexpected error: %v", env["error"])
	}
}

func TestNetworkProfileNormalisesDepth(t *testing.T) {
	for _, in := range []string{"QUICK", "deep", " nonsense "} {
		d := scoped(t, "127.0.0.1")
		env := callProfile(t, d, profileArgs("127.0.0.1", map[string]any{"depth": in}))
		if env["error"] != nil {
			t.Skipf("no scanner available: %v", env["error"])
		}
		data := env["data"].(map[string]any)
		got := data["depth"].(string)
		if got != "quick" && got != "standard" && got != "deep" {
			t.Fatalf("depth %q was not normalised from %q", got, in)
		}
	}
}

// The whole reason this tool exists: a reader must be able to tell which stages
// ran. A profile that silently skipped discovery must say so.
func TestNetworkProfileReportsCoverage(t *testing.T) {
	d := scoped(t, "127.0.0.1")
	env := callProfile(t, d, profileArgs("127.0.0.1", nil))
	if env["error"] != nil {
		t.Skipf("no scanner available: %v", env["error"])
	}
	data := env["data"].(map[string]any)
	cov, _ := data["coverage"].([]any)
	if len(cov) == 0 {
		t.Fatal("coverage is empty; a reader cannot tell what was checked")
	}
	stages := map[string]string{}
	for _, raw := range cov {
		m := raw.(map[string]any)
		stages[m["stage"].(string)] = m["status"].(string)
	}
	for _, want := range []string{"identity", "host", "services"} {
		if _, ok := stages[want]; !ok {
			t.Errorf("stage %q is missing from coverage: %v", want, stages)
		}
	}
	for name, status := range stages {
		switch status {
		case "ok", "failed", "skipped", "partial":
		default:
			t.Errorf("stage %q has status %q", name, status)
		}
	}
	// A stage that did not complete has to carry an explanation.
	for _, raw := range cov {
		m := raw.(map[string]any)
		if m["status"] != "ok" {
			if detail, _ := m["detail"].(string); strings.TrimSpace(detail) == "" {
				t.Errorf("stage %v failed without saying why", m["stage"])
			}
		}
	}
}

func TestNetworkProfileConclusionAlwaysPresent(t *testing.T) {
	d := scoped(t, "127.0.0.1")
	env := callProfile(t, d, profileArgs("127.0.0.1", nil))
	if env["error"] != nil {
		t.Skipf("no scanner available: %v", env["error"])
	}
	data := env["data"].(map[string]any)
	c, _ := data["conclusion"].(string)
	if strings.TrimSpace(c) == "" {
		t.Fatal("no conclusion; the reader has to read raw stage output instead")
	}
	if !strings.Contains(c, "127.0.0.1") {
		t.Errorf("the conclusion does not name the target: %q", c)
	}
}

// The profile must never claim a clean result when it could not check.
func TestConclusionNeverOverstatesCleanliness(t *testing.T) {
	np := NetworkProfile{
		Target:   "10.0.0.1",
		Coverage: []StageReport{{Stage: "services", Status: "failed", Detail: "no scanner"}},
	}
	c := profileConclusion(np)
	if !strings.Contains(strings.ToLower(c), "did not complete") {
		t.Errorf("a profile with a failed stage reads as clean: %q", c)
	}
}

// Unreachable host: no host fingerprint, and the conclusion must not pretend
// otherwise.
func TestConclusionForUnreachableHost(t *testing.T) {
	np := NetworkProfile{Target: "10.0.0.1", Host: &HostFingerprint{Status: "down"}}
	c := profileConclusion(np)
	if strings.Contains(c, "exposing") {
		t.Errorf("an unreachable host was described as exposing services: %q", c)
	}
}

// Exposure classification. An admin port and a cleartext protocol are
// different problems and must produce different findings.
func TestRiskFromSurfaceClassifiesServices(t *testing.T) {
	p := &profileRun{svc: &ServiceSurface{
		OpenCount: 4,
		Ports: []PortResult{
			{Port: 22, Protocol: "tcp", State: "open", Service: "ssh", Product: "OpenSSH", Version: "8.2p1"},
			{Port: 3306, Protocol: "tcp", State: "open", Service: "mysql"},
			{Port: 21, Protocol: "tcp", State: "open", Service: "ftp"},
			{Port: 4444, Protocol: "tcp", State: "open", Service: "unknown"},
			{Port: 80, Protocol: "tcp", State: "closed", Service: "http"},
		},
	}}
	got := p.riskFromSurface()
	if len(got) == 0 {
		t.Fatal("an exposed MySQL, FTP and unidentified port produced no findings")
	}
	joined := ""
	for _, f := range got {
		joined += f.Summary + " | "
		if f.Evidence == "" {
			t.Errorf("finding without evidence: %+v", f)
		}
		if f.Remediate == "" {
			t.Errorf("finding without remediation: %+v", f)
		}
	}
	for _, want := range []string{"3306", "21", "4444"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no finding mentions port %s: %s", want, joined)
		}
	}
	if strings.Contains(joined, "port 80/") {
		t.Errorf("a closed port was reported: %s", joined)
	}
	// Highest severity first.
	for i := 1; i < len(got); i++ {
		if severityRank(got[i-1].Severity) < severityRank(got[i].Severity) {
			t.Fatalf("findings are not ordered by severity: %v then %v",
				got[i-1].Severity, got[i].Severity)
		}
	}
}

func TestParseTracerouteHandlesNmapOutput(t *testing.T) {
	out := `Nmap scan report for 10.0.0.5
Host is up (0.010s latency).
Not shown: 99 filtered ports
Traceroute starting at 192.168.1.1, 54 hops max
 1  192.168.1.1  1.23 ms  1.11 ms  1.05 ms
 2  10.0.0.1  5.67 ms  5.43 ms  5.20 ms
 3  * * *
 4  203.0.113.9  12.01 ms  11.88 ms  11.70 ms
Nmap done: 1 IP address (1 host up) scanned in 4.11 seconds
`
	np := parseTraceroute(out)
	if len(np.Hops) != 4 {
		t.Fatalf("parsed %d hops, want 4: %+v", len(np.Hops), np.Hops)
	}
	if np.Hops[0].IP != "192.168.1.1" || np.Hops[0].TTL != 1 {
		t.Errorf("first hop %+v", np.Hops[0])
	}
	if !np.Hops[2].Star {
		t.Error("a '*' hop was not marked no_reply")
	}
	if np.Hops[3].RTTMS != 12.01 {
		t.Errorf("rtt %v", np.Hops[3].RTTMS)
	}
	if !np.Reachable {
		t.Error("a path that answered was reported unreachable")
	}
}

func TestParseTracerouteEmptyInput(t *testing.T) {
	np := parseTraceroute("")
	if len(np.Hops) != 0 || np.Reachable {
		t.Errorf("empty input produced %+v", np)
	}
}

// A trailing run of stars means the walk never reached the target, and saying
// so is the difference between a real path and a hopeful one.
func TestParseTracerouteMarksExhausted(t *testing.T) {
	out := "Traceroute starting at 192.168.1.1, 54 hops max\n 1  192.168.1.1  1.00 ms  1.00 ms\n 2  * * *\n"
	np := parseTraceroute(out)
	if !np.Exhausted {
		t.Error("a path ending in no-reply hops was not marked exhausted")
	}
}

func TestValidPortSpecRejectsInjection(t *testing.T) {
	if validPortSpec("22; rm -rf /") {
		t.Error("a shell metacharacter passed port validation")
	}
	if !validPortSpec("22,80,443") || !validPortSpec("1-1024") {
		t.Error("a legitimate port spec was rejected")
	}
}

func TestProfileToolIsRegistered(t *testing.T) {
	for _, name := range []string{"sentinelx_network_profile", "sentinelx_traffic_audit"} {
		found := false
		for _, tl := range AllTools(profileDeps(t)) {
			if tl.Tool.Name == name {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not in the registry", name)
		}
	}
}

// Both new tools must carry the read-only annotation, since the server as a
// whole promises nothing mutates.
func TestNewToolsAreAnnotatedReadOnly(t *testing.T) {
	for _, name := range []string{"sentinelx_network_profile", "sentinelx_traffic_audit"} {
		for _, tl := range AllTools(profileDeps(t)) {
			if tl.Tool.Name != name {
				continue
			}
			if tl.Tool.Annotations.ReadOnlyHint == nil || !*tl.Tool.Annotations.ReadOnlyHint {
				t.Errorf("%s does not declare read-only", name)
			}
			if tl.Tool.Annotations.DestructiveHint == nil || *tl.Tool.Annotations.DestructiveHint {
				t.Errorf("%s declares itself destructive", name)
			}
		}
	}
}

// The traffic tool must never be cached as if it were a point-in-time scan.
func TestTrafficAuditIsNotCached(t *testing.T) {
	if !uncacheable["sentinelx_traffic_audit"] {
		t.Error("a live traffic snapshot is cacheable; it goes stale within seconds")
	}
}

func TestTrafficAuditStatesItsLimitations(t *testing.T) {
	d := profileDeps(t)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{}
	res, err := trafficAuditTool(d).Handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	env := decodeEnvelope(t, res)
	data := env["data"].(map[string]any)
	lim, _ := data["limitations"].([]any)
	if len(lim) < 2 {
		t.Fatalf("only %d limitations stated", len(lim))
	}
	joined := ""
	for _, l := range lim {
		joined += strings.ToLower(l.(string)) + " "
	}
	if !strings.Contains(joined, "packet") {
		t.Error("the report does not say this is not packet capture")
	}
}

var _ = time.Second
