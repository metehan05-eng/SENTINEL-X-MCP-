package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sentinel-x/sentinel-x/internal/config"
	"github.com/sentinel-x/sentinel-x/internal/tools"
	"github.com/sentinel-x/sentinel-x/internal/utils"
)

func TestDoctorUnknownFlagIsRejected(t *testing.T) {
	if err := runDoctor([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestDoctorHelpIsAccepted(t *testing.T) {
	if err := runDoctor([]string{"--help"}); err != nil {
		t.Fatalf("help rejected: %v", err)
	}
}

// An empty scope does not mean "nothing is allowed", it means enforcement is
// off. If doctor ever describes it as refusing everything, an operator reads
// "safe" and points the server at someone else's infrastructure.
func TestDoctorReportsUnenforcedScopeAsUnenforced(t *testing.T) {
	t.Setenv("SENTINELX_SCOPE_TARGETS", "")
	var out strings.Builder
	withDoctorStdout(t, &out, func() {
		_ = runDoctor([]string{"--json"})
	})
	var r doctorReport
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, out.String())
	}
	if r.Enforced {
		t.Fatal("empty scope reported as enforced")
	}
	if !strings.Contains(out.String(), "SCOPE IS NOT ENFORCED") {
		t.Fatalf("no loud warning about unenforced scope:\n%s", out.String())
	}
	if strings.Contains(out.String(), "will be refused") {
		t.Fatalf("report claims an empty scope refuses targets:\n%s", out.String())
	}
}

func TestDoctorCoversEveryRegisteredTool(t *testing.T) {
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := utils.NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	all := tools.AllTools(tools.Deps{Cfg: cfg, Runner: runner})
	if len(all) == 0 {
		t.Fatal("no tools registered")
	}
	// Every tool that shells out must declare what it shells out to, otherwise
	// doctor reports it as ready and it fails on first use.
	for _, tl := range all {
		for _, name := range []string{"sentinelx_port_scan", "sentinelx_http_probe", "sentinelx_nuclei_scan", "sentinelx_whois_lookup"} {
			if tl.Tool.Name != name {
				continue
			}
			if len(tl.Requires) == 0 {
				t.Errorf("%s declares no binary requirement but shells out", name)
			}
		}
	}
}

func TestDoctorJSONIsMachineReadable(t *testing.T) {
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := utils.NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rep := buildDoctorReport(cfg, runner, tools.AllTools(tools.Deps{Cfg: cfg, Runner: runner}))
	if rep.ToolsTotal == 0 || rep.ToolsTotal != len(rep.Tools) {
		t.Fatalf("tool count disagrees with the tool list: %d vs %d", rep.ToolsTotal, len(rep.Tools))
	}
	// Counters that disagree with the list would let a caller that reads only
	// the counters see a healthy system.
	if rep.ToolsBroken != countBroken(rep.Tools) {
		t.Fatalf("broken count %d disagrees with the list (%d)", rep.ToolsBroken, countBroken(rep.Tools))
	}
	if rep.ToolsUsable+rep.ToolsDegraded+rep.ToolsBroken != rep.ToolsTotal {
		t.Fatalf("usable+degraded+broken (%d) does not add up to %d",
			rep.ToolsUsable+rep.ToolsDegraded+rep.ToolsBroken, rep.ToolsTotal)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("report does not serialise: %v", err)
	}
	var round doctorReport
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
}

// A configured scope must show up as enforced, since "not enforced" is the
// difference between a bounded run and an open one.
func TestDoctorEnforcedScopeIsReported(t *testing.T) {
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := utils.NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := *cfg
	c.Policy.ScopeTargets = []string{"example.com"}
	c.Policy.EnforceScope = true
	rep := buildDoctorReport(&c, runner, tools.AllTools(tools.Deps{Cfg: &c, Runner: runner}))
	if !rep.Enforced {
		t.Fatal("configured scope not reported as enforced")
	}
	for _, n := range rep.Notes {
		if strings.Contains(n, "SCOPE IS NOT ENFORCED") {
			t.Fatalf("enforced scope still warned as unenforced: %s", n)
		}
	}
}

func countBroken(ts []toolStatus) int {
	n := 0
	for _, s := range ts {
		if !s.Usable {
			n++
		}
	}
	return n
}

func withDoctorStdout(t *testing.T, sb *strings.Builder, fn func()) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b := make([]byte, 0, 1<<16)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	sb.WriteString(<-done)
	_ = r.Close()
}
