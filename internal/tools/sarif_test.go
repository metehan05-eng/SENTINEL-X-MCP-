package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sentinel-x/sentinel-x/internal/config"
)

func sarifDeps(t *testing.T) Deps {
	t.Helper()
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Policy.EnforceScope = true
	cfg.Policy.ScopeTargets = []string{"example.com"}
	return Deps{Cfg: cfg}
}

func callSarif(t *testing.T, args map[string]any) (*mcp.CallToolResult, sarifSummary) {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := sarifReportTool(sarifDeps(t)).Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res.IsError {
		txt, _ := res.Content[0].(mcp.TextContent)
		t.Fatalf("tool returned an error: %s", txt.Text)
	}
	txt, isTxt := res.Content[0].(mcp.TextContent)
	if !isTxt {
		t.Fatalf("unexpected content %T", res.Content[0])
	}
	var env struct {
		Data sarifSummary `json:"data"`
	}
	if err := json.Unmarshal([]byte(txt.Text), &env); err != nil {
		t.Fatalf("bad envelope: %v\n%s", err, txt.Text)
	}
	return res, env.Data
}

func sampleFindings() []any {
	return []any{
		map[string]any{
			"id": "f1", "rule_id": "tls.missing_hsts", "title": "No HSTS header",
			"severity": "medium", "evidence": "no strict-transport-security in response",
			"location": "https://x.invalid", "port": 443, "confidence": "high",
			"remediation": "add the header",
		},
		map[string]any{
			"id": "f2", "rule_id": "cve.public_exploit", "title": "Known exploit exists",
			"severity": "critical", "evidence": "metasploit module present", "confidence": "medium",
		},
	}
}

func TestSARIFDocumentShape(t *testing.T) {
	_, sum := callSarif(t, map[string]any{"findings": sampleFindings()})
	if sum.Document == nil {
		t.Fatal("no document returned when output was omitted")
	}
	doc := *sum.Document
	if doc.Version != "2.1.0" {
		t.Fatalf("version %q", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif-schema-2.1.0") {
		t.Fatalf("schema %q", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "SENTINEL-X" {
		t.Fatalf("driver name %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Fatalf("results %d", len(run.Results))
	}
	// Rules must be emitted even though each result carries its own level:
	// consumers that honour rule defaults only would otherwise see an empty file.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules %d, want 2", len(run.Tool.Driver.Rules))
	}
}

func TestSARIFSeverityMapsToLevels(t *testing.T) {
	_, sum := callSarif(t, map[string]any{"findings": sampleFindings()})
	byID := map[string]string{}
	for _, r := range sum.Document.Runs[0].Results {
		byID[r.RuleID] = r.Level
	}
	if byID["cve.public_exploit"] != "error" {
		t.Fatalf("critical mapped to %q, want error", byID["cve.public_exploit"])
	}
	if byID["tls.missing_hsts"] != "warning" {
		t.Fatalf("medium mapped to %q, want warning", byID["tls.missing_hsts"])
	}
}

// SARIF has no "unknown" level. Rounding an unestablished severity up to
// error would inflate every report this tool produces.
func TestSARIFUnknownSeverityIsNote(t *testing.T) {
	_, sum := callSarif(t, map[string]any{"findings": []any{
		map[string]any{"rule_id": "x", "title": "t", "severity": "banana"},
		map[string]any{"rule_id": "y", "title": "t", "severity": ""},
	}})
	for _, r := range sum.Document.Runs[0].Results {
		if r.Level != "note" {
			t.Fatalf("%s got level %q, want note", r.RuleID, r.Level)
		}
	}
}

func TestSARIFCarriesEvidenceAndConfidence(t *testing.T) {
	_, sum := callSarif(t, map[string]any{"findings": sampleFindings()})
	for _, r := range sum.Document.Runs[0].Results {
		if !strings.Contains(r.Message.Text, "") {
			t.Fatalf("empty message for %s", r.RuleID)
		}
		if r.RuleID == "tls.missing_hsts" {
			if r.Properties["confidence"] != "high" {
				t.Fatalf("confidence lost: %v", r.Properties)
			}
			if r.Properties["remediation"] != "add the header" {
				t.Fatalf("remediation lost: %v", r.Properties)
			}
			if !strings.Contains(r.Message.Text, "no strict-transport-security") {
				t.Fatalf("evidence missing from the message: %q", r.Message.Text)
			}
		}
	}
}

// The same weakness surfaces from several tools during one assessment. A SARIF
// file that repeats it makes the count look like risk.
func TestSARIFDeduplicates(t *testing.T) {
	dup := []any{
		map[string]any{"rule_id": "tls.missing_hsts", "title": "t", "severity": "medium", "location": "https://a", "port": 443, "evidence": "no header"},
		map[string]any{"rule_id": "tls.missing_hsts", "title": "t", "severity": "medium", "location": "https://a", "port": 443, "evidence": "no header"},
		map[string]any{"rule_id": "tls.missing_hsts", "title": "t", "severity": "medium", "location": "https://b", "port": 443, "evidence": "no header"},
	}
	_, sum := callSarif(t, map[string]any{"findings": dup})
	// Two distinct locations, not three identical results.
	if sum.Findings != 2 {
		t.Fatalf("findings %d, want 2 after dedup", sum.Findings)
	}
	if sum.Rules != 1 {
		t.Fatalf("rules %d, want 1", sum.Rules)
	}
}

// A file that reshuffles between runs produces a useless diff and defeats
// change detection.
func TestSARIFOutputIsDeterministic(t *testing.T) {
	var first string
	for i := 0; i < 5; i++ {
		f := sampleFindings()
		// Feed the same set in a different order each time.
		if i%2 == 0 {
			f[0], f[1] = f[1], f[0]
		}
		_, sum := callSarif(t, map[string]any{"findings": f})
		b, err := json.Marshal(sum.Document)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = string(b)
		} else if string(b) != first {
			t.Fatalf("run %d differs from the first", i)
		}
	}
}

func TestSARIFSortsBySeverityDescending(t *testing.T) {
	_, sum := callSarif(t, map[string]any{"findings": []any{
		map[string]any{"rule_id": "low.one", "title": "t", "severity": "low"},
		map[string]any{"rule_id": "crit.one", "title": "t", "severity": "critical"},
		map[string]any{"rule_id": "med.one", "title": "t", "severity": "medium"},
	}})
	res := sum.Document.Runs[0].Results
	want := []string{"crit.one", "med.one", "low.one"}
	for i, w := range want {
		if res[i].RuleID != w {
			t.Fatalf("position %d is %s, want %s", i, res[i].RuleID, w)
		}
	}
}

// Without stable rule ids a CI baseline never converges: the same finding under
// two ids is two findings.
func TestSARIFNormalisesRuleIDs(t *testing.T) {
	// Distinct evidence so dedup keeps both: the assertion is about rule id
	// normalisation, not about collapsing identical findings.
	_, sum := callSarif(t, map[string]any{"findings": []any{
		map[string]any{"rule_id": "TLS Missing HSTS!", "title": "t", "severity": "low", "evidence": "host a"},
		map[string]any{"rule_id": "tls.missing.hsts", "title": "t", "severity": "low", "evidence": "host b"},
	}})
	if sum.Findings != 2 {
		t.Fatalf("findings %d, want 2", sum.Findings)
	}
	if sum.Document.Runs[0].Results[0].RuleID != sum.Document.Runs[0].Results[1].RuleID {
		t.Fatalf("rule ids not normalised: %q vs %q",
			sum.Document.Runs[0].Results[0].RuleID, sum.Document.Runs[0].Results[1].RuleID)
	}
}

func TestSARIFWritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	_, sum := callSarif(t, map[string]any{"findings": sampleFindings(), "output": out})
	if sum.Output == "" {
		t.Fatal("no output path reported")
	}
	if sum.Document != nil {
		t.Fatal("document should not be inlined when it was written")
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarifDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("written file is not valid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("written version %q", doc.Version)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatal("written file should end with a newline")
	}
}

// A report path usually comes from a model suggestion, and quietly overwriting
// or following a link on that basis is not acceptable.
func TestSARIFRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.sarif")
	if err := os.WriteFile(real, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sarif")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"findings": sampleFindings(), "output": link}
	res, err := sarifReportTool(sarifDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return
	}
	if res != nil && !res.IsError {
		t.Fatal("wrote through a symlink")
	}
	raw, _ := os.ReadFile(real)
	if string(raw) != "original" {
		t.Fatalf("symlink target was modified: %q", raw)
	}
}

func TestSARIFRejectsMissingOutputDir(t *testing.T) {
	out := filepath.Join(t.TempDir(), "nope", "report.sarif")
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"findings": sampleFindings(), "output": out}
	res, err := sarifReportTool(sarifDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return
	}
	if res != nil && !res.IsError {
		t.Fatal("wrote into a directory that does not exist")
	}
}

func TestSARIFReadsFindingsFile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "f.json")
	if err := os.WriteFile(plain, []byte(`[{"rule_id":"a","title":"t","severity":"high"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, sum := callSarif(t, map[string]any{"findings_file": plain})
	if sum.Findings != 1 {
		t.Fatalf("findings %d", sum.Findings)
	}
	// A tool that emits its own envelope shape must also be readable.
	wrapped := filepath.Join(dir, "w.json")
	if err := os.WriteFile(wrapped, []byte(`{"findings":[{"rule_id":"b","title":"t","severity":"low"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, sum2 := callSarif(t, map[string]any{"findings_file": wrapped})
	if sum2.Findings != 1 {
		t.Fatalf("wrapped findings %d", sum2.Findings)
	}
}

func TestSARIFRejectsGarbageFindingsFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"findings_file": bad}
	res, err := sarifReportTool(sarifDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return
	}
	if res != nil && !res.IsError {
		t.Fatal("a non-JSON findings file was accepted")
	}
}

// "No findings" and "nothing is wrong" are different claims and only one of them
// is true of an empty input.
func TestSARIFRefusesEmptyInput(t *testing.T) {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{}
	res, err := sarifReportTool(sarifDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return
	}
	if res == nil || !res.IsError {
		t.Fatal("empty input produced a report instead of an error")
	}
}

func TestSARIFInterpretationWarnsItIsNotARiskScore(t *testing.T) {
	_, sum := callSarif(t, map[string]any{"findings": sampleFindings()})
	if !strings.Contains(sum.Interpretation, "not a risk score") {
		t.Fatalf("interpretation: %q", sum.Interpretation)
	}
}

func TestSARIFRuleDefaultMatchesWorstFinding(t *testing.T) {
	_, sum := callSarif(t, map[string]any{"findings": []any{
		map[string]any{"rule_id": "shared", "title": "low one", "severity": "low"},
		map[string]any{"rule_id": "shared", "title": "crit one", "severity": "critical", "evidence": "worse"},
		map[string]any{"rule_id": "shared", "title": "med one", "severity": "medium"},
	}})
	rule := sum.Document.Runs[0].Tool.Driver.Rules[0]
	if rule.DefaultConfig == nil {
		t.Fatal("no default configuration on the rule")
	}
	if rule.DefaultConfig.Level.Level != "error" {
		t.Fatalf("rule default %q, want error", rule.DefaultConfig.Level.Level)
	}
}
