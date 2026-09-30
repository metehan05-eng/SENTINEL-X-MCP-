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

func blDeps(t *testing.T) Deps {
	t.Helper()
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Policy.EnforceScope = true
	cfg.Policy.ScopeTargets = []string{"example.com"}
	return Deps{Cfg: cfg}
}

func callBaseline(t *testing.T, args map[string]any) (sarifSummary, map[string]any) {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := baselineTool(blDeps(t)).Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	txt, isTxt := res.Content[0].(mcp.TextContent)
	if !isTxt {
		t.Fatalf("unexpected content %T", res.Content[0])
	}
	if res.IsError {
		t.Fatalf("tool error: %s", txt.Text)
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(txt.Text), &env); err != nil {
		t.Fatalf("bad envelope: %v\n%s", err, txt.Text)
	}
	return sarifSummary{}, env.Data
}

func findingsArgs(fs ...map[string]any) map[string]any {
	arr := make([]any, 0, len(fs))
	for _, f := range fs {
		arr = append(arr, f)
	}
	return map[string]any{"findings": arr}
}

func f1(sev, loc string) map[string]any {
	return map[string]any{
		"rule_id": "tls.missing_hsts", "title": "No HSTS", "severity": sev,
		"location": loc, "port": 443, "evidence": "no header",
	}
}

func TestBaselineSaveThenDiff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)

	_, saved := callBaseline(t, mergeArgs(
		map[string]any{"action": "save", "baseline_id": "weekly"},
		findingsArgs(f1("medium", "https://a"), f1("high", "https://b")),
	))
	if saved["status"] != "saved" {
		t.Fatalf("status %v", saved["status"])
	}
	if saved["findings"].(float64) != 2 {
		t.Fatalf("findings %v", saved["findings"])
	}

	// Second run: b resolved, c new, a still open at the same severity.
	_, d := callBaseline(t, mergeArgs(
		map[string]any{"action": "diff", "baseline_id": "weekly"},
		findingsArgs(f1("medium", "https://a"),
			map[string]any{"rule_id": "tls.weak_cipher", "title": "weak", "severity": "low", "location": "https://c", "port": 443}),
	))
	if got := d["new"].([]any); len(got) != 1 {
		t.Fatalf("new %d, want 1", len(got))
	}
	if got := d["resolved"].([]any); len(got) != 1 {
		t.Fatalf("resolved %d, want 1", len(got))
	}
	if got := d["open"].([]any); len(got) != 1 {
		t.Fatalf("open %d, want 1", len(got))
	}
	if d["current_findings"].(float64) != 2 || d["previous_findings"].(float64) != 2 {
		t.Fatalf("counts %v / %v", d["current_findings"], d["previous_findings"])
	}
}

func mergeArgs(maps ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// A finding that was only re-rated is the same finding. Folding severity into
// the fingerprint would report every re-rating as a fix plus a new finding.
func TestBaselineReRatingIsNotFixPlusNew(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("medium", "https://a"))))

	_, d := callBaseline(t, mergeArgs(map[string]any{"action": "diff", "baseline_id": "b"},
		findingsArgs(f1("high", "https://a"))))
	if got := d["new"].([]any); len(got) != 0 {
		t.Fatalf("a re-rated finding was reported as new: %v", got)
	}
	if got := d["resolved"].([]any); len(got) != 0 {
		t.Fatalf("a re-rated finding was reported as resolved: %v", got)
	}
	rc := d["reclassified"].([]any)
	if len(rc) != 1 {
		t.Fatalf("reclassified %d, want 1", len(rc))
	}
	entry := rc[0].(map[string]any)
	if entry["direction"] != "worsened" {
		t.Fatalf("direction %v", entry["direction"])
	}
	if entry["from"] != "medium" || entry["to"] != "high" {
		t.Fatalf("transition %v -> %v", entry["from"], entry["to"])
	}
}

func TestBaselineImprovedDirection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("high", "https://a"))))
	_, d := callBaseline(t, mergeArgs(map[string]any{"action": "diff", "baseline_id": "b"},
		findingsArgs(f1("low", "https://a"))))
	rc := d["reclassified"].([]any)
	if len(rc) != 1 || rc[0].(map[string]any)["direction"] != "improved" {
		t.Fatalf("reclassified %v", rc)
	}
}

// "Resolved" is an inference. A reader who does not know that will report fixes
// that did not happen, so the caveat travels with every diff.
func TestBaselineAlwaysCarriesResolutionCaveats(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("medium", "https://a"))))
	_, d2 := callBaseline(t, mergeArgs(map[string]any{"action": "diff", "baseline_id": "b"},
		findingsArgs(f1("medium", "https://b"))))
	caveats, _ := d2["caveats"].([]any)
	if len(caveats) == 0 {
		t.Fatal("a diff with a resolved finding carried no caveats")
	}
	joined := ""
	for _, c := range caveats {
		joined += c.(string) + " "
	}
	if !strings.Contains(joined, "NOT verified as fixed") {
		t.Fatalf("caveats do not say a resolution is unverified: %s", joined)
	}
	if !strings.Contains(joined, "service being removed") {
		t.Fatalf("caveats do not list what else produces a resolution: %s", joined)
	}
}

// A baseline on disk must not become a second copy of everything the assessment
// found, so evidence is not stored.
func TestBaselineStoresNoEvidence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	_, saved := callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("high", "https://a"))))
	raw, err := os.ReadFile(saved["baseline_path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "no header") {
		t.Fatalf("evidence was written to the baseline:\n%s", raw)
	}
	var doc baselineDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].Fingerprint == "" {
		t.Fatalf("baseline content %+v", doc.Findings)
	}
}

func TestBaselineFileIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	_, saved := callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("high", "https://a"))))
	st, err := os.Stat(saved["baseline_path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("baseline is readable by others: %o", perm)
	}
}

// The id becomes a filename and is usually chosen by a model, so it is
// validated rather than sanitised.
func TestBaselineRejectsPathTraversalID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	for _, bad := range []string{"../../etc/passwd", "a/b", "", " ", ".hidden", strings.Repeat("x", 65)} {
		req := mcp.CallToolRequest{}
		req.Params.Arguments = mergeArgs(map[string]any{"action": "save", "baseline_id": bad},
			findingsArgs(f1("high", "https://a")))
		res, err := baselineTool(blDeps(t)).Handler(context.Background(), req)
		if err != nil {
			continue
		}
		if res != nil && !res.IsError {
			t.Errorf("accepted baseline id %q", bad)
		}
	}
	// Nothing should have been written outside the root.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("wrote %d files for rejected ids", len(entries))
	}
}

func TestBaselineDiffWithoutSaveFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = mergeArgs(map[string]any{"action": "diff", "baseline_id": "never-saved"},
		findingsArgs(f1("high", "https://a")))
	res, err := baselineTool(blDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return
	}
	if res != nil && !res.IsError {
		t.Fatal("diff against a nonexistent baseline succeeded")
	}
}

func TestBaselineCorruptFileIsReported(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := mcp.CallToolRequest{}
	req.Params.Arguments = mergeArgs(map[string]any{"action": "diff", "baseline_id": "bad"},
		findingsArgs(f1("high", "https://a")))
	res, err := baselineTool(blDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return
	}
	if res != nil && !res.IsError {
		t.Fatal("a corrupt baseline was accepted")
	}
}

func TestBaselineRejectsEmptyFindings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"action": "save", "baseline_id": "b"}
	res, err := baselineTool(blDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return
	}
	if res != nil && !res.IsError {
		t.Fatal("saved an empty baseline")
	}
}

func TestBaselineFingerprintIsStableAcrossSeverityAndTitle(t *testing.T) {
	a := findingFingerprint("tls.hsts", "https://a", 443)
	b := findingFingerprint("TLS.HSTS", "https://a", 443)
	if a != b {
		t.Fatalf("fingerprint changed for the same finding: %s vs %s", a, b)
	}
	// A different port is a different finding.
	if a == findingFingerprint("tls.hsts", "https://a", 8443) {
		t.Fatal("port ignored by the fingerprint")
	}
	// A different rule is a different finding.
	if a == findingFingerprint("tls.other", "https://a", 443) {
		t.Fatal("rule id ignored by the fingerprint")
	}
}

// "Nothing changed" is a weak signal, not a strong one: a swapped finding keeps
// the count identical.
func TestBaselineNoChangeIsReportedWeakly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("high", "https://a"))))
	_, d := callBaseline(t, mergeArgs(map[string]any{"action": "diff", "baseline_id": "b"},
		findingsArgs(f1("high", "https://a"))))
	interp := d["interpretation"].(string)
	if !strings.Contains(interp, "Nothing changed") {
		t.Fatalf("interpretation: %q", interp)
	}
	if !strings.Contains(interp, "weak signal") {
		t.Fatalf("an identical count was reported as strong assurance: %q", interp)
	}
}

func TestBaselineOverwriteIsDisclosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("high", "https://a"))))
	_, again := callBaseline(t, mergeArgs(map[string]any{"action": "save", "baseline_id": "b"},
		findingsArgs(f1("low", "https://z"))))
	if !strings.Contains(again["note"].(string), "overwrote") {
		t.Fatalf("overwriting a baseline was silent: %v", again["note"])
	}
}

func TestBaselineTargetUsedAsID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_BASELINE_DIR", dir)
	_, saved := callBaseline(t, mergeArgs(map[string]any{"action": "save", "target": "example.com"},
		findingsArgs(f1("high", "https://a"))))
	if saved["baseline_id"] != "example.com" {
		t.Fatalf("baseline id %v", saved["baseline_id"])
	}
}
