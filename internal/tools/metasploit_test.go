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

// writeModule lays down a module directory the way metasploit-framework does:
// modules/<type>/<os>/<arch>/<name>/metadata.json. relPath is the part after
// "modules/", so tests name the layout directly.
func writeModule(t *testing.T, root, relPath string, refs []string) {
	t.Helper()
	name := filepath.Base(relPath)
	dir := filepath.Join(root, relPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"name":              name + " module",
		"description":       "test module for " + name,
		"references":        refs,
		"modification_date": "2024-01-02",
		"authors":           []string{"nobody"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeModule(t, root, "exploits/windows/x86/smb/MS17-010", []string{
		"CVE-2017-0143", "OSVDB-46734", "URL-https://example.invalid/a",
	})
	writeModule(t, root, "exploits/windows/x64/smb/MS08-067", []string{
		"CVE-2008-4250",
	})
	writeModule(t, root, "auxiliary/scanner/ssh/openssh/enum", []string{
		"CVE-2017-0143", "URL-https://example.invalid/b",
	})
	writeModule(t, root, "auxiliary/scanner/http/log4j/lookup", []string{
		"CVE-2021-44228", "CVE-2021-45046",
	})
	writeModule(t, root, "exploits/multi/http/log4shell/lookup", []string{
		"CVE-2021-44228",
	})
	// Decoys that must not be indexed: wrong depth, and unrelated data files.
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data", "metadata.json"), []byte(`{"name":"decoy"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata.json"), []byte(`{"name":"decoy"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func resetIndex(t *testing.T, root string) {
	t.Helper()
	t.Setenv("SENTINELX_METASPLOIT_MODULES", root)
	old := msfIndex
	msfIndex = nil
	t.Cleanup(func() { msfIndex = old })
}

func msfDecode(t *testing.T, res *mcp.CallToolResult) msfData {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatal("no result content")
	}
	txt, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", res.Content[0])
	}
	var env struct {
		Data msfData `json:"data"`
	}
	if err := json.Unmarshal([]byte(txt.Text), &env); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, txt.Text)
	}
	return env.Data
}

// msfDeps builds a Deps with a real config. The shared ok() helper reads
// d.Cfg.Policy, so a zero Deps panics rather than returning an envelope.
func msfDeps(t *testing.T) Deps {
	t.Helper()
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Policy.EnforceScope = true
	cfg.Policy.ScopeTargets = []string{"example.com"}
	return Deps{Cfg: cfg}
}

func callMSF(t *testing.T, d Deps, args map[string]any) msfData {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := metasploitReferenceTool(d).Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return msfDecode(t, res)
}

func TestMSFCVEOwnedByExploitAndScanner(t *testing.T) {
	root := fakeTree(t)
	resetIndex(t, root)
	d := msfDeps(t)
	// Searchsploit and Metasploit are both absent here, which is exactly the
	// environment this tool has to be useful in.
	data := callMSF(t, d, map[string]any{"query": "CVE-2017-0143"})
	if data.Status != "ok" {
		t.Fatalf("status %q (%s)", data.Status, data.Reason)
	}
	if data.Matches != 2 {
		t.Fatalf("want 2 modules for CVE-2017-0143, got %d: %+v", data.Matches, data.Modules)
	}
	if data.Counts["exploit"] != 1 || data.Counts["scanner"] != 1 {
		t.Fatalf("want 1 exploit + 1 scanner, got %v", data.Counts)
	}
	// A public exploit module is the single most consequential fact this tool
	// reports, so assert the flag actually survives the round trip.
	rce := false
	for _, m := range data.Modules {
		if m.Class == "exploit" {
			rce = true
		}
	}
	if !rce {
		t.Fatal("no exploit class module in the result")
	}
}

func TestMSFExploitOnlyFilter(t *testing.T) {
	resetIndex(t, fakeTree(t))
	data := callMSF(t, msfDeps(t), map[string]any{"query": "CVE-2017-0143", "exploits_only": true})
	if data.Matches != 1 {
		t.Fatalf("exploits_only returned %d modules, want 1", data.Matches)
	}
	if data.Modules[0].Class != "exploit" {
		t.Fatalf("returned a %s module", data.Modules[0].Class)
	}
}

// A CVE query must be an exact lookup. A substring search would return every
// module that merely mentions CVE-2021-44228 in prose.
func TestMSFCVEQueryIsExact(t *testing.T) {
	resetIndex(t, fakeTree(t))
	data := callMSF(t, msfDeps(t), map[string]any{"query": "CVE-2021-44228"})
	if data.Matches != 2 {
		t.Fatalf("want 2, got %d", data.Matches)
	}
	for _, m := range data.Modules {
		if m.Class != "exploit" && m.Class != "scanner" {
			t.Fatalf("unexpected class %s in %s", m.Class, m.Path)
		}
	}
}

// Near-miss CVEs must not bleed into each other's results.
func TestMSFCVEPrefixDoesNotMatchOtherCVE(t *testing.T) {
	resetIndex(t, fakeTree(t))
	data := callMSF(t, msfDeps(t), map[string]any{"query": "CVE-2021-4422"})
	if data.Matches != 0 {
		t.Fatalf("a non-existent CVE returned %d modules", data.Matches)
	}
	if data.Note == "" {
		t.Fatal("an empty result must explain itself")
	}
}

func TestMSFProductSearchFindsScanner(t *testing.T) {
	resetIndex(t, fakeTree(t))
	data := callMSF(t, msfDeps(t), map[string]any{"query": "openssh"})
	if data.Matches == 0 {
		t.Fatal("product search found nothing")
	}
	if data.Counts["scanner"] == 0 {
		t.Fatalf("expected a scanner class, got %v", data.Counts)
	}
}

// Scanner-only coverage is the better outcome and the interpretation has to
// say so, otherwise an assessor rates it as bad news.
func TestMSFScannerOnlyInterpretation(t *testing.T) {
	resetIndex(t, fakeTree(t))
	data := callMSF(t, msfDeps(t), map[string]any{"query": "openssh"})
	if want := "scanner module"; !strings.Contains(data.Interpretation, want) {
		t.Fatalf("interpretation does not mention the scanner: %q", data.Interpretation)
	}
}

func TestMSFExploitWithoutScannerWarnsAboutNoSafeCheck(t *testing.T) {
	resetIndex(t, fakeTree(t))
	data := callMSF(t, msfDeps(t), map[string]any{"query": "CVE-2008-4250"})
	if data.Counts["exploit"] != 1 || data.Counts["scanner"] != 0 {
		t.Fatalf("fixture wrong: %v", data.Counts)
	}
	if !strings.Contains(data.Interpretation, "no scanner module") {
		t.Fatalf("must state there is no safe check: %q", data.Interpretation)
	}
}

// The dangerous failure is a typo'd module root reporting "no coverage". An
// assessor reads that as good news about the target, so it has to be an error.
func TestMSFWrongRootNeverLooksLikeNoCoverage(t *testing.T) {
	t.Setenv("SENTINELX_METASPLOIT_MODULES", filepath.Join(t.TempDir(), "nope"))
	old := msfIndex
	msfIndex = nil
	t.Cleanup(func() { msfIndex = old })
	data := callMSF(t, msfDeps(t), map[string]any{"query": "CVE-2021-44228"})
	if data.Status != "unavailable" {
		t.Fatalf("a missing root reported status %q with %d matches; a wrong path must never read as 'no coverage'",
			data.Status, data.Matches)
	}
	if data.Matches != 0 {
		t.Fatalf("matches reported for an unindexed tree: %d", data.Matches)
	}
}

// An existing but wrong directory must fail too, rather than indexing zero
// modules and reporting that as a clean result.
func TestMSFEmptyDirectoryIsNotCleanCoverage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SENTINELX_METASPLOIT_MODULES", dir)
	old := msfIndex
	msfIndex = nil
	t.Cleanup(func() { msfIndex = old })
	data := callMSF(t, msfDeps(t), map[string]any{"query": "CVE-2021-44228"})
	if data.Status != "unavailable" {
		t.Fatalf("empty directory reported status %q; expected unavailable", data.Status)
	}
}

func TestMSFAbsentTreeIsUnavailableNotAnError(t *testing.T) {
	t.Setenv("SENTINELX_METASPLOIT_MODULES", filepath.Join(t.TempDir(), "does-not-exist"))
	old := msfIndex
	msfIndex = nil
	t.Cleanup(func() { msfIndex = old })
	data := callMSF(t, msfDeps(t), map[string]any{"query": "CVE-2021-44228"})
	if data.Status != "unavailable" {
		t.Fatalf("status %q, want unavailable", data.Status)
	}
	if data.HowTo == "" || data.Reason == "" {
		t.Fatal("an unavailable result must say what to do about it")
	}
}

func TestMSFEmptyQueryIsRejected(t *testing.T) {
	resetIndex(t, fakeTree(t))
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"query": "  "}
	res, err := metasploitReferenceTool(msfDeps(t)).Handler(context.Background(), req)
	if err != nil {
		return // a protocol-level error is also an acceptable rejection
	}
	if res == nil || res.IsError {
		return
	}
	t.Fatal("blank query was accepted as a normal result")
}

func TestMSFOnlyIndexesRealModulePaths(t *testing.T) {
	resetIndex(t, fakeTree(t))
	idx := loadMetasploitIndex()
	if idx.Err != nil {
		t.Fatal(idx.Err)
	}
	// 5 real modules; the two decoy metadata.json files must not be counted.
	if len(idx.Modules) != 5 {
		t.Fatalf("indexed %d modules, want 5: %+v", len(idx.Modules), idx.Modules)
	}
}

func TestMSFCVERefsExtractsOnlyCVEIdentifiers(t *testing.T) {
	got := cveRefs([]string{"CVE-2017-0143", "OSVDB-46734", "URL-https://x.invalid/cve-2017-0143-notes", "cve-2018-0001"})
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "CVE-2017-0143" || got[1] != "CVE-2018-0001" {
		t.Fatalf("unexpected refs %v", got)
	}
}

func TestMSFClassDerivation(t *testing.T) {
	cases := map[string]string{
		"exploits/windows/x86/smb/ms17_010":     "exploit",
		"auxiliary/scanner/ssh/openssh_enum":    "scanner",
		"auxiliary/server/http/jenkins_groovy":  "auxiliary",
		"payloads/linked/x86/shell_reverse_tcp": "other",
	}
	for p, want := range cases {
		if got := classOfModule(p); got != want {
			t.Errorf("classOfModule(%q) = %q, want %q", p, got, want)
		}
	}
}
