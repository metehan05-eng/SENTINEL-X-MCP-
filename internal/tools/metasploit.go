package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// Metasploit module reference
//
// This reads Metasploit's own module metadata off disk. It deliberately does
// not drive msfconsole: msfconsole is a stateful REPL that wants a database and
// a long-lived session, and starting one per MCP call would be slow and fragile
// for what is a lookup. The metadata files answer the question an assessment
// actually asks — "is there a known exploit for this, and is it a scanner or
// a real exploit?" — without a database, and without ever touching a target.
//
// Nothing here executes a module, so the read-only contract holds: no packets,
// no payloads, no session.
// ---------------------------------------------------------------------------

// moduleRoots are searched in order. The first that exists wins, so a system
// install is preferred over a copy left in the user's home directory.
var moduleRoots = []string{
	"/usr/share/metasploit-framework/modules",
	"/opt/metasploit-framework/modules",
	"/usr/local/share/metasploit-framework/modules",
	"/opt/homebrew/share/metasploit-framework/modules",
}

// msfModule is the subset of a module's metadata.json that is worth exposing.
type msfModule struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
	Authors     []any    `json:"authors,omitempty"`
	Date        string   `json:"modification_date,omitempty"`

	// Derived from the module's path, not the file: the directory is what
	// distinguishes a detection module from an exploit, and Metasploit
	// guarantees the layout.
	Path  string `json:"path"`
	Class string `json:"class"` // exploit | scanner | other
	OS    string `json:"os"`    // windows | linux | unix | multi
	Arch  string `json:"arch"`  // x86 | arm | multi | ...
	RCE   bool   `json:"remote_code_execution"`
}

// cveRef is any reference in a module's list that identifies a CVE.
func cveRefs(refs []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, r := range refs {
		for _, tok := range strings.Fields(r) {
			u := strings.ToUpper(tok)
			if strings.HasPrefix(u, "CVE-") && !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	sort.Strings(out)
	return out
}

// classOfModule maps a module path to a coarse class. Exploit and auxiliary
// scanner modules are the two that change how a finding should be read: one
// means there is a public exploit, the other means there is a safe check.
func classOfModule(p string) string {
	// Module paths are relative to the modules/ directory, so they start with
	// "exploits/" and never contain "/exploits/". Matching a leading slash
	// classifies every real module as "other".
	segs := strings.Split(strings.Trim(filepath.ToSlash(p), "/"), "/")
	for _, seg := range segs {
		if seg == "exploits" {
			return "exploit"
		}
	}
	for i, seg := range segs {
		if seg == "auxiliary" {
			if i+1 < len(segs) && segs[i+1] == "scanner" {
				return "scanner"
			}
			return "auxiliary"
		}
	}
	return "other"
}

func osOfModule(p string) string {
	parts := strings.Split(strings.Trim(filepath.ToSlash(p), "/"), "/")
	for _, part := range parts {
		switch part {
		case "windows", "linux", "unix", "android", "osx":
			return part
		case "multi":
			return "multi"
		}
	}
	return ""
}

func archOfModule(p string) string {
	parts := strings.Split(strings.Trim(filepath.ToSlash(p), "/"), "/")
	for _, part := range parts {
		switch part {
		case "x86", "x64", "arm", "mips", "aarch64", "ppc", "sparc":
			return part
		case "multi":
			return "multi"
		}
	}
	return ""
}

// indicatesRCE is deliberately conservative. The presence of a payload
// reference is a strong signal of remote code execution, but absence proves
// nothing, so this is reported as an indicator and not as a verdict.
func indicatesRCE(refs []string) bool {
	for _, r := range refs {
		l := strings.ToLower(r)
		if strings.Contains(l, "/payloads") || strings.Contains(l, "payload-") {
			return true
		}
	}
	return false
}

// metasploitIndex is a lazily built, process-cached view of the module tree.
// Rebuilding on every call would walk several thousand directories for a
// question a single lookup answers.
type metasploitIndex struct {
	Root    string
	Built   time.Time
	Modules []msfModule
	ByCVE   map[string][]msfModule
	Scanned bool
	Err     error
}

var msfIndex *metasploitIndex

// loadMetasploitIndex finds the module tree and reads it once.
func loadMetasploitIndex() *metasploitIndex {
	if msfIndex != nil {
		return msfIndex
	}
	idx := &metasploitIndex{ByCVE: map[string][]msfModule{}}

	if root := os.Getenv("SENTINELX_METASPLOIT_MODULES"); root != "" {
		idx.Root = root
	} else {
		for _, c := range moduleRoots {
			if st, err := os.Stat(filepath.Join(c, "metadata.json")); err == nil && st.IsDir() {
				idx.Root = c
				break
			}
		}
	}
	if idx.Root == "" {
		idx.Err = fmt.Errorf("no Metasploit module tree found; set SENTINELX_METASPLOIT_MODULES to the path of a metasploit-framework modules directory")
		msfIndex = idx
		return idx
	}
	// A wrong root must not degrade into "no coverage indexed". WalkDir calls
	// the callback with the error for a missing root, the callback swallows it,
	// and the caller sees an empty index and reports that as a clean result —
	// which is the one reading that would lead an assessor to under-rate a
	// finding. Check the root exists and is a directory before trusting it.
	if st, err := os.Stat(idx.Root); err != nil || !st.IsDir() {
		idx.Err = fmt.Errorf("SENTINELX_METASPLOIT_MODULES=%s is not a readable directory", idx.Root)
		msfIndex = idx
		return idx
	}

	err := filepath.WalkDir(idx.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable subtree should not abort the whole index
		}
		if d.IsDir() || d.Name() != "metadata.json" {
			return nil
		}
		rel, rerr := filepath.Rel(idx.Root, filepath.Dir(path))
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		// Module metadata lives under modules/<type>/<os>/<arch>/<name>/, and
		// the deeper the better the correlation. Everything else is a data file
		// that happens to be called metadata.json.
		if len(strings.Split(rel, "/")) < 3 {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var m msfModule
		if json.Unmarshal(raw, &m) != nil {
			return nil
		}
		m.Path = rel
		m.Class = classOfModule(rel)
		m.OS = osOfModule(rel)
		m.Arch = archOfModule(rel)
		m.RCE = indicatesRCE(m.References)
		idx.Modules = append(idx.Modules, m)
		for _, c := range cveRefs(m.References) {
			idx.ByCVE[c] = append(idx.ByCVE[c], m)
		}
		return nil
	})
	idx.Err = err
	if idx.Err == nil && len(idx.Modules) == 0 {
		idx.Err = fmt.Errorf("%s contains no module metadata; this is not a metasploit-framework modules directory", idx.Root)
	}
	idx.Scanned = true
	idx.Built = time.Now()
	sort.Slice(idx.Modules, func(i, j int) bool { return idx.Modules[i].Path < idx.Modules[j].Path })
	msfIndex = idx
	return idx
}

// searchMetasploit looks up modules by CVE, product or module path substring.
func searchMetasploit(query string, limit int) (*metasploitIndex, []msfModule, bool) {
	idx := loadMetasploitIndex()
	q := strings.ToLower(strings.TrimSpace(query))
	hits := []msfModule{}
	if q == "" {
		return idx, hits, false
	}
	// A CVE query is an exact set lookup, not a substring search: CVE-2021-44228
	// must not also return modules that merely mention the string.
	if cves := cveRefs([]string{q}); len(cves) == 1 && strings.HasPrefix(strings.ToUpper(q), "CVE-") {
		return idx, idx.ByCVE[cves[0]], true
	}
	for _, m := range idx.Modules {
		if strings.Contains(strings.ToLower(m.Path), q) ||
			strings.Contains(strings.ToLower(m.Name), q) ||
			strings.Contains(strings.ToLower(m.Description), q) {
			hits = append(hits, m)
		}
	}
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return idx, hits, false
}

// moduleCounts summarises the index for the response header, so a caller can
// tell "no matches" from "searched the wrong tree".
func moduleCounts(mods []msfModule) map[string]int {
	out := map[string]int{"total": len(mods)}
	for _, m := range mods {
		out[m.Class]++
		if m.OS != "" {
			out["os:"+m.OS]++
		}
	}
	return out
}

func msfModuleSummary(m msfModule) msfModuleView {
	return msfModuleView{
		Path:     m.Path,
		Name:     m.Name,
		Class:    m.Class,
		RCE:      m.RCE,
		OS:       m.OS,
		Arch:     m.Arch,
		CVEs:     cveRefs(m.References),
		Refs:     m.References,
		Descr:    truncate(m.Description, 240),
		Modified: m.Date,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// msfData is the tool payload. Status is inside the data rather than being an
// error, because "Metasploit is not installed" is a fact about the environment
// that a caller should receive and route around, not a failure of the call.
type msfData struct {
	Status         string          `json:"status"`
	Query          string          `json:"query"`
	ModuleRoot     string          `json:"module_root,omitempty"`
	IndexedModules int             `json:"indexed_modules,omitempty"`
	Matches        int             `json:"matches"`
	Counts         map[string]int  `json:"counts,omitempty"`
	Modules        []msfModuleView `json:"modules"`
	Interpretation string          `json:"interpretation,omitempty"`
	Note           string          `json:"note,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	HowTo          string          `json:"how_to,omitempty"`
	SearchedPaths  []string        `json:"searched_paths,omitempty"`
}

// msfModuleView is the per-module view returned to the model.
type msfModuleView struct {
	Path     string   `json:"path"`
	Name     string   `json:"name,omitempty"`
	Class    string   `json:"class"`
	RCE      bool     `json:"remote_code_execution"`
	OS       string   `json:"os,omitempty"`
	Arch     string   `json:"arch,omitempty"`
	CVEs     []string `json:"cves"`
	Refs     []string `json:"references,omitempty"`
	Descr    string   `json:"description,omitempty"`
	Modified string   `json:"modified,omitempty"`
}

func metasploitReferenceTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_metasploit_reference",
		mcp.WithDescription(
			"Look up Metasploit Framework module coverage for a CVE, product or service — how many modules "+
				"reference it, whether they are exploit or scanner modules, and which OS/arch they target. Use "+
				"this to decide how seriously to treat a finding: a CVE with a public exploit module is materially "+
				"worse than the same CVE with only a scanner module.\n\n"+
				"STRICTLY READ-ONLY AND OFFLINE: this reads module metadata.json files from the local "+
				"metasploit-framework install. It never runs msfconsole, never executes a module, never sends a "+
				"packet to a target, and never returns exploit code. It answers only \"what coverage exists\". "+
				"To actually verify a target is vulnerable, use the assessment tools; an exploit module existing "+
				"is not evidence that the target is exploitable."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("CVE id (CVE-2021-44228), product/service name, or module name fragment."),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum modules to return. Default 25, capped at 100."),
		),
		mcp.WithBoolean("exploits_only",
			mcp.Description("Return only modules under exploits/, dropping scanner and auxiliary modules. Default false."),
		),
	)
	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_metasploit_reference"
		query := strings.TrimSpace(req.GetString("query", ""))
		if query == "" {
			return failf(toolName, query, start,
				"query is required: pass a CVE id such as CVE-2021-44228, a product name, or a module name")
		}
		limit := clampInt(req.GetInt("limit", 25), 1, 100, 25)

		idx, hits, _ := searchMetasploit(query, limit)
		if idx.Err != nil {
			// Not an error: the caller asked a reasonable question and the
			// answer is "this machine has no Metasploit to ask".
			return ok(d, toolName, query, start, nil, msfData{
				Status:        "unavailable",
				Query:         query,
				Matches:       0,
				Modules:       []msfModuleView{},
				Reason:        idx.Err.Error(),
				HowTo:         "Install metasploit-framework, or set SENTINELX_METASPLOIT_MODULES to a modules directory. This tool reads metadata only; it needs no database and no running console.",
				SearchedPaths: moduleRoots,
			})
		}

		if req.GetBool("exploits_only", false) {
			kept := []msfModule{}
			for _, m := range hits {
				if m.Class == "exploit" {
					kept = append(kept, m)
				}
			}
			hits = kept
		}

		data := msfData{
			Status:         "ok",
			Query:          query,
			ModuleRoot:     idx.Root,
			IndexedModules: len(idx.Modules),
			Matches:        len(hits),
			Counts:         moduleCounts(hits),
			Modules:        []msfModuleView{},
		}
		for _, m := range hits {
			data.Modules = append(data.Modules, msfModuleSummary(m))
		}
		if len(hits) == 0 {
			// "No match" and "searched the wrong tree" look identical from the
			// outside, so say which one this was and what it does not mean.
			data.Note = fmt.Sprintf(
				"No Metasploit module in %s matches %q. An empty result means no coverage is indexed for that "+
					"term — it does not mean the target is unaffected. Check the spelling, or search the "+
					"product name rather than the CVE id.", idx.Root, query)
		} else {
			data.Interpretation = interpretMetasploit(hits)
		}
		return ok(d, toolName, query, start, nil, data)
	}
	return Tool{Tool: t, Handler: h}
}

// interpretMetasploit turns module classes into the sentence an assessor
// actually needs. Counts alone invite over-reading in both directions.
func interpretMetasploit(hits []msfModule) string {
	counts := moduleCounts(hits)
	exploits, scanners := counts["exploit"], counts["scanner"]
	switch {
	case exploits > 0 && scanners > 0:
		return fmt.Sprintf(
			"%d exploit module(s) and %d scanner module(s) reference this. The scanner modules can confirm "+
				"vulnerability without side effects; the exploit modules indicate a public attack path exists. "+
				"Treat the finding as high priority and verify with the scanner before considering anything else.",
			exploits, scanners)
	case exploits > 0:
		return fmt.Sprintf(
			"%d exploit module(s) reference this and no scanner module does, so there is no safe Metasploit "+
				"check for it. A public attack path exists but confirming exploitability means sending traffic "+
				"that changes the target's state. This is a strong signal from index data only, not evidence "+
				"the target is actually vulnerable.", exploits)
	case scanners > 0:
		return fmt.Sprintf(
			"%d scanner module(s) reference this and no exploit module does. That is the better outcome: it "+
				"means there is a way to confirm the vulnerability without side effects, so use it to verify "+
				"before rating severity.", scanners)
	default:
		return "Modules were found but none are exploit or scanner classes; they are likely auxiliary or post-exploitation and not directly applicable to an external assessment."
	}
}
