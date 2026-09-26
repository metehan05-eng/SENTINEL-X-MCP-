package tools

// Software supply-chain analysis.
//
// Two tools live here. The first is a pure offline reader: it walks a project,
// finds its dependency manifests, and emits a CycloneDX-shaped software
// bill of materials. The second correlates that inventory against the NVD
// vulnerability database, which is the step most scanning setups skip and the
// one that turns "we have 400 dependencies" into "three of them are exploitable".
//
// Neither tool builds, installs, resolves or modifies anything. Manifests are
// read as text and parsed locally. The only outbound request is the read-only
// NVD API query, which is skipped entirely in offline mode.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// SupplyChain is the module slice for the supply-chain tools.
func SupplyChain(d Deps) []Tool {
	return []Tool{
		sbomInventoryTool(d),
		dependencyAuditTool(d),
	}
}

// ---------------------------------------------------------------------------
// Manifest parsing
// ---------------------------------------------------------------------------

// dependency is one resolved package from a manifest.
type dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Ecosystem string `json:"ecosystem"`
	// Manifest records which file this came from, so a result is traceable.
	Manifest string `json:"manifest"`
	// Direct distinguishes a first-party requirement from a transitive one.
	Direct bool `json:"direct"`
	// License is filled in where the manifest states it.
	License string `json:"license,omitempty"`
}

// manifestKind describes a supported manifest file.
type manifestKind struct {
	// Ecosystem is the CycloneDX/SBOM name.
	Ecosystem string
	// Parse extracts dependencies from the file body.
	Parse func(body string) []dependency
}

var reGoModuleLine = regexp.MustCompile(`^\s*([a-zA-Z0-9._~/-]+\.[a-zA-Z0-9._~/-]+)\s+(v[^\s]+)`)
var reGoReplace = regexp.MustCompile(`(?m)^\s*(?:require\s+)?//\s*replace`)

// parseGoMod reads a go.mod. The format is line-oriented, so a small parser
// beats pulling in a full module-graph implementation: it reads the require
// directives and nothing else, which is exactly the intent of this tool.
func parseGoMod(body string) []dependency {
	var out []dependency
	inBlock := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Block form must be tested first: "require (" also has the prefix
		// "require ", so a single-line check placed above it would consume the
		// opening of the block and silently drop every dependency inside it.
		if trimmed == "require (" || trimmed == "require(" {
			inBlock = true
			continue
		}
		// Single-line require.
		if strings.HasPrefix(trimmed, "require ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "require"))
			if m := reGoModuleLine.FindStringSubmatch(trimmed); m != nil {
				direct := !strings.Contains(line, "// indirect")
				out = append(out, dependency{Name: m[1], Version: m[2], Ecosystem: "go", Direct: direct})
			}
			continue
		}
		if inBlock {
			if trimmed == ")" {
				inBlock = false
				continue
			}
			if m := reGoModuleLine.FindStringSubmatch(trimmed); m != nil {
				direct := !strings.Contains(trimmed, "// indirect")
				out = append(out, dependency{Name: m[1], Version: m[2], Ecosystem: "go", Direct: direct})
			}
		}
	}
	return out
}

// reRequirement covers pip requirement lines: name[extras]==1.2.3, name>=1.0,
// name~=2.0, and bare name. Only pinned or lower-bounded versions are useful
// for correlation, so a bare name is recorded without a version.
var reRequirement = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|~=|>|<|!=)?\s*([0-9][^\s;#,]*)?`)

func parseRequirementsTxt(body string) []dependency {
	var out []dependency
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		if strings.HasPrefix(trimmed, "git+") || strings.HasPrefix(trimmed, "http") {
			continue // VCS/URL pins carry no comparable version
		}
		// Drop inline comments and environment markers before matching.
		if i := strings.Index(trimmed, ";"); i >= 0 {
			trimmed = trimmed[:i]
		}
		if i := strings.Index(trimmed, " #"); i >= 0 {
			trimmed = trimmed[:i]
		}
		m := reRequirement.FindStringSubmatch(strings.TrimSpace(trimmed))
		if m == nil || m[1] == "" {
			continue
		}
		out = append(out, dependency{Name: m[1], Version: m[3], Ecosystem: "pypi", Direct: true})
	}
	return out
}

var reMavenCoord = regexp.MustCompile(`<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>`)

func parsePomXML(body string) []dependency {
	var out []dependency
	for _, m := range reMavenCoord.FindAllStringSubmatch(body, -1) {
		ver := strings.TrimSpace(m[3])
		// Unresolved ${property} placeholders cannot be correlated.
		if strings.HasPrefix(ver, "${") {
			ver = ""
		}
		out = append(out, dependency{
			Name:      m[1] + ":" + m[2],
			Version:   ver,
			Ecosystem: "maven",
			Direct:    true,
		})
	}
	return out
}

var reGemLine = regexp.MustCompile(`^\s{4}([a-zA-Z0-9_.-]+)\s+\(([^)]+)\)`)

func parseGemfileLock(body string) []dependency {
	var out []dependency
	// GEM/specs: section headers are followed by 4-space-indented entries.
	inSpecs := false
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "GEM") || strings.HasPrefix(line, "  specs:") {
			inSpecs = true
			continue
		}
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
		}
		if !inSpecs {
			continue
		}
		if m := reGemLine.FindStringSubmatch(line); m != nil {
			out = append(out, dependency{Name: m[1], Version: m[2], Ecosystem: "gem", Direct: true})
		}
	}
	return out
}

var reCargoPkg = regexp.MustCompile(`(?m)^\[\[package\]\]\s*$(?:\s*\n(?:name|version|source)\s*=\s*"[^"]*")*`)
var reCargoField = regexp.MustCompile(`(?m)^\s*(name|version|source)\s*=\s*"([^"]*)"`)

func parseCargoLock(body string) []dependency {
	var out []dependency
	for _, block := range strings.Split(body, "[[package]]") {
		if !strings.Contains(block, "name") {
			continue
		}
		var name, ver, source string
		for _, fm := range reCargoField.FindAllStringSubmatch(block, -1) {
			switch fm[1] {
			case "name":
				name = fm[2]
			case "version":
				ver = fm[2]
			case "source":
				source = fm[2]
			}
		}
		if name == "" || strings.Contains(source, "git+") {
			continue
		}
		out = append(out, dependency{Name: name, Version: ver, Ecosystem: "cargo", Direct: true})
	}
	_ = reCargoPkg
	return out
}

var reComposerName = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
var reComposerVersion = regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)

func parseComposerJSON(body string) []dependency {
	var out []dependency
	// composer.lock is a flat packages array; pair each name with the nearest
	// following version rather than trying to model the whole document.
	locs := reComposerName.FindAllStringSubmatchIndex(body, -1)
	vlocs := reComposerVersion.FindAllStringSubmatchIndex(body, -1)
	for i, nl := range locs {
		ver := ""
		for _, vl := range vlocs {
			if vl[0] > nl[0] {
				ver = body[vl[2]:vl[3]]
				break
			}
		}
		out = append(out, dependency{Name: body[nl[2]:nl[3]], Version: ver, Ecosystem: "composer", Direct: true})
		if i > 5000 { // defensive bound
			break
		}
	}
	return out
}

// npmLockModels are the two shapes npm has used for package-lock.json.
type npmLockModel struct {
	Dependencies map[string]npmDep `json:"dependencies"`
	Packages     map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
		License string `json:"license"`
	} `json:"packages"`
}

type npmDep struct {
	Version      string            `json:"version"`
	Dev          bool              `json:"dev"`
	Requires     map[string]string `json:"requires"`
	Dependencies map[string]npmDep `json:"dependencies"`
	License      string            `json:"license"`
}

func parsePackageLock(body string) []dependency {
	var lock npmLockModel
	if err := json.Unmarshal([]byte(body), &lock); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []dependency
	add := func(name, ver, lic string, dev bool) {
		key := name + "@" + ver
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, dependency{Name: name, Version: ver, License: lic, Ecosystem: "npm", Direct: true})
	}
	// v2/v3 "packages" map.
	for path, meta := range lock.Packages {
		if path == "" || !strings.Contains(path, "node_modules/") {
			continue
		}
		name := path
		if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
			name = path[i+len("node_modules/"):]
		}
		add(name, meta.Version, meta.License, meta.Dev)
	}
	// v1 nested "dependencies" tree.
	var walk func(map[string]npmDep)
	walk = func(m map[string]npmDep) {
		for name, dep := range m {
			add(name, strings.TrimPrefix(dep.Version, "^"), dep.License, dep.Dev)
			if len(dep.Dependencies) > 0 {
				walk(dep.Dependencies)
			}
		}
	}
	if len(lock.Packages) == 0 {
		walk(lock.Dependencies)
	}
	return out
}

// manifestTable maps a file's base name to its parser.
var manifestTable = map[string]manifestKind{
	"go.mod":            {Ecosystem: "go", Parse: parseGoMod},
	"requirements.txt":  {Ecosystem: "pypi", Parse: parseRequirementsTxt},
	"pyproject.toml":    {Ecosystem: "pypi", Parse: nil}, // handled specially below
	"pom.xml":           {Ecosystem: "maven", Parse: parsePomXML},
	"Gemfile.lock":      {Ecosystem: "gem", Parse: parseGemfileLock},
	"Cargo.lock":        {Ecosystem: "cargo", Parse: parseCargoLock},
	"composer.lock":     {Ecosystem: "composer", Parse: parseComposerJSON},
	"composer.json":     {Ecosystem: "composer", Parse: parseComposerJSON},
	"package-lock.json": {Ecosystem: "npm", Parse: parsePackageLock},
	"Pipfile.lock":      {Ecosystem: "pypi", Parse: parsePipfileLock},
}

var rePyProjectDep = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9._-]+)\s*=\s*[{"]?\s*[\^~>=<]*\s*([0-9][0-9A-Za-z.\-]*)`)

func parsePyProjectToml(body string) []dependency {
	// Only the PEP 621 [project] dependencies array and the legacy
	// [tool.poetry.dependencies] table are of interest; both use the same
	// "name = spec" shape, so one line-oriented pass suffices.
	var out []dependency
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		if !strings.Contains(trimmed, "=") {
			continue
		}
		m := rePyProjectDep.FindStringSubmatch(trimmed)
		if m == nil || m[1] == "" || strings.EqualFold(m[1], "version") {
			continue
		}
		// Skip build-system requirements and tool tables that are not deps.
		lower := strings.ToLower(m[1])
		if lower == "python" || strings.HasPrefix(lower, "setuptools") {
			continue
		}
		out = append(out, dependency{Name: m[1], Version: m[2], Ecosystem: "pypi", Direct: true})
	}
	return out
}

func parsePipfileLock(body string) []dependency {
	// Pipenv nests a "default" and "develop" section, each mapping name to a
	// {"version": "==x.y.z"} object.
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal([]byte(body), &lock); err != nil {
		return nil
	}
	var out []dependency
	for name, meta := range lock.Default {
		out = append(out, dependency{Name: name, Version: strings.TrimPrefix(meta.Version, "=="), Ecosystem: "pypi", Direct: true})
	}
	for name, meta := range lock.Develop {
		out = append(out, dependency{Name: name, Version: strings.TrimPrefix(meta.Version, "=="), Ecosystem: "pypi", Scope: "development", Direct: false})
	}
	return out
}

// buildInventory walks root and returns every dependency it can find.
func buildInventory(root string, maxManifests, maxDeps int) (deps []dependency, files []string, truncated bool, err error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, nil, false, fmt.Errorf("cannot inspect %s: %w", root, err)
	}
	if !st.IsDir() {
		// A single manifest may be pointed at directly.
		if deps, err = parseManifest(root, maxDeps); err != nil {
			return nil, nil, false, err
		}
		return deps, []string{root}, false, nil
	}

	seenDep := map[string]bool{}
	walkErr := filepath.WalkDir(root, func(p string, entry os.DirEntry, werr error) error {
		if werr != nil {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if p != root && shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		kind, known := manifestTable[entry.Name()]
		if !known {
			return nil
		}
		// pyproject.toml needs a dedicated parser, not the generic one.
		if entry.Name() == "pyproject.toml" {
			kind.Parse = parsePyProjectToml
		}
		body, rerr := readCappedFileBody(p, 4<<20)
		if rerr != nil {
			return nil
		}
		var found []dependency
		if kind.Parse != nil {
			found = kind.Parse(body)
		}
		rel, _ := filepath.Rel(root, p)
		files = append(files, rel)
		for _, dep := range found {
			dep.Manifest = rel
			key := dep.Ecosystem + "|" + dep.Name + "|" + dep.Version
			if seenDep[key] {
				continue
			}
			seenDep[key] = true
			deps = append(deps, dep)
		}
		if len(files) >= maxManifests || len(deps) >= maxDeps {
			truncated = true
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		// A partial inventory is more useful than none; the caller is told it
		// was truncated.
		truncated = true
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ecosystem != deps[j].Ecosystem {
			return deps[i].Ecosystem < deps[j].Ecosystem
		}
		return deps[i].Name < deps[j].Name
	})
	return deps, files, truncated, nil
}

func parseManifest(path string, maxDeps int) ([]dependency, error) {
	kind, known := manifestTable[filepath.Base(path)]
	if !known {
		return nil, fmt.Errorf("%s is not a supported dependency manifest", filepath.Base(path))
	}
	if path == "" || strings.HasSuffix(path, "pyproject.toml") {
		kind.Parse = parsePyProjectToml
	}
	body, err := readCappedFileBody(path, 4<<20)
	if err != nil {
		return nil, err
	}
	deps := kind.Parse(body)
	rel := filepath.Base(path)
	for i := range deps {
		deps[i].Manifest = rel
	}
	if len(deps) > maxDeps {
		deps = deps[:maxDeps]
	}
	return deps, nil
}

func readCappedFileBody(path string, limit int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > limit {
		b = b[:limit]
	}
	return string(b), nil
}

// ---------------------------------------------------------------------------
// Tool: SBOM inventory
// ---------------------------------------------------------------------------

// SBOMResult is a CycloneDX-shaped software bill of materials.
type SBOMResult struct {
	Root        string       `json:"root"`
	SpecVersion string       `json:"spec_version"`
	Components  []dependency `json:"components"`
	Manifests   []string     `json:"manifests"`
	Ecosystems  []string     `json:"ecosystems"`
	Truncated   bool         `json:"truncated"`
	Notes       []string     `json:"notes,omitempty"`
}

func sbomInventoryTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_sbom_inventory",
		mcp.WithDescription(
			"Produce a software bill of materials for a project by parsing its dependency "+
				"manifests: go.mod, package-lock.json, requirements.txt, pyproject.toml, "+
				"Pipfile.lock, pom.xml, Gemfile.lock, Cargo.lock and composer.json. Returns a "+
				"CycloneDX-shaped component list with ecosystem, version, licence and whether the "+
				"dependency is direct or transitive. "+
				"READ-ONLY: manifests are read from disk. Nothing is installed, resolved, or built.",
		),
		mcp.WithToolTitle("SENTINEL-X SBOM Inventory"),
		mcp.WithString("path",
			mcp.Description("Absolute path to a project directory or a single manifest file. Must be inside the configured audit roots."),
			mcp.Required(),
		),
		mcp.WithNumber("max_components",
			mcp.Description("Maximum components to return (1-2000)."),
			mcp.DefaultNumber(500),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_sbom_inventory"

		path, aerr := requireArg(req, "path")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if path == "" {
			return failf(toolName, path, start, "path is required")
		}
		if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
			return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
		}

		maxC := req.GetInt("max_components", 500)
		if maxC < 1 {
			maxC = 1
		}
		if maxC > 2000 {
			maxC = 2000
		}

		deps, files, truncated, err := buildInventory(path, 64, maxC)
		if err != nil {
			return fail(toolName, path, start, err)
		}

		eco := map[string]bool{}
		for _, dep := range deps {
			eco[dep.Ecosystem] = true
		}
		ecosystems := make([]string, 0, len(eco))
		for e := range eco {
			ecosystems = append(ecosystems, e)
		}
		sort.Strings(ecosystems)

		res := SBOMResult{
			Root:        path,
			SpecVersion: "CycloneDX 1.5 (subset: components only)",
			Components:  deps,
			Manifests:   files,
			Ecosystems:  ecosystems,
			Truncated:   truncated,
			Notes: []string{
				"versions come from the manifest's own pins, not from a live resolver, so a stale lockfile will report stale versions",
			},
		}
		if res.Components == nil {
			res.Components = []dependency{}
		}
		return ok(d, toolName, path, start, nil, res)
	}

	return Tool{Tool: t, Handler: h}
}

// ---------------------------------------------------------------------------
// Tool: dependency vulnerability audit
// ---------------------------------------------------------------------------

// DepFinding is one vulnerable dependency.
type DepFinding struct {
	Package    string  `json:"package"`
	Version    string  `json:"version,omitempty"`
	Ecosystem  string  `json:"ecosystem"`
	Manifest   string  `json:"manifest"`
	CVE        string  `json:"cve,omitempty"`
	CVSS       float64 `json:"cvss,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	Summary    string  `json:"summary,omitempty"`
	Exploited  bool    `json:"known_exploited"`
	Confidence string  `json:"match_confidence"`
	MatchBasis string  `json:"match_basis"`
	Remediate  string  `json:"remediation,omitempty"`
}

// DepAuditResult is the outcome of correlating an inventory against the NVD.
type DepAuditResult struct {
	Root        string       `json:"root"`
	Manifests   []string     `json:"manifests,omitempty"`
	Components  int          `json:"components"`
	Audited     int          `json:"audited"`
	Vulnerable  int          `json:"vulnerable_components"`
	Critical    int          `json:"critical"`
	High        int          `json:"high"`
	Offline     bool         `json:"offline"`
	Findings    []DepFinding `json:"findings"`
	NotAudited  []string     `json:"not_audited,omitempty"`
	Limitations []string     `json:"limitations"`
}

func dependencyAuditTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_dependency_audit",
		mcp.WithDescription(
			"Correlate a project's declared dependencies against the NVD vulnerability database "+
				"and return a prioritised list of vulnerable components. Parses go.mod, "+
				"package-lock.json, requirements.txt, pyproject.toml, Pipfile.lock, pom.xml, "+
				"Gemfile.lock, Cargo.lock and composer.json, then queries the NVD API for each "+
				"package. Reports CVSS severity, known-exploited status, an explicit match "+
				"confidence, and the fact that CPE-based matching cannot see distribution "+
				"backports. "+
				"READ-ONLY: manifests are read and the NVD API is queried read-only. Nothing is "+
				"installed or upgraded.",
		),
		mcp.WithToolTitle("SENTINEL-X Dependency Audit"),
		mcp.WithString("path",
			mcp.Description("Absolute path to a project directory or manifest file. Must be inside the configured audit roots."),
			mcp.Required(),
		),
		mcp.WithNumber("max_components",
			mcp.Description("Maximum components to submit to the NVD (1-200). The public NVD API is rate limited to 5 requests per 30 seconds without a key, so a large inventory takes proportionally longer. Set NVD_API_KEY to raise the limit."),
			mcp.DefaultNumber(40),
		),
		mcp.WithNumber("min_cvss",
			mcp.Description("Only report CVEs at or above this score (0-10)."),
			mcp.DefaultNumber(4.0),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_dependency_audit"

		path, aerr := requireArg(req, "path")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if path == "" {
			return failf(toolName, path, start, "path is required")
		}
		if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
			return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
		}

		maxC := req.GetInt("max_components", 40)
		if maxC < 1 {
			maxC = 1
		}
		if maxC > 200 {
			maxC = 200
		}
		minCVSS := req.GetFloat("min_cvss", 4.0)

		deps, files, truncated, err := buildInventory(path, 64, maxC)
		if err != nil {
			return fail(toolName, path, start, err)
		}
		if len(deps) == 0 {
			return ok(d, toolName, path, start, nil, DepAuditResult{
				Root: path, Manifests: files, Offline: d.Cfg.Policy.Offline,
				Findings:    []DepFinding{},
				NotAudited:  []string{},
				Limitations: []string{"no dependency manifests were found under this path"},
			})
		}

		res := DepAuditResult{
			Root:       path,
			Manifests:  files,
			Components: len(deps),
			Offline:    d.Cfg.Policy.Offline,
			Findings:   []DepFinding{},
			Limitations: []string{
				"CPE matching is exact-string and cannot detect distribution backports; a clean result is not proof of safety",
				"only components with a declared version are correlated; floating or VCS-pinned dependencies are reported as not audited",
			},
		}
		if truncated {
			res.Limitations = append(res.Limitations, "the inventory was truncated, so some components were not analysed")
		}

		if d.Cfg.Policy.Offline {
			res.NotAudited = allNames(deps)
			return ok(d, toolName, path, start, nil, res,
				"offline mode is enabled, so no NVD queries were made; every component is listed as not audited")
		}

		// Only components with a version can be correlated.
		var auditable []dependency
		for _, dep := range deps {
			if dep.Version != "" {
				auditable = append(auditable, dep)
			} else {
				res.NotAudited = append(res.NotAudited, dep.Name)
			}
		}
		if len(auditable) > maxC {
			res.NotAudited = append(res.NotAudited, namesOf(auditable[maxC:])...)
			auditable = auditable[:maxC]
		}

		for _, dep := range auditable {
			// queryNVD applies the shared rate limiter, so there is no second
			// throttle here; a cancelled context propagates as a query error.
			if err := ctx.Err(); err != nil {
				res.NotAudited = append(res.NotAudited, namesOf(auditable)...)
				return ok(d, toolName, path, start, nil, res, "the audit was cancelled before every component could be queried")
			}
			res.Audited++

			cves, qerr := nvdKeywordSearch(ctx, d, dep.Name, minCVSS)
			if qerr != nil {
				res.NotAudited = append(res.NotAudited, dep.Name+" ("+qerr.Error()+")")
				continue
			}
			for _, c := range cves {
				if !versionMatchesRange(c, dep.Version) {
					continue
				}
				f := DepFinding{
					Package:   dep.Name,
					Version:   dep.Version,
					Ecosystem: dep.Ecosystem,
					Manifest:  dep.Manifest,
					CVE:       c.ID,
					CVSS:      c.CVSS,
					Severity:  c.Severity,
					Summary:   collapse(c.Description),
					Exploited: len(c.ExploitRefs) > 0,
					Remediate: remediationHint(c),
				}
				f.Confidence, f.MatchBasis = matchConfidence(c, dep.Version)
				res.Findings = append(res.Findings, f)
				switch {
				case c.CVSS >= 9.0:
					res.Critical++
				case c.CVSS >= 7.0:
					res.High++
				}
			}
		}

		sort.Slice(res.Findings, func(i, j int) bool {
			if res.Findings[i].CVSS != res.Findings[j].CVSS {
				return res.Findings[i].CVSS > res.Findings[j].CVSS
			}
			return res.Findings[i].Package < res.Findings[j].Package
		})
		if n := len(res.Findings); n > 0 {
			seen := map[string]bool{}
			for _, f := range res.Findings {
				if !seen[f.Package] {
					seen[f.Package] = true
					res.Vulnerable++
				}
			}
		}
		return ok(d, toolName, path, start, nil, res)
	}

	return Tool{Tool: t, Handler: h}
}

// nvdKeywordSearch runs one rate-limited NVD keyword query and returns the
// matching CVEs at or above minCVSS.
func nvdKeywordSearch(ctx context.Context, d Deps, keyword string, minCVSS float64) ([]CVEDetail, error) {
	kw := strings.TrimSpace(keyword)
	if kw == "" {
		return nil, fmt.Errorf("empty search keyword")
	}
	q := url.Values{"keywordSearch": {kw}, "resultsPerPage": {"40"}}
	recs, err := queryNVD(d, ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]CVEDetail, 0, len(recs))
	for _, r := range recs {
		c, err := adaptCVE(r)
		if err != nil {
			// A keyword hit with an unreadable record is not evidence either way.
			continue
		}
		if minCVSS > 0 && c.CVSS < minCVSS {
			continue
		}
		// A keyword hit is only meaningful if the keyword really is in the
		// record; NVD occasionally returns loosely-related rows.
		if !strings.Contains(strings.ToLower(c.ID+" "+c.Description), strings.ToLower(kw)) &&
			!anyProductMentions(c.Products, kw) {
			continue
		}
		out = append(out, c)
	}
	sortBySeverity(out)
	return out, nil
}

// anyProductMentions reports whether any CPE names the keyword.
func anyProductMentions(products []string, keyword string) bool {
	k := strings.ToLower(strings.ReplaceAll(keyword, "_", ""))
	for _, p := range products {
		parts := strings.Split(strings.ToLower(p), ":")
		for _, seg := range parts {
			if strings.ReplaceAll(seg, "_", "") == k {
				return true
			}
		}
	}
	return false
}

func allNames(deps []dependency) []string { return namesOf(deps) }

func namesOf(deps []dependency) []string {
	out := make([]string, 0, len(deps))
	for _, d := range deps {
		label := d.Name
		if d.Version != "" {
			label += "@" + d.Version
		}
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

// versionMatchesRange decides whether a reported affected-version range really
// covers the pinned version. NVD ranges arrive as CPE version strings that may
// be a specific version, a comparison like ">=1.0 <1.2", or "*" (all versions).
func versionMatchesRange(c CVEDetail, pinned string) bool {
	// A record with no CPE data at all cannot be version-checked, so the
	// product-name hit is reported at low confidence rather than dropped.
	if len(c.Products) == 0 {
		return true
	}
	for _, p := range c.Products {
		v := cpeVersion(p)
		if v == "" || v == "*" {
			return true
		}
		if inVersionRange(pinned, v) {
			return true
		}
	}
	return false
}

// cpeVersion pulls the version field out of a CPE 2.3 string:
// cpe:2.3:a:vendor:product:1.2:*:*:*:*:*:*:* -> 1.2
func cpeVersion(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[5]
}

// reVersionBound matches one comparison term in an NVD version range.
var reVersionBound = regexp.MustCompile(`(>=|<=|>|<|=)?\s*([0-9][0-9A-Za-z.\-+]*)`)

func inVersionRange(version, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return true
	}
	// Some CPE ranges are already prefixed with the comparison, others are
	// bare versions meaning "this version exactly".
	if !strings.ContainsAny(spec, "<>") {
		return looseVersionEqual(version, spec)
	}
	for _, term := range strings.Fields(spec) {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		m := reVersionBound.FindStringSubmatch(term)
		if m == nil {
			continue
		}
		op, bound := m[1], m[2]
		if bound == "" {
			continue
		}
		cmp := compareVersions(version, bound)
		switch op {
		case ">=":
			if cmp < 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case ">":
			if cmp <= 0 {
				return false
			}
		case "<":
			if cmp >= 0 {
				return false
			}
		case "=":
			if cmp != 0 {
				return false
			}
		}
	}
	return true
}

func looseVersionEqual(a, b string) bool {
	return compareVersions(strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")) == 0
}

// compareVersions does a numeric-segment comparison, which handles the
// overwhelmingly common case (1.2.3 < 1.10.0) without a full semver
// implementation. Non-numeric suffixes are compared lexically.
// compareVersions orders two version strings. A purely numeric pair is compared
// segment by segment with absent segments read as zero, so that "1.24" and
// "1.24.0" are equal: that is how distributions actually number the same
// release, and treating the missing tail as "less than" made nginx 1.24.0 fall
// below a range ending at 1.24.0. A version carrying a non-numeric tag (rc,
// beta) is ordered lexically per segment instead, since zero-padding it would
// turn "1.0" into a later release than "1.0rc1".
func compareVersions(a, b string) int {
	as, bs := splitVersion(a), splitVersion(b)
	if na, ok := numericSegments(as); ok {
		if nb, ok2 := numericSegments(bs); ok2 {
			return compareInts(na, nb)
		}
	}
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x == y {
			continue
		}
		if x < y {
			return -1
		}
		return 1
	}
	return 0
}

// numericSegments converts each dot-separated segment to an int, reporting false
// if any segment is present but not a number.
func numericSegments(parts []string) ([]int, bool) {
	out := make([]int, len(parts))
	for i, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func compareInts(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Cut off pre-release/build metadata for the numeric comparison.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '_' || r == '~' || r == '-'
	})
}

// matchConfidence rates how much weight to put on a CPE hit. NVD keyword
// search is fuzzy, so a match on the product name alone is a lead, not a
// conclusion; a match that also pinned the version is stronger.
func matchConfidence(c CVEDetail, pinned string) (confidence, basis string) {
	if len(c.Products) == 0 {
		return "low", "the NVD record carries no CPE version data, so this matched on product name alone"
	}
	for _, p := range c.Products {
		if cpeVersion(p) == pinned {
			return "high", "the NVD record names this exact version as affected"
		}
	}
	return "medium", "the pinned version falls inside the NVD record's affected version range"
}
