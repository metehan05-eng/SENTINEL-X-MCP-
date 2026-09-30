package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// SARIF 2.1.0
//
// Every tool here returns bespoke JSON shaped for a model to read. That is the
// right shape for the model and the wrong shape for everything else: GitHub
// code scanning, GitLab, Azure DevOps and most CI systems all read SARIF, and
// none of them read ours. Without it a result has to be re-typed by hand before
// it can appear in a pipeline, which is the step people skip.
//
// SARIF is also where the distinction between "a finding" and "a hypothesis"
// gets made explicit. A rule can carry a default severity, an individual result
// can override it, and every result can carry its own properties — which is
// where the evidence and the confidence live.
// ---------------------------------------------------------------------------

const sarifVersion = "2.1.0"
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// sarifFinding is one reported problem, in SENTINEL-X's own vocabulary.
type sarifFinding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Evidence    string         `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Confidence  string         `json:"confidence,omitempty"`
	Location    string         `json:"location,omitempty"`
	Port        int            `json:"port,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifRuleDesc struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription sarifRuleDesc      `json:"shortDescription"`
	FullDescription  sarifRuleDesc      `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifRuleDefault  `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any     `json:"properties,omitempty"`
	Help             *sarifRuleHelpText `json:"help,omitempty"`
}

type sarifRuleDefault struct {
	Level sarifLevel `json:"level"`
}

type sarifRuleHelpText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifLogicalLocation struct {
	Name           string `json:"name"`
	FullyQualified string `json:"fullyQualifiedName,omitempty"`
	Kind           string `json:"kind,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifRuleDesc   `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifLevels maps SENTINEL-X severities onto SARIF's four. SARIF has no
// "informational" and no "unknown", and guessing upward would inflate every
// report this produces.
var sarifLevels = map[string]struct {
	level   string
	rank    int
	comment string
}{
	"critical": {"error", 5, "directly exploitable with severe impact"},
	"high":     {"error", 4, "exploitable with significant impact"},
	"medium":   {"warning", 3, "real risk, but exploitation is constrained"},
	"low":      {"note", 2, "hardening gap or weak configuration"},
	"info":     {"note", 1, "informational"},
	"unknown":  {"note", 0, "severity could not be established"},
}

var severityOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

// levelFor maps a severity to a SARIF level, defaulting to the most cautious
// level rather than the most alarming one.
func levelFor(sev string) (string, int) {
	if m, ok := sarifLevels[strings.ToLower(strings.TrimSpace(sev))]; ok {
		return m.level, m.rank
	}
	return "note", 0
}

// normalizeRuleID keeps rule ids stable across runs, because a CI system that
// sees the same finding under two rule ids treats it as a new finding and the
// baseline never converges.
func normalizeRuleID(ruleID string) string {
	r := strings.ToLower(strings.TrimSpace(ruleID))
	if r == "" {
		return "sentinelx.unspecified"
	}
	var b strings.Builder
	for _, c := range r {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteRune('.')
		}
	}
	return strings.Trim(b.String(), ".")
}

// findingMessage is what a human reads in the CI annotation. It leads with the
// evidence rather than the category, because "TLS: missing HSTS" tells nobody
// whether to act today and "no Strict-Transport-Security header" does.
func findingMessage(f sarifFinding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	if f.Evidence != "" {
		fmt.Fprintf(&b, " — %s", truncate(f.Evidence, 300))
	}
	if f.Confidence != "" {
		fmt.Fprintf(&b, " (confidence: %s)", f.Confidence)
	}
	return b.String()
}

func sarifLocationFor(f sarifFinding) []sarifLocation {
	out := []sarifLocation{}
	if f.Location != "" {
		out = append(out, sarifLocation{
			PhysicalLocation: &sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: f.Location},
			},
		})
	}
	if f.Port > 0 {
		out = append(out, sarifLocation{
			LogicalLocations: []sarifLogicalLocation{{
				Name:           fmt.Sprintf("port/%d", f.Port),
				FullyQualified: fmt.Sprintf("tcp://%s:%d", f.Location, f.Port),
				Kind:           "resource",
			}},
		})
	}
	return out
}

// ruleFor emits one driver rule per distinct rule id, with a default level
// taken from the most severe finding that uses it. A rule's default has to
// exist even when every result also carries an explicit level, or consumers
// that honour defaults only will render the file as empty.
func ruleFor(id string, findings []sarifFinding) sarifRule {
	level := "note"
	desc := ""
	best := -1
	title := ""
	for _, f := range findings {
		if rank := severityRank(f.Severity); rank > best {
			best = rank
			level, _ = levelFor(f.Severity)
			desc = f.Title
			title = f.Title
		}
	}
	rule := sarifRule{
		ID:               id,
		Name:             strings.ReplaceAll(id, ".", "_"),
		ShortDescription: sarifRuleDesc{Text: fallback(desc, title, id)},
		DefaultConfig:    &sarifRuleDefault{Level: sarifLevel{Level: level}},
		Properties: map[string]any{
			"tags": []string{"security", "sentinel-x"},
		},
	}
	if best >= 0 {
		if m, ok := sarifLevels[level]; ok {
			rule.FullDescription = sarifRuleDesc{
				Text: fmt.Sprintf("%s. %s.", rule.ShortDescription.Text, m.comment),
			}
		}
	}
	return rule
}

func fallback(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "unspecified"
}

// buildSARIF converts findings into a SARIF document.
func buildSARIF(findings []sarifFinding, toolName, toolVersion, target string) sarifDocument {
	// Deduplicate on rule + location + evidence. The same weakness surfaces
	// from several tools during one assessment, and a SARIF file that repeats
	// it makes the count look like risk.
	seen := map[string]bool{}
	uniq := []sarifFinding{}
	for _, f := range findings {
		key := strings.Join([]string{normalizeRuleID(f.RuleID), f.Location, fmt.Sprint(f.Port), f.Evidence}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		uniq = append(uniq, f)
	}
	// Deterministic order: a SARIF file that reshuffles between runs produces a
	// useless diff and defeats change detection in CI.
	sort.SliceStable(uniq, func(i, j int) bool {
		ri, rj := severityRank(uniq[i].Severity), severityRank(uniq[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if uniq[i].RuleID != uniq[j].RuleID {
			return uniq[i].RuleID < uniq[j].RuleID
		}
		return uniq[i].Location < uniq[j].Location
	})

	byRule := map[string][]sarifFinding{}
	ruleOrder := []string{}
	for _, f := range uniq {
		id := normalizeRuleID(f.RuleID)
		if _, seen := byRule[id]; !seen {
			ruleOrder = append(ruleOrder, id)
		}
		byRule[id] = append(byRule[id], f)
	}
	sort.Strings(ruleOrder)

	results := []sarifResult{}
	for _, f := range uniq {
		level, _ := levelFor(f.Severity)
		props := map[string]any{"severity": fallback(f.Severity, "unknown")}
		if f.Confidence != "" {
			props["confidence"] = f.Confidence
		}
		if f.Remediation != "" {
			props["remediation"] = f.Remediation
		}
		if f.Location != "" {
			props["target"] = f.Location
		}
		if len(f.Properties) > 0 {
			for k, v := range f.Properties {
				props[k] = v
			}
		}
		results = append(results, sarifResult{
			RuleID:     normalizeRuleID(f.RuleID),
			Level:      level,
			Message:    sarifRuleDesc{Text: findingMessage(f)},
			Locations:  sarifLocationFor(f),
			Properties: props,
		})
	}

	rules := []sarifRule{}
	for _, id := range ruleOrder {
		rules = append(rules, ruleFor(id, byRule[id]))
	}

	return sarifDocument{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				Version:        toolVersion,
				InformationURI: "https://github.com/metehan05-eng/SENTINEL-X-MCP-",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

func sarifReportTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_sarif_report",
		mcp.WithDescription(
			"Convert findings from this assessment into a SARIF 2.1.0 document, optionally writing it to "+
				"a file. SARIF is what GitHub code scanning, GitLab, Azure DevOps and most CI systems read, "+
				"so this is how a SENTINEL-X assessment reaches a pipeline without being re-typed by hand.\n\n"+
				"Pass the findings gathered from the other tools, or read a JSON file of them. Duplicate "+
				"findings are collapsed, output is ordered deterministically so a diff between runs is "+
				"meaningful, and rule ids are normalised so the same weakness keeps the same id across runs — "+
				"without that a CI baseline never converges.\n\n"+
				"Severity is mapped to SARIF conservatively: unknown severity becomes `note`, never `error`. "+
				"Every result carries its evidence and confidence as properties, so a consumer can tell a "+
				"confirmed finding from a fingerprint hypothesis.\n\n"+
				"NOTE: an empty results array means no findings were passed in. It is not a statement that the "+
				"target is clean."),
		mcp.WithArray("findings",
			mcp.Description("Findings to report. Each item: id, rule_id, title, severity (critical|high|medium|low|info|unknown), evidence, remediation, confidence, location, port."),
			mcp.Items(map[string]any{}),
		),
		mcp.WithString("findings_file",
			mcp.Description("Path to a JSON file containing an array of findings, as an alternative to passing them inline. The file is read and never executed."),
		),
		mcp.WithString("output",
			mcp.Description("Path to write the SARIF document to. When omitted the document is returned inline and nothing is written."),
		),
	)
	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_sarif_report"

		findings := []sarifFinding{}
		// GetStringSlice only handles arrays of strings, and these are objects,
		// so the raw argument map is read directly.
		if raw, present := req.GetArguments()["findings"]; present && raw != nil {
			arr, isArr := raw.([]any)
			if !isArr {
				return failf(toolName, "", start, "findings must be an array of objects, got %T", raw)
			}
			for i, item := range arr {
				m, isMap := item.(map[string]any)
				if !isMap {
					return failf(toolName, "", start, "findings[%d] is %T, not an object", i, item)
				}
				findings = append(findings, findingFromMap(m))
			}
		}
		if path := strings.TrimSpace(req.GetString("findings_file", "")); path != "" {
			loaded, err := loadFindingsFile(path)
			if err != nil {
				return fail(toolName, path, start, err)
			}
			findings = append(findings, loaded...)
		}
		if len(findings) == 0 {
			return failf(toolName, "", start,
				"no findings supplied. This tool converts findings that already exist; it does not scan. "+
					"Run the assessment tools first, or pass findings_file")
		}

		doc := buildSARIF(findings, "SENTINEL-X", "1.0.0", "")
		sum := summariseSARIF(doc)
		sum.Interpretation = sarifInterpretation(sum)

		if out := strings.TrimSpace(req.GetString("output", "")); out != "" {
			written, err := writeSARIF(out, doc)
			if err != nil {
				return fail(toolName, out, start, err)
			}
			sum.Output = written
			sum.Note = "The document was written, not returned inline. Read the file to inspect it."
			return ok(d, toolName, out, start, nil, sum)
		}
		sum.Document = &doc
		return ok(d, toolName, "", start, nil, sum)
	}
	return Tool{Tool: t, Handler: h}
}
