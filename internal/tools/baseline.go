package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// Baselines
//
// A one-off assessment produces a list. An assessment programme produces the
// same list again next week, and the only question that matters is what
// changed. That is the workflow this supports: save today's findings, and a
// later run reports what is new, what is still open, and what has been fixed.
//
// Two things it deliberately does not do. It does not silently treat a finding
// as fixed because the tool stopped reporting it — that may mean the service
// went away, the scan was narrower, or the tool changed. It says which of those
// it cannot distinguish. And it stores a fingerprint, not the evidence, so a
// baseline on disk does not become a second copy of everything the assessment
// found.
// ---------------------------------------------------------------------------

// baselineFinding is what gets stored. Evidence is deliberately excluded: it is
// the largest and most target-specific part, and a baseline that accumulates
// full responses becomes a file worth stealing.
type baselineFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title,omitempty"`
	Location    string `json:"location,omitempty"`
	Port        int    `json:"port,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// baselineDoc is the on-disk format.
type baselineDoc struct {
	Version  int               `json:"version"`
	Tool     string            `json:"tool"`
	Target   string            `json:"target"`
	Created  string            `json:"created"`
	Findings []baselineFinding `json:"findings"`
	Note     string            `json:"note,omitempty"`
}

// findingFingerprint identifies a finding across runs. It deliberately excludes
// severity and title: a finding that gets re-rated, or retitled by a tool
// update, is the same finding. Including either would report every re-rating
// as a fix plus a new finding.
func findingFingerprint(ruleID, location string, port int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", normalizeRuleID(ruleID), strings.ToLower(strings.TrimSpace(location)), port)))
	return hex.EncodeToString(h[:])[:16]
}

var baselineIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// baselineRoot is where baselines live. Under the user's config directory
// rather than the working directory, so the file does not end up committed
// alongside whatever was being assessed.
func baselineRoot() string {
	if v := os.Getenv("SENTINELX_BASELINE_DIR"); v != "" {
		return v
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "sentinel-x", "baselines")
	}
	return filepath.Join(base, "sentinel-x", "baselines")
}

func baselinePath(id string) (string, error) {
	// The id becomes a filename, so it is validated rather than sanitised. A
	// baseline id is chosen by a model, and "../../etc/passwd" has no business
	// resolving to anything.
	if !baselineIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid baseline id %q: use letters, digits, dot, dash and underscore, starting with a letter or digit, up to 64 characters", id)
	}
	return filepath.Join(baselineRoot(), id+".json"), nil
}

func readBaseline(id string) (baselineDoc, error) {
	p, err := baselinePath(id)
	if err != nil {
		return baselineDoc{}, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return baselineDoc{}, fmt.Errorf("no baseline %q: %w", id, err)
	}
	var doc baselineDoc
	if json.Unmarshal(raw, &doc) != nil {
		return baselineDoc{}, fmt.Errorf("baseline %s is not readable; it may be truncated or hand-edited", p)
	}
	return doc, nil
}

func writeBaseline(doc baselineDoc) (string, error) {
	p, err := baselinePath(doc.Target)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", fmt.Errorf("cannot create the baseline directory: %w", err)
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(p, append(body, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("cannot write the baseline: %w", err)
	}
	abs, _ := filepath.Abs(p)
	return abs, nil
}

// diffBaselines compares two sets of findings.
type diffBuckets struct {
	New          []sarifFinding   `json:"new"`
	Resolved     []sarifFinding   `json:"resolved"`
	Open         []sarifFinding   `json:"open"`
	Reclassified []severityChange `json:"reclassified"`
}

// severityChange is a finding that is still present but has been re-rated. It is
// not a new finding and not a fix, which is why it gets its own bucket.
type severityChange struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Location    string `json:"location,omitempty"`
	Port        int    `json:"port,omitempty"`
	From        string `json:"from"`
	To          string `json:"to"`
	Direction   string `json:"direction"`
}

func diffFindings(current, previous []sarifFinding) diffBuckets {
	prevFP := map[string]sarifFinding{}
	for _, f := range previous {
		prevFP[findingFingerprint(f.RuleID, f.Location, f.Port)] = f
	}
	curFP := map[string]sarifFinding{}
	for _, f := range current {
		curFP[findingFingerprint(f.RuleID, f.Location, f.Port)] = f
	}
	out := diffBuckets{New: []sarifFinding{}, Resolved: []sarifFinding{}, Open: []sarifFinding{}, Reclassified: []severityChange{}}
	for _, f := range current {
		fp := findingFingerprint(f.RuleID, f.Location, f.Port)
		curFP[fp] = f
		old, wasThere := prevFP[fp]
		switch {
		case !wasThere:
			out.New = append(out.New, f)
		case severityRank(f.Severity) != severityRank(old.Severity):
			dir := "changed"
			if severityRank(f.Severity) > severityRank(old.Severity) {
				dir = "worsened"
			} else {
				dir = "improved"
			}
			out.Reclassified = append(out.Reclassified, severityChange{
				Fingerprint: fp, RuleID: normalizeRuleID(f.RuleID), Location: f.Location, Port: f.Port,
				From: old.Severity, To: f.Severity, Direction: dir,
			})
			out.Open = append(out.Open, f)
		default:
			out.Open = append(out.Open, f)
		}
	}
	for fp, f := range prevFP {
		if _, stillThere := curFP[fp]; !stillThere {
			out.Resolved = append(out.Resolved, f)
		}
	}
	return out
}

func sortFindings(fs []sarifFinding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := severityRank(fs[i].Severity), severityRank(fs[j].Severity); ri != rj {
			return ri > rj
		}
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		return fs[i].Location < fs[j].Location
	})
}

// diffData is the tool payload.
type diffData struct {
	Status         string           `json:"status"`
	BaselineID     string           `json:"baseline_id"`
	BaselinePath   string           `json:"baseline_path,omitempty"`
	BaselineAge    string           `json:"baseline_age,omitempty"`
	Target         string           `json:"target,omitempty"`
	Current        int              `json:"current_findings"`
	Previous       int              `json:"previous_findings"`
	New            []sarifFinding   `json:"new"`
	Resolved       []sarifFinding   `json:"resolved"`
	Open           []sarifFinding   `json:"open"`
	Reclassified   []severityChange `json:"reclassified"`
	Interpretation string           `json:"interpretation"`
	Caveats        []string         `json:"caveats,omitempty"`
	Note           string           `json:"note,omitempty"`
}

func baselineTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_baseline",
		mcp.WithDescription(
			"Save this assessment's findings as a named baseline, or compare the current findings against a "+
				"saved one and report what is new, what is still open, and what no longer appears.\n\n"+
				"Use `action: \"save\"` to record a baseline after an assessment, and `action: \"diff\"` on a "+
				"later run to see the change. A programme that assesses weekly needs this: the useful question "+
				"is not what is wrong now, it is what changed since last time.\n\n"+
				"STRICTLY LOCAL: baselines store a fingerprint, a rule id, a location and a severity. They do "+
				"not store evidence or responses, so a baseline is not a second copy of everything the "+
				"assessment found. They are written under the user config directory with owner-only "+
				"permissions, and can be redirected with SENTINELX_BASELINE_DIR.\n\n"+
				"A finding that stops appearing is reported as resolved, but that word is doing real work: it "+
				"cannot distinguish \"fixed\" from \"service gone\", \"scan covered less\" and \"tool changed\". "+
				"The response lists those caveats. Confirm a resolution before reporting it as fixed.",
		),
		mcp.WithString("action",
			mcp.Required(),
			mcp.Description("`save` to record the current findings as a baseline, `diff` to compare against one."),
			mcp.Enum("save", "diff"),
		),
		mcp.WithString("baseline_id",
			mcp.Description("Name for the baseline. Letters, digits, dot, dash and underscore; it becomes a filename, so it is validated rather than sanitised."),
		),
		mcp.WithArray("findings",
			mcp.Description("The findings to save or compare. Each item: rule_id, title, severity, location, port, evidence, confidence."),
			mcp.Items(map[string]any{}),
		),
		mcp.WithString("findings_file",
			mcp.Description("Path to a JSON file of findings, as an alternative to passing them inline."),
		),
		mcp.WithString("target",
			mcp.Description("What was assessed. Recorded with the baseline so a diff is not compared against the wrong host."),
		),
	)
	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_baseline"
		action := strings.ToLower(strings.TrimSpace(req.GetString("action", "")))
		id := strings.TrimSpace(req.GetString("baseline_id", ""))
		if action == "" {
			return failf(toolName, id, start, "action is required: pass \"save\" or \"diff\"")
		}
		if id == "" {
			id = strings.TrimSpace(req.GetString("target", ""))
		}
		if id == "" {
			return failf(toolName, "", start,
				"baseline_id is required (or target, which is used as the name). A baseline needs a stable name "+
					"so a later run can find it")
		}
		if _, err := baselinePath(id); err != nil {
			return fail(toolName, id, start, err)
		}

		findings, err := collectFindings(req)
		if err != nil {
			return fail(toolName, id, start, err)
		}
		if len(findings) == 0 {
			return failf(toolName, id, start,
				"no findings supplied. This tool records findings that already exist; it does not scan")
		}
		sortFindings(findings)

		if action == "save" {
			doc := baselineDoc{
				Version: 1, Tool: "SENTINEL-X", Target: id, Created: now(),
				Findings: toBaselineFindings(findings),
				Note:     "Fingerprints only; evidence is not stored.",
			}
			p, werr := writeBaseline(doc)
			if werr != nil {
				return fail(toolName, id, start, werr)
			}
			return ok(d, toolName, id, start, nil, map[string]any{
				"status":        "saved",
				"baseline_id":   id,
				"baseline_path": p,
				"findings":      len(doc.Findings),
				"by_severity":   severityCounts(findings),
				"note":          "This overwrote any existing baseline with this name. Use a new name to keep both.",
			})
		}

		prev, err := readBaseline(id)
		if err != nil {
			return fail(toolName, id, start, err)
		}
		prevFindings := fromBaselineFindings(prev)
		b := diffFindings(findings, prevFindings)
		age := ""
		if t, terr := time.Parse(time.RFC3339, prev.Created); terr == nil {
			age = humanAge(time.Since(t))
		}
		data := diffData{
			Status: "ok", BaselineID: id, BaselinePath: prevBaselinePath(prev), BaselineAge: age,
			Target: prev.Target, Current: len(findings), Previous: len(prevFindings),
			New: b.New, Resolved: b.Resolved, Open: b.Open, Reclassified: b.Reclassified,
		}
		if data.New == nil {
			data.New = []sarifFinding{}
		}
		if data.Resolved == nil {
			data.Resolved = []sarifFinding{}
		}
		if data.Open == nil {
			data.Open = []sarifFinding{}
		}
		if data.Reclassified == nil {
			data.Reclassified = []severityChange{}
		}
		data.Interpretation = diffInterpretation(data)
		data.Caveats = resolutionCaveats()
		return ok(d, toolName, id, start, nil, data)
	}
	return Tool{Tool: t, Handler: h}
}

func prevBaselinePath(doc baselineDoc) string {
	p, err := baselinePath(doc.Target)
	if err != nil {
		return ""
	}
	abs, _ := filepath.Abs(p)
	return abs
}

func toBaselineFindings(fs []sarifFinding) []baselineFinding {
	out := make([]baselineFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, baselineFinding{
			RuleID:      normalizeRuleID(f.RuleID),
			Severity:    fallback(f.Severity, "unknown"),
			Title:       f.Title,
			Location:    f.Location,
			Port:        f.Port,
			Confidence:  f.Confidence,
			Fingerprint: findingFingerprint(f.RuleID, f.Location, f.Port),
		})
	}
	return out
}

func fromBaselineFindings(doc baselineDoc) []sarifFinding {
	out := make([]sarifFinding, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		out = append(out, sarifFinding{
			RuleID: f.RuleID, Severity: f.Severity, Title: f.Title,
			Location: f.Location, Port: f.Port, Confidence: f.Confidence,
		})
	}
	return out
}

func severityCounts(fs []sarifFinding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[fallback(f.Severity, "unknown")]++
	}
	return out
}

// collectFindings reads findings from either the inline array or a file, shared
// with the SARIF tool.
func collectFindings(req mcp.CallToolRequest) ([]sarifFinding, error) {
	out := []sarifFinding{}
	if raw, present := req.GetArguments()["findings"]; present && raw != nil {
		arr, isArr := raw.([]any)
		if !isArr {
			return nil, fmt.Errorf("findings must be an array of objects, got %T", raw)
		}
		for i, item := range arr {
			m, isMap := item.(map[string]any)
			if !isMap {
				return nil, fmt.Errorf("findings[%d] is %T, not an object", i, item)
			}
			out = append(out, findingFromMap(m))
		}
	}
	if p := strings.TrimSpace(req.GetString("findings_file", "")); p != "" {
		loaded, err := loadFindingsFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, loaded...)
	}
	return out, nil
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// diffInterpretation leads with what changed, because a count of what is
// currently open is the number the reader already has.
func diffInterpretation(d diffData) string {
	worse, better := 0, 0
	for _, r := range d.Reclassified {
		switch r.Direction {
		case "worsened":
			worse++
		case "improved":
			better++
		}
	}
	switch {
	case len(d.New) == 0 && len(d.Resolved) == 0 && len(d.Reclassified) == 0:
		return fmt.Sprintf(
			"Nothing changed since the baseline %s ago: %d findings, all still open, none new, none gone. "+
				"Identical counts can still hide a swapped finding, so this is a real but weak signal.",
			d.BaselineAge, d.Current)
	case len(d.New) == 0 && len(d.Resolved) > 0:
		return fmt.Sprintf(
			"Nothing new. %d previously reported findings no longer appear. Confirm each one before calling "+
				"it fixed: a service that is down, a narrower scan, or a changed tool all produce the same "+
				"result as a genuine fix.", len(d.Resolved))
	case len(d.New) > 0 && len(d.Resolved) == 0:
		return fmt.Sprintf(
			"%d new findings and nothing resolved. New findings appear when coverage grows as often as when "+
				"the target changes, so check whether the scan was wider this time before treating these as "+
				"regressions.", len(d.New))
	default:
		return fmt.Sprintf(
			"%d new, %d no longer reported, %d still open, %d re-rated (%d worse, %d better).",
			len(d.New), len(d.Resolved), len(d.Open), len(d.Reclassified), worse, better)
	}
}

// resolutionCaveats is returned with every diff. The word "resolved" in a diff
// is an inference, and a reader who does not know that will report fixes that
// did not happen.
func resolutionCaveats() []string {
	return []string{
		"A finding that no longer appears was NOT verified as fixed. This tool compares what was reported, and cannot distinguish a genuine fix from: the service being removed or down, the scan covering fewer hosts or ports this time, an authenticated check failing and being skipped, or the detecting tool having changed its behaviour.",
		"New findings can come from wider coverage rather than a change in the target. Compare scope before calling them regressions.",
		"Fingerprints ignore severity and title, so a finding that was only re-rated appears as still open, not as a new finding plus a resolved one.",
	}
}
