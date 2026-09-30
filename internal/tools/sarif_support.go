package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sarifSummary reports what a SARIF file contains, so a caller that has just
// been handed a path knows whether to read it.
type sarifSummary struct {
	Status         string         `json:"status"`
	Version        string         `json:"sarif_version"`
	Findings       int            `json:"findings"`
	Rules          int            `json:"rules"`
	ByLevel        map[string]int `json:"by_level"`
	BySeverity     map[string]int `json:"by_severity"`
	TopRules       []ruleCount    `json:"top_rules"`
	Output         string         `json:"output,omitempty"`
	Document       *sarifDocument `json:"document,omitempty"`
	Interpretation string         `json:"interpretation"`
	Note           string         `json:"note,omitempty"`
}

type ruleCount struct {
	RuleID   string `json:"rule_id"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

// findingFromMap reads one finding from an untyped tool argument. Callers
// assemble these by hand and from model output, so every field has to be
// tolerated as missing or as the wrong type rather than panicking.
func findingFromMap(m map[string]any) sarifFinding {
	f := sarifFinding{
		RuleID:      str(m["rule_id"]),
		Title:       str(m["title"]),
		Severity:    str(m["severity"]),
		Evidence:    str(m["evidence"]),
		Remediation: str(m["remediation"]),
		Confidence:  str(m["confidence"]),
		Location:    str(m["location"]),
	}
	f.ID = str(m["id"])
	if f.ID == "" {
		f.ID = f.RuleID
	}
	if f.Title == "" {
		// A SARIF result with an empty message renders as a blank annotation,
		// which is worse than useless in a CI comment.
		f.Title = fallback(f.RuleID, f.ID, "unspecified finding")
	}
	if f.RuleID == "" {
		f.RuleID = f.Title
	}
	f.Port = num(m["port"])
	if props, isMap := m["properties"].(map[string]any); isMap {
		f.Properties = props
	}
	return f
}

func str(v any) string {
	if s, isStr := v.(string); isStr {
		return strings.TrimSpace(s)
	}
	return ""
}

func num(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0
		}
		return int(i)
	case string:
		var i int
		if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
			return i
		}
	}
	return 0
}

// loadFindingsFile reads findings from disk. The path is read as data and
// never executed, and a JSON file that is not an array of findings gets a
// clear error rather than an empty result.
func loadFindingsFile(path string) ([]sarifFinding, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read findings file: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("findings_file %s is a directory", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read findings file: %w", err)
	}
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) != nil {
		// Tolerate a wrapper, since that is how several tools emit their output.
		var wrapped struct {
			Findings []map[string]any `json:"findings"`
			Data     []map[string]any `json:"data"`
		}
		if json.Unmarshal(raw, &wrapped) != nil {
			return nil, fmt.Errorf("findings_file %s is not a JSON array of findings", path)
		}
		if len(wrapped.Findings) > 0 {
			arr = wrapped.Findings
		} else {
			arr = wrapped.Data
		}
	}
	out := make([]sarifFinding, 0, len(arr))
	for _, m := range arr {
		out = append(out, findingFromMap(m))
	}
	return out, nil
}

// writeSARIF writes the document, refusing to follow a symlink or clobber
// something that is not a file. A report path usually comes from a model
// suggestion, and quietly overwriting a file is not a thing to do on that
// basis.
func writeSARIF(path string, doc sarifDocument) (string, error) {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing to write through the symlink %s", path)
		}
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("%s exists and is not a regular file", path)
		}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return "", fmt.Errorf("output directory %s does not exist", dir)
		}
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", fmt.Errorf("cannot write %s: %w", path, err)
	}
	abs, _ := filepath.Abs(path)
	return abs, nil
}

func summariseSARIF(doc sarifDocument) sarifSummary {
	s := sarifSummary{
		Status:     "ok",
		Version:    doc.Version,
		Findings:   len(doc.Runs[0].Results),
		Rules:      len(doc.Runs[0].Tool.Driver.Rules),
		ByLevel:    map[string]int{},
		BySeverity: map[string]int{},
	}
	perRule := map[string]int{}
	ruleSeverity := map[string]string{}
	for _, r := range doc.Runs[0].Results {
		s.ByLevel[r.Level]++
		if v, isStr := r.Properties["severity"].(string); isStr && v != "" {
			s.BySeverity[v]++
		}
		perRule[r.RuleID]++
		if v, isStr := r.Properties["severity"].(string); isStr {
			if best, seen := ruleSeverity[r.RuleID]; !seen || severityRank(v) > severityRank(best) {
				ruleSeverity[r.RuleID] = v
			}
		}
	}
	for id, n := range perRule {
		s.TopRules = append(s.TopRules, ruleCount{RuleID: id, Count: n, Severity: ruleSeverity[id]})
	}
	sort.Slice(s.TopRules, func(i, j int) bool {
		if s.TopRules[i].Count != s.TopRules[j].Count {
			return s.TopRules[i].Count > s.TopRules[j].Count
		}
		return s.TopRules[i].RuleID < s.TopRules[j].RuleID
	})
	if len(s.TopRules) > 10 {
		s.TopRules = s.TopRules[:10]
	}
	return s
}

// sarifInterpretation says what the counts mean, in the same spirit as the
// Metasploit tool: a consumer that reads only numbers will read them as a
// risk score, and a count of findings is not one.
func sarifInterpretation(s sarifSummary) string {
	parts := []string{}
	if n := s.BySeverity["critical"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", n))
	}
	if n := s.BySeverity["high"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d high", n))
	}
	if n := s.ByLevel["warning"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", n))
	}
	if n := s.ByLevel["note"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d low or informational", n))
	}
	head := "No findings were supplied."
	if len(parts) > 0 {
		head = fmt.Sprintf("Reported: %s.", strings.Join(parts, ", "))
	}
	return head + " This is a count of distinct findings, not a risk score: severity is as reported by the " +
		"tool that produced each finding, and a fingerprint match is a hypothesis. Read the evidence on each " +
		"result before deciding what to act on."
}
