package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// nucleiPassiveTags is the observation-only tag set.
//
// The classification is an allowlist, not a denylist, on purpose. A denylist
// of "bad" tags would silently start permitting every tag nuclei adds in a
// future release, so an upgrade could turn a passive scan into an RCE scan
// without anyone changing a setting. Treating anything unrecognised as active
// makes new tags fail closed instead.
var nucleiPassiveTags = []string{
	"exposure",
	"misconfiguration",
	"technologies",
	"ssl",
	"dns",
}

// Active is the group of tools that may, depending on how they are called,
// send more than observation traffic. They are kept in their own group so the
// read-only groups above them stay true by construction rather than by
// convention.
func Active(d Deps) []Tool {
	return []Tool{
		nucleiScanTool(d),
	}
}

// nucleiTagIsPassive reports whether every requested tag is in the
// observation-only set.
func nucleiTagIsPassive(tags []string) (bool, []string) {
	var active []string
	for _, t := range tags {
		ok := false
		for _, p := range nucleiPassiveTags {
			if strings.EqualFold(t, p) {
				ok = true
				break
			}
		}
		if !ok {
			active = append(active, t)
		}
	}
	return len(active) == 0, active
}

// NucleiFinding is one matched template.
type NucleiFinding struct {
	TemplateID     string   `json:"template_id"`
	Name           string   `json:"name,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Type           string   `json:"type,omitempty"`
	Host           string   `json:"host,omitempty"`
	MatchedAt      string   `json:"matched_at,omitempty"`
	Matcher        string   `json:"matcher,omitempty"`
	Extracted      []string `json:"extracted,omitempty"`
	Classification string   `json:"classification,omitempty"`
}

type NucleiResult struct {
	Targets        []string        `json:"targets"`
	TagsUsed       []string        `json:"tags_used"`
	SeverityFilter []string        `json:"severity_filter,omitempty"`
	Traffic        string          `json:"traffic_class"`
	Note           string          `json:"note"`
	Findings       []NucleiFinding `json:"findings"`
	Count          int             `json:"findings_count"`
	BySeverity     map[string]int  `json:"by_severity"`
	Elapsed        float64         `json:"elapsed_seconds"`
	RawLines       int             `json:"result_lines_parsed"`
	Unparsed       int             `json:"result_lines_unparsed"`
}

// nucleiResultLine mirrors the subset of nuclei's JSONL output that is worth
// reporting. Fields not decoded here are ignored rather than guessed at.
type nucleiResultLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification struct {
			CVEID []string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
}

func nucleiScanTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_nuclei_scan",
		mcp.WithDescription(
			"Run ProjectDiscovery nuclei against in-scope targets and report matched templates: id, "+
				"name, severity, matched location and any extracted values. Requires the nuclei binary "+
				"and explicit operator opt-in (SENTINELX_ALLOWED_BINARIES=nuclei), because nuclei can be "+
				"directed to send exploit traffic and it downloads templates on first run. "+
				"By default only observation tags run: exposure, misconfiguration, technologies, ssl, "+
				"dns. Any other tag — cve, rce, fuzzing, dos, intrusive — requires allow_active_templates "+
				"and changes traffic_class to 'attack'. Note that -severity does NOT restrict this: a "+
				"critical-only run still executes RCE templates, which is why the gate is on tags and not "+
				"on severity. This tool is not read-only when active tags are enabled and does not "+
				"advertise the read-only annotation.",
		),
		mcp.WithToolTitle("SENTINEL-X Nuclei Template Scan"),
		mcp.WithString("targets",
			mcp.Description("Comma-separated in-scope URLs or hosts. Every one is scope-checked before nuclei starts."),
			mcp.Required(),
		),
		mcp.WithString("tags",
			mcp.Description("Template tags to run, comma separated. Default 'exposure,misconfiguration,technologies'."),
			mcp.DefaultString("exposure,misconfiguration,technologies"),
		),
		mcp.WithString("severity",
			mcp.Description("Severity filter for reporting only, e.g. 'low,medium,high,critical'. It does not restrict which templates execute."),
			mcp.DefaultString(""),
		),
		mcp.WithBoolean("allow_active_templates",
			mcp.Description("Required to run any tag outside the observation set. Sends attack payloads; the result is labelled traffic_class='attack'."),
			mcp.DefaultBool(false),
		),
		mcp.WithNumber("rate_limit",
			mcp.Description("Requests per second. Default 10, cap 50."),
			mcp.DefaultNumber(10),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Per-request timeout. Capped by server policy."),
			mcp.DefaultNumber(0),
		),
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_nuclei_scan"

		raw, aerr := requireArg(req, "targets")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if d.Cfg.Policy.Offline {
			return failf(toolName, raw, start, "network access is disabled (SENTINELX_OFFLINE=true)")
		}
		bin, err := requireBinary(d, "nuclei")
		if err != nil {
			return fail(toolName, raw, start, err)
		}

		targets := splitTargetList(raw)
		if len(targets) == 0 {
			return failf(toolName, raw, start, "targets is required")
		}

		// Scope-check every target before the process starts. nuclei has no
		// notion of authorisation, so this is the only place the decision can
		// be made, and making it here rather than per-match is what prevents a
		// single out-of-scope entry in a list from being scanned at all.
		var inScope []string
		var refused []string
		for _, target := range targets {
			u, err := parseURL(normaliseTarget(target))
			if err != nil {
				refused = append(refused, target+" (not a valid host or URL)")
				continue
			}
			if err := scopeCheck(d, u.host()); err != nil {
				refused = append(refused, target+" (outside the configured scope)")
				continue
			}
			inScope = append(inScope, sanitiseURL(u))
		}
		if len(inScope) == 0 {
			return failf(toolName, raw, start, "no target is in scope; refused: %s", strings.Join(refused, ", "))
		}

		tags := splitTargetList(strings.ToLower(req.GetString("tags", "exposure,misconfiguration,technologies")))
		if len(tags) == 0 {
			tags = []string{"exposure", "misconfiguration", "technologies"}
		}
		passive, active := nucleiTagIsPassive(tags)
		allowActive := req.GetBool("allow_active_templates", false)
		if !passive && !allowActive {
			return failf(toolName, raw, start,
				"tags %s can send attack payloads; pass allow_active_templates=true to run them, "+
					"or use one of the observation tags: %s",
				strings.Join(active, ", "), strings.Join(nucleiPassiveTags, ", "))
		}

		timeout := argTimeout(d, req, d.Cfg.Timeouts.HTTP)
		rl := clampInt(int(req.GetFloat("rate_limit", 10)), 1, 50, 10)

		args := []string{
			"-silent",
			"-jsonl",
			// Never auto-update: it downloads and unpacks template archives,
			// which is a network fetch and a filesystem write this server does
			// not perform on the operator's behalf.
			"-duc",
			"-rate-limit", fmt.Sprint(rl),
			"-timeout", fmt.Sprint(int(timeout.Seconds())),
			"-tags", strings.Join(tags, ","),
			"-target", strings.Join(inScope, ","),
		}
		if sev := splitTargetList(strings.ToLower(req.GetString("severity", ""))); len(sev) > 0 {
			args = append(args, "-severity", strings.Join(sev, ","))
		}

		res := NucleiResult{
			Targets:        inScope,
			TagsUsed:       tags,
			Traffic:        "observation",
			Findings:       []NucleiFinding{},
			BySeverity:     map[string]int{},
			SeverityFilter: splitTargetList(strings.ToLower(req.GetString("severity", ""))),
		}
		if !passive {
			res.Traffic = "attack"
			res.Note = "ACTIVE: templates outside the observation set ran, so attack payloads were sent to " +
				"these targets. A finding here means a template matched, not that exploitation was " +
				"attempted or succeeded; several of these tags send payloads that can alter server state."
		} else {
			res.Note = "Observation templates only. These fetch and compare; they do not send exploit payloads."
		}
		if len(refused) > 0 {
			res.Note += " Refused and not scanned: " + strings.Join(refused, ", ") + "."
		}
		res.Note += " Result count is templates that matched, not the number of templates executed, and " +
			"a match is a heuristic signal rather than proof of exploitability."

		began := time.Now()
		out, _, runErr := d.Runner.RunCombined(ctx, utils.Spec{
			Binary:  bin,
			Args:    args,
			Timeout: timeout + 5*time.Minute,
		})
		res.Elapsed = time.Since(began).Seconds()

		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var rl nucleiResultLine
			if err := json.Unmarshal([]byte(line), &rl); err != nil {
				// A line that is not JSON is nuclei writing something else —
				// a banner, a warning, a stack trace. It is counted rather than
				// dropped, so a run that produced nothing parseable cannot be
				// mistaken for a clean scan.
				res.Unparsed++
				continue
			}
			if rl.TemplateID == "" {
				res.Unparsed++
				continue
			}
			f := NucleiFinding{
				TemplateID:     rl.TemplateID,
				Name:           rl.Info.Name,
				Severity:       strings.ToLower(rl.Info.Severity),
				Type:           rl.Type,
				Host:           rl.Host,
				MatchedAt:      rl.MatchedAt,
				Matcher:        rl.MatcherName,
				Extracted:      rl.ExtractedResults,
				Classification: strings.Join(rl.Info.Classification.CVEID, ", "),
			}
			res.Findings = append(res.Findings, f)
			sev := f.Severity
			if sev == "" {
				sev = "unknown"
			}
			res.BySeverity[sev]++
			res.RawLines++
		}

		// Hostile or simply odd output should not be handed to a model as if
		// it were structured data, so the ordering is made deterministic here.
		sort.SliceStable(res.Findings, func(i, j int) bool {
			a, b := res.Findings[i], res.Findings[j]
			if a.Severity != b.Severity {
				return severityRank(a.Severity) > severityRank(b.Severity)
			}
			return a.TemplateID < b.TemplateID
		})
		res.Count = len(res.Findings)

		if runErr != nil && res.Count == 0 {
			return fail(toolName, strings.Join(inScope, ", "), start,
				fmt.Errorf("nuclei produced no parseable results: %w", translateExec(runErr)))
		}
		if res.Unparsed > 0 && res.Count == 0 {
			return failf(toolName, strings.Join(inScope, ", "), start,
				"nuclei wrote %d lines but none were parseable results; a run that cannot be parsed "+
					"must not be reported as clean", res.Unparsed)
		}
		return ok(d, toolName, strings.Join(inScope, ", "), start, nil, res)
	}

	return Tool{Tool: t, Handler: h}
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "informative":
		return 1
	default:
		return 0
	}
}
