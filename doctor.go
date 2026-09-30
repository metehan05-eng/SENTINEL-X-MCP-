package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sentinel-x/sentinel-x/internal/config"
	"github.com/sentinel-x/sentinel-x/internal/tools"
	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// toolStatus is the per-tool verdict doctor reports.
type toolStatus struct {
	Tool     string   `json:"tool"`
	Usable   bool     `json:"usable"`
	Needs    []string `json:"needs,omitempty"`
	Missing  []string `json:"missing,omitempty"`
	Degraded string   `json:"degraded,omitempty"`
}

// binaryStatus groups the tools that a single binary would satisfy.
type binaryStatus struct {
	Binary    string   `json:"binary"`
	Installed bool     `json:"installed"`
	Tools     []string `json:"tools,omitempty"`
}

// doctorReport is the machine-readable form of `sentinel-x doctor --json`.
type doctorReport struct {
	Scope         []string        `json:"scope"`
	Enforced      bool            `json:"scope_enforced"`
	ToolsTotal    int             `json:"tools_total"`
	ToolsUsable   int             `json:"tools_usable"`
	ToolsDegraded int             `json:"tools_degraded"`
	ToolsBroken   int             `json:"tools_broken"`
	Binaries      []binaryStatus  `json:"binaries"`
	Tools         []toolStatus    `json:"tools"`
	Notes         []string        `json:"notes,omitempty"`
	Config        map[string]bool `json:"config,omitempty"`
}

// degradedTools maps a tool to the binary whose absence downgrades it, and to
// what is lost. Doctor checks the binary is really missing before printing the
// note: telling an operator "dig not installed" on a machine that has dig is
// how a report section gets learned to be ignored.
var degradedTools = map[string]struct{ bin, note string }{
	"sentinelx_advisory_index": {"searchsploit",
		"falling back to the built-in advisory index, which is smaller and not updated automatically"},
	"sentinelx_subdomain_discovery": {"dig",
		"subdomain reachability cannot be confirmed, so it stays `unknown` instead of resolved"},
	"sentinelx_dns_security_audit": {"dig",
		"DNSSEC delegation checks need a second resolver and are skipped"},
}

func runDoctor(args []string) error {
	for _, a := range args {
		switch a {
		case "--json":
		case "-h", "--help":
			fmt.Println("usage: sentinel-x doctor [--json]")
			fmt.Println()
			fmt.Println("  Reports which tools can actually run here: external binaries")
			fmt.Println("  present, whether scan scope is enforced, and API keys. A tool")
			fmt.Println("  listed as unusable will fail at call time, which is a poor moment")
			fmt.Println("  to find out. Exits non-zero when any tool cannot run.")
			return nil
		default:
			return fmt.Errorf("unknown doctor flag: %s", a)
		}
	}

	cfg, err := config.Get()
	if err != nil {
		return err
	}
	runner, err := utils.NewRunner(cfg)
	if err != nil {
		return err
	}
	deps := tools.Deps{Cfg: cfg, Runner: runner}
	return renderDoctor(args, buildDoctorReport(cfg, runner, tools.AllTools(deps)))
}

// buildDoctorReport is separate from runDoctor so the classification can be
// tested against a chosen config. config.Get() caches for the life of the
// process, so a test that sets an env var and then calls the CLI is really
// testing whichever test happened to run first.
func buildDoctorReport(cfg *config.Config, runner *utils.Runner, all []tools.Tool) doctorReport {
	report := doctorReport{
		Scope:    cfg.Policy.ScopeTargets,
		Enforced: cfg.Policy.EnforceScope,
		Config:   map[string]bool{},
	}

	// Probe each distinct binary once, then fan the answer out to the tools
	// that accept it. Thirteen probes instead of twenty-five tool checks.
	byBinary := map[string][]string{}
	for _, t := range all {
		for _, b := range t.Requires {
			byBinary[b] = append(byBinary[b], t.Tool.Name)
		}
	}
	names := make([]string, 0, len(byBinary))
	for b := range byBinary {
		names = append(names, b)
	}
	sort.Strings(names)

	installed := map[string]bool{}
	for _, b := range names {
		ok, _ := runner.Available(b)
		installed[b] = ok
		report.Binaries = append(report.Binaries, binaryStatus{
			Binary: b, Installed: ok, Tools: byBinary[b],
		})
	}

	for _, t := range all {
		st := toolStatus{Tool: t.Tool.Name, Usable: true, Needs: t.Requires}
		if len(t.Requires) > 0 {
			// requireBinary takes whichever candidate resolves first, so any
			// one of them is enough.
			for _, b := range t.Requires {
				if installed[b] {
					st.Usable = true
					break
				}
				st.Missing = append(st.Missing, b)
			}
		}
		if dg, ok := degradedTools[t.Tool.Name]; ok && !installed[dg.bin] {
			st.Degraded = dg.note
		}
		switch {
		case !st.Usable:
			report.ToolsBroken++
		case st.Degraded != "":
			report.ToolsDegraded++
		default:
			report.ToolsUsable++
		}
		report.Tools = append(report.Tools, st)
	}
	report.ToolsTotal = len(all)

	// An NVD key is optional: without it, lookups still work but are rate
	// limited, so this is a note rather than a broken tool.
	if cfg.NVDAPIKey == "" {
		report.Notes = append(report.Notes,
			"NVD_API_KEY is not set; CVE lookups fall back to unauthenticated NVD requests, which are rate limited")
	} else {
		report.Config["nvd_api_key"] = true
	}

	// An empty scope does not mean "nothing is allowed" — it means enforcement
	// is off and every target is accepted with a warning on the result.
	// Describing it as refusing everything would be the worst possible lie here.
	if !cfg.Policy.EnforceScope {
		report.Notes = append(report.Notes,
			"SCOPE IS NOT ENFORCED: no scope targets configured, so every target is accepted and results carry a warning. Set SENTINELX_SCOPE_TARGETS to the hosts you are authorised to assess before scanning third parties")
	}
	if os.Geteuid() == 0 {
		report.Notes = append(report.Notes,
			"running as root; raw sockets and SYN scans work, but every result should be double-checked for scope mistakes")
	}
	return report
}

func renderDoctor(args []string, report doctorReport) error {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printDoctor(report)
	}
	if report.ToolsBroken > 0 {
		return fmt.Errorf("%d tool(s) cannot run on this machine", report.ToolsBroken)
	}
	return nil
}

func printDoctor(r doctorReport) {
	fmt.Println("SENTINEL-X doctor")
	fmt.Println()
	fmt.Printf("  tools        %d total, %d ready, %d degraded, %d broken\n",
		r.ToolsTotal, r.ToolsUsable, r.ToolsDegraded, r.ToolsBroken)
	if !r.Enforced {
		fmt.Println("  scope        NOT ENFORCED — every target is accepted")
	} else {
		fmt.Printf("  scope        enforced: %s\n", strings.Join(r.Scope, ", "))
	}
	fmt.Println()

	fmt.Println("  external binaries")
	for _, b := range r.Binaries {
		mark := "missing"
		if b.Installed {
			mark = "ok"
		}
		fmt.Printf("    %-8s %-12s %s\n", mark, b.Binary, strings.Join(b.Tools, ", "))
	}
	fmt.Println()

	if r.ToolsBroken > 0 {
		fmt.Println("  unusable tools")
		for _, t := range r.Tools {
			if !t.Usable {
				fmt.Printf("    %-28s needs one of: %s\n", t.Tool, strings.Join(t.Needs, ", "))
			}
		}
		fmt.Println()
	}

	if r.ToolsDegraded > 0 {
		fmt.Println("  usable but degraded")
		for _, t := range r.Tools {
			if t.Usable && t.Degraded != "" {
				fmt.Printf("    %-28s %s\n", t.Tool, t.Degraded)
			}
		}
		fmt.Println()
	}

	if len(r.Notes) > 0 {
		fmt.Println("  notes")
		for _, n := range r.Notes {
			fmt.Printf("    %s\n", n)
		}
		fmt.Println()
	}

	if r.ToolsBroken == 0 {
		fmt.Println("  all tools can run")
	}
}
