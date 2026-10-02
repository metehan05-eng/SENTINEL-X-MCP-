// Package budget caps how much scanning a single server process can do.
//
// An assessment driven by a model has no natural stopping point. One misread
// instruction — "check all subdomains" against a domain with forty thousand of
// them — turns into tens of thousands of requests against someone else's
// infrastructure, from this machine, with this machine's address in the logs.
// That is the scenario a budget exists to make survivable.
//
// The budget is enforced at the process that actually makes the request rather
// than in each tool, so a new tool is bounded by default instead of by
// remembering to add a check.
package budget

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits are the configured caps. Zero means unlimited for that dimension,
// which is the default because a silent cap would truncate an assessment
// without saying so.
type Limits struct {
	// MaxPerTarget bounds requests aimed at one host in a single process.
	MaxPerTarget int
	// MaxTotal bounds requests across the whole process.
	MaxTotal int
	// MaxPerTool bounds requests to any one tool.
	MaxPerTool int
	// MaxConcurrent bounds simultaneous external processes.
	MaxConcurrent int
	// Window is how long the counters hold. A long-running server should not
	// have its whole-day assessment cut off at an arbitrary point, so counters
	// reset once the window passes.
	Window time.Duration
}

// DefaultLimits are conservative enough to stop an accidental flood and loose
// enough that a normal assessment never notices them.
func DefaultLimits() Limits {
	return Limits{
		MaxPerTarget:  500,
		MaxTotal:      5000,
		MaxPerTool:    1500,
		MaxConcurrent: 6,
		Window:        time.Hour,
	}
}

// State is the live counter set.
type State struct {
	mu       sync.Mutex
	limits   Limits
	started  time.Time
	windowAt time.Time
	total    int
	perTgt   map[string]int
	perTool  map[string]int
	denied   int
	peaked   int
}

// New builds a counter set.
func New(l Limits) *State {
	if l.Window <= 0 {
		l.Window = time.Hour
	}
	return &State{
		limits:   l,
		started:  time.Now(),
		windowAt: time.Now().Add(l.Window),
		perTgt:   map[string]int{},
		perTool:  map[string]int{},
	}
}

// Decision is the outcome of a budget check.
type Decision struct {
	Allowed bool
	Reason  string
	// Limit names the dimension that refused, so the message can tell the
	// operator which knob to turn rather than just saying "no".
	Limit string
}

// Check records an intended request and decides whether it may proceed.
//
// A refused request still counts against the total: a caller looping on a
// refusal should not be able to spin forever either.
func (s *State) Check(target, tool string) Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollLocked()
	s.total++

	// Per-tool first: it is the dimension a runaway loop hits.
	if s.limits.MaxPerTool > 0 && s.perTool[tool] >= s.limits.MaxPerTool {
		n := s.perTool[tool]
		s.denied++
		s.peaked = n
		return Decision{Reason: fmt.Sprintf(
			"%s has already made %d requests, which is the configured per-tool limit. "+
				"Split the work across sessions rather than raising this, so the request rate stays bounded.",
			tool, n), Limit: "SENTINELX_BUDGET_PER_TOOL"}
	}
	if s.limits.MaxPerTarget > 0 && s.perTgt[target] >= s.limits.MaxPerTarget {
		n := s.perTgt[target]
		s.denied++
		s.peaked = n
		scopeNote := ""
		if target == "" {
			scopeNote = " (requests without a single target host count together)"
		}
		return Decision{Reason: fmt.Sprintf(
			"%s has already received %d requests, which is the configured per-target limit%s. "+
				"Further requests were not sent. Confirm the target is authorised and in scope before raising this.",
			target, n, scopeNote), Limit: "SENTINELX_BUDGET_PER_TARGET"}
	}
	if s.limits.MaxTotal > 0 && s.total > s.limits.MaxTotal {
		s.denied++
		s.peaked = s.total
		return Decision{Reason: fmt.Sprintf(
			"This server has made %d requests, which is the configured total limit for the window. "+
				"Start a new session or raise SENTINELX_BUDGET_TOTAL.", s.total), Limit: "SENTINELX_BUDGET_TOTAL"}
	}

	if s.limits.MaxPerTool > 0 {
		s.perTool[tool]++
	}
	if s.limits.MaxTotal == 0 || s.total <= s.limits.MaxTotal {
		s.perTgt[target]++
	}
	return Decision{Allowed: true}
}

// rollLocked resets the counters once the window has passed. The window exists
// so a server left running overnight does not refuse everything at hour two.
func (s *State) rollLocked() {
	if time.Now().Before(s.windowAt) {
		return
	}
	s.windowAt = time.Now().Add(s.limits.Window)
	s.total = 0
	s.perTgt = map[string]int{}
	s.perTool = map[string]int{}
	s.denied = 0
}

// Snapshot is the budget state, returned with results so a long assessment
// shows its own pressure instead of failing without explanation.
type Snapshot struct {
	WindowMinutes  int            `json:"window_minutes"`
	Total          int            `json:"total"`
	LimitTotal     int            `json:"limit_total"`
	LimitPerTarget int            `json:"limit_per_target"`
	LimitPerTool   int            `json:"limit_per_tool"`
	Denied         int            `json:"denied"`
	TopTargets     map[string]int `json:"top_targets,omitempty"`
	Exhausted      bool           `json:"exhausted"`
	Note           string         `json:"note,omitempty"`
}

// Snapshot returns the current counters.
func (s *State) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollLocked()
	snap := Snapshot{
		WindowMinutes:  int(s.limits.Window.Minutes()),
		Total:          s.total,
		LimitTotal:     s.limits.MaxTotal,
		LimitPerTarget: s.limits.MaxPerTarget,
		LimitPerTool:   s.limits.MaxPerTool,
		Denied:         s.denied,
		TopTargets:     map[string]int{},
	}
	for t, n := range s.perTgt {
		if n > 0 {
			snap.TopTargets[t] = n
		}
	}
	// Only the heaviest targets are reported; a hundred-host scan should not
	// bury the summary under a counter for every host.
	if len(snap.TopTargets) > 5 {
		all := make([]kv, 0, len(snap.TopTargets))
		for k, n := range snap.TopTargets {
			all = append(all, kv{k, n})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].n != all[j].n {
				return all[i].n > all[j].n
			}
			return all[i].k < all[j].k
		})
		top := map[string]int{}
		for _, e := range all[:5] {
			top[e.k] = e.n
		}
		snap.TopTargets = top
	}
	if s.denied > 0 {
		snap.Exhausted = true
		snap.Note = fmt.Sprintf("%d request(s) were refused by the budget. The limit that stopped them is named in the error.", s.denied)
	}
	return snap
}

// Warning returns a heads-up before the limit is hit, so a scan slows down
// visibly rather than stopping dead.
func (s *State) Warning(target, tool string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollLocked()
	if s.limits.MaxPerTarget > 0 {
		used := s.perTgt[target]
		if used >= s.limits.MaxPerTarget*3/4 && used > 0 {
			return fmt.Sprintf("Budget: %d of %d requests used against %s in this window. Consider splitting the assessment.",
				used, s.limits.MaxPerTarget, orDefault(target, "this target"))
		}
	}
	if s.limits.MaxTotal > 0 && s.total >= s.limits.MaxTotal*3/4 {
		return fmt.Sprintf("Budget: %d of %d total requests used in this window.", s.total, s.limits.MaxTotal)
	}
	return ""
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// kv is a counter entry, kept out of Snapshot so the JSON stays a plain map.
type kv struct {
	k string
	n int
}

// HostOf pulls a target host out of a command line so counters are per host
// rather than per request. It is deliberately conservative: anything it cannot
// recognise is grouped under the empty key, which shares one counter, so an
// unrecognised invocation is still bounded.
func HostOf(args []string) string {
	// nmap's -p takes a port range, not a target, so it is deliberately not
	// treated as a host source: reading it as one makes every port scan look
	// like it targeted "1-1024", and all of them then share one counter.
	for i, a := range args {
		switch {
		case a == "--url" && i+1 < len(args):
			return hostToken(args[i+1])
		case strings.HasPrefix(a, "https://"), strings.HasPrefix(a, "http://"):
			return hostToken(a)
		case !strings.HasPrefix(a, "-") && looksLikeHost(a) && !isFlagLike(a):
			return hostToken(a)
		}
	}
	return ""
}

func hostToken(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.IndexAny(s, "/:"); i > 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func looksLikeHost(s string) bool {
	if strings.Contains(s, ".") || isIPv4(s) {
		return true
	}
	return false
}

func isFlagLike(s string) bool {
	// Flag values (nmap's -oX file, curl's -o file) must not be read as hosts.
	lower := strings.ToLower(s)
	for _, ext := range []string{".xml", ".json", ".txt", ".nmap", ".gnmap", ".out", ".log", ".html", ".csv"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return strings.HasPrefix(s, "/")
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
