// Package utils provides the only sanctioned way for SENTINEL-X to invoke an
// external binary.
//
// Three properties are guaranteed for every call:
//
//  1. Allowlisting — the binary name must appear in the configured allowlist.
//  2. Argument vetting — every argument is screened against the denylist
//     regexes before the process is created.
//  3. Containment — the command runs under a wall-clock timeout inside its
//     own process group, so a hung or forking child is killed outright rather
//     than leaking, and its output is captured through a size-capped buffer.
//
// Nothing here can be coerced into running a shell: commands are always
// executed as an argv vector, never through `sh -c`.
package utils

import (
	"context"
	"errors"
	"fmt"
	"github.com/sentinel-x/sentinel-x/internal/budget"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sentinel-x/sentinel-x/internal/config"
)

// Spec describes a single external invocation.
type Spec struct {
	// Binary is a bare program name resolved through PATH.
	Binary string
	// Args is the argument vector, excluding argv[0]. It is never re-parsed
	// by a shell, so quoting and metacharacters have no special meaning.
	Args []string
	// Timeout overrides the module default when non-zero.
	Timeout time.Duration
	// MaxOutput overrides the configured cap when non-zero.
	MaxOutput int
	// ExtraEnv is appended to the sanitised base environment.
	ExtraEnv []string
}

// Result is the captured outcome of an invocation.
type Result struct {
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	DurationMS int64    `json:"duration_ms"`
	TimedOut   bool     `json:"timed_out"`
	Truncated  bool     `json:"truncated"`
	OK         bool     `json:"ok"`
	Note       string   `json:"note,omitempty"`
}

// CommandLine renders the invocation for auditing and error messages.
func (r *Result) CommandLine() string {
	return strings.Join(append([]string{r.Command}, r.Args...), " ")
}

// Sentinel errors.
var (
	ErrBinaryNotAllowed = errors.New("binary is not in the SENTINEL-X allowlist")
	ErrBinaryDenied     = errors.New("binary is explicitly denied by SENTINEL-X policy")
	ErrBinaryNotFound   = errors.New("binary not found on PATH")
	ErrArgumentDenied   = errors.New("argument rejected by SENTINEL-X policy")
)

// Runner executes specs under the configured policy. It is safe for
// concurrent use and is shared by every tool module.
type Runner struct {
	cfg *config.Config
	// denied holds the global patterns, which apply to every binary.
	denied []*regexp.Regexp
	// perBinary holds binary-specific patterns. Keeping them separate is
	// essential: a global rule strong enough to block `searchsploit -p` would
	// also block the legitimate `nmap -p 1-1024`.
	perBinary map[string][]*regexp.Regexp
	sem       chan struct{}
	redactor  *Redactor

	// resolved caches PATH lookups so repeated tool calls stay cheap.
	mu       sync.RWMutex
	resolved map[string]string

	// budget bounds how much this process can send. It is checked here, at the
	// one place every external request passes through, so a tool added later
	// is bounded without anyone remembering to add a check.
	budget *budget.State
}

// BudgetExhaustedError reports a refusal by the request budget. It is
// distinguishable so a caller can tell "you asked for too much" from
// "the scan could not run".
type BudgetExhaustedError struct {
	Reason string
	Limit  string
}

func (e *BudgetExhaustedError) Error() string { return e.Reason }

// budgetLimitsFrom reads the budget caps from config, falling back to defaults
// for anything unset.
func budgetLimitsFrom(cfg *config.Config) budget.Limits {
	l := budget.DefaultLimits()
	if v := envInt("SENTINELX_BUDGET_PER_TARGET", 0); v > 0 {
		l.MaxPerTarget = v
	}
	if v := envInt("SENTINELX_BUDGET_TOTAL", 0); v > 0 {
		l.MaxTotal = v
	}
	if v := envInt("SENTINELX_BUDGET_PER_TOOL", 0); v > 0 {
		l.MaxPerTool = v
	}
	return l
}

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

// Forget drops a cached PATH lookup so the next call re-resolves it.
//
// Negative results are cached too, which is correct for the common case and
// wrong immediately after a dependency is installed: without this, a tool
// would report the binary missing for the rest of the process even though the
// package manager just put it on disk.
func (r *Runner) Forget(binary string) {
	r.mu.Lock()
	delete(r.resolved, binary)
	r.mu.Unlock()
}

// Budget returns the attached budget, or nil.
func (r *Runner) Budget() *budget.State { return r.budget }

// spend consults the budget before an external process is started.
func (r *Runner) spend(args []string, tool string) error {
	if r.budget == nil {
		return nil
	}
	if d := r.budget.Check(budget.HostOf(args), tool); !d.Allowed {
		return &BudgetExhaustedError{Reason: d.Reason, Limit: d.Limit}
	}
	return nil
}

// NewRunner compiles the policy regexes once. A malformed regex in the policy
// is a programming error and is reported here rather than at scan time.
func NewRunner(cfg *config.Config) (*Runner, error) {
	compile := func(pats []string) ([]*regexp.Regexp, error) {
		out := make([]*regexp.Regexp, 0, len(pats))
		for _, p := range pats {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("config: invalid denied-arg pattern %q: %w", p, err)
			}
			out = append(out, re)
		}
		return out, nil
	}

	denied, err := compile(cfg.Policy.DeniedArgPatterns)
	if err != nil {
		return nil, err
	}
	perBinary := make(map[string][]*regexp.Regexp, len(cfg.Policy.BinaryArgDenylist))
	for bin, pats := range cfg.Policy.BinaryArgDenylist {
		compiled, err := compile(pats)
		if err != nil {
			return nil, err
		}
		perBinary[strings.ToLower(bin)] = compiled
	}

	return &Runner{
		cfg:       cfg,
		denied:    denied,
		perBinary: perBinary,
		sem:       make(chan struct{}, cfg.Policy.MaxConcurrency),
		budget:    budget.New(budgetLimitsFrom(cfg)),
		redactor:  NewRedactor(cfg.Policy.RedactPatterns),
		resolved:  make(map[string]string),
	}, nil
}

// Redactor exposes the shared scrubber for text that never passed through the
// process runner (for example HTTP response bodies).
func (r *Runner) Redactor() *Redactor { return r.redactor }

// Available reports whether a binary is both allowlisted and present on PATH.
func (r *Runner) Available(binary string) (bool, string) {
	if err := r.checkBinary(binary); err != nil {
		return false, err.Error()
	}
	if _, err := r.lookPath(binary); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// HasBinary is Available for a list of candidates: it returns the first one
// that is usable, which lets a module gracefully fall back between tools.
func (r *Runner) HasBinary(candidates ...string) string {
	for _, c := range candidates {
		if ok, _ := r.Available(c); ok {
			return c
		}
	}
	return ""
}

// Run executes the spec under a timeout and returns a structured result.
// A non-zero exit status is reported in the result rather than as an error;
// only policy violations and spawn failures produce an error.
func (r *Runner) Run(ctx context.Context, spec Spec) (*Result, error) {
	if err := r.spend(spec.Args, spec.Binary); err != nil {
		return nil, err
	}
	if err := r.checkBinary(spec.Binary); err != nil {
		return nil, err
	}
	path, err := r.lookPath(spec.Binary)
	if err != nil {
		return nil, err
	}
	if err := r.CheckArgs(spec.Binary, spec.Args); err != nil {
		return nil, err
	}

	timeout := spec.Timeout
	if timeout <= 0 || timeout > r.cfg.Timeouts.Max {
		timeout = r.cfg.Timeouts.Max
	}
	maxOut := spec.MaxOutput
	if maxOut <= 0 {
		maxOut = r.cfg.Policy.MaxOutputBytes
	}

	// Bound concurrency before doing any work.
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// A minimal, explicit environment: PATH and locale only. The server may be
	// launched from a hostile shell, and inheriting its full environment would
	// hand attacker-controlled variables (LD_PRELOAD, http_proxy, ...) to the
	// child.
	cmd := exec.CommandContext(runCtx, path, spec.Args...)
	cmd.Env = append(sanitisedEnv(), spec.ExtraEnv...)
	cmd.Dir = ""
	setProcessGroup(cmd)
	// Never let a tool wait on a human.
	cmd.Stdin = nil

	stdout := newCapBuffer(maxOut)
	stderr := newCapBuffer(maxOut)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	res := &Result{
		Command: spec.Binary,
		Args:    spec.Args,
	}
	start := time.Now()

	runErr := r.start(runCtx, cmd, killGroup)
	res.DurationMS = time.Since(start).Milliseconds()
	res.Stdout = r.redactor.Scrub(stdout.String())
	res.Stderr = r.redactor.Scrub(stderr.String())
	res.Truncated = stdout.Truncated() || stderr.Truncated()

	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		res.TimedOut = true
		res.ExitCode = -1
		res.Note = fmt.Sprintf("command exceeded its %s timeout and was terminated", timeout)
	case runErr == nil:
		res.ExitCode = 0
		res.OK = true
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			res.ExitCode = ee.ExitCode()
			// A non-zero status is normal for tools that encode findings in
			// their exit status, so the result is still useful.
			res.Note = fmt.Sprintf("command exited with status %d", res.ExitCode)
		} else {
			return nil, fmt.Errorf("executing %s: %w", spec.Binary, runErr)
		}
	}
	return res, nil
}

// RunCombined runs the spec and returns a single string: stdout when the tool
// wrote something useful there, otherwise stderr. nmap in particular reports
// most of its findings on stderr.
func (r *Runner) RunCombined(ctx context.Context, spec Spec) (string, *Result, error) {
	if err := r.spend(spec.Args, spec.Binary); err != nil {
		return "", nil, err
	}
	res, err := r.Run(ctx, spec)
	if err != nil {
		return "", nil, err
	}
	out := strings.TrimSpace(res.Stdout)
	if out == "" {
		out = strings.TrimSpace(res.Stderr)
	}
	return out, res, nil
}

func (r *Runner) checkBinary(binary string) error {
	name := strings.ToLower(strings.TrimSpace(binary))
	if name == "" {
		return fmt.Errorf("%w: empty binary name", ErrBinaryNotAllowed)
	}
	// Compare on the base name so a path cannot be used to smuggle a different
	// binary past either the denylist or the per-binary argument rules.
	base := baseName(binary)
	for _, d := range r.cfg.Policy.DeniedBinaries {
		if name == d || base == d {
			return fmt.Errorf("%w: %s", ErrBinaryDenied, base)
		}
	}
	for _, a := range r.cfg.Policy.AllowedBinaries {
		if base == a {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrBinaryNotAllowed, base)
}

// reapGrace is how long start waits for cmd.Wait to return after signalling a
// timed-out process group, before giving up on it entirely. Bounding this
// matters: the whole point of the timeout is that a wedged child cannot pin the
// caller's tool slot indefinitely.
const reapGrace = 2 * time.Second

// start runs cmd and guarantees that a timeout is honoured promptly.
//
// exec.CommandContext alone is not sufficient here. It signals only the direct
// child, and cmd.Wait blocks until the stdout/stderr pipes close — so a
// backgrounded grandchild that survives keeps Run blocked long past the
// deadline. start therefore signals the whole process group the moment the
// context fires, and refuses to wait on the reaper for longer than reapGrace.
func (r *Runner) start(ctx context.Context, cmd *exec.Cmd, killGroup func(*exec.Cmd)) error {
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		killGroup(cmd)
		select {
		case err := <-done:
			if err == nil {
				// The child happened to exit cleanly; the context error is
				// still the more useful signal for the caller.
				return ctx.Err()
			}
			return err
		case <-time.After(reapGrace):
			// Something in the tree is unkillable. Return anyway rather than
			// letting the caller's context leak into an unbounded wait.
			return ctx.Err()
		}
	}
}

// CheckArgs screens an argument vector against the global denylist and the
// rules registered for the specific binary. It is exported so modules can
// validate synthesized commands before deciding to run them.
func (r *Runner) CheckArgs(binary string, args []string) error {
	rules := append(append([]*regexp.Regexp{}, r.denied...), r.perBinary[strings.ToLower(baseName(binary))]...)
	for i, a := range args {
		for _, re := range rules {
			if re.MatchString(a) {
				return fmt.Errorf("%w: %s argv[%d]=%q matched rule %s", ErrArgumentDenied, baseName(binary), i, a, re.String())
			}
		}
	}
	return nil
}

// baseName strips any directory component so a caller cannot reach a different
// binary, or dodge a per-binary rule, by supplying a path.
func baseName(binary string) string {
	b := strings.ToLower(strings.TrimSpace(binary))
	if i := strings.LastIndexAny(b, `/\`); i >= 0 {
		b = b[i+1:]
	}
	return b
}

func (r *Runner) lookPath(binary string) (string, error) {
	r.mu.RLock()
	p, ok := r.resolved[binary]
	r.mu.RUnlock()
	if ok {
		if p == "" {
			return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, binary)
		}
		return p, nil
	}
	found, err := exec.LookPath(binary)
	if err != nil {
		found = ""
	}
	r.mu.Lock()
	r.resolved[binary] = found
	r.mu.Unlock()
	if found == "" {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, binary)
	}
	return found, nil
}

// sanitisedEnv builds the minimal environment handed to child processes.
func sanitisedEnv() []string {
	env := []string{
		"PATH=" + defaultPath,
		"HOME=" + osGetenvFallback("HOME", "/nonexistent"),
		"LC_ALL=C",
		"LANG=C",
	}
	// Preserve the resolver and proxy-free TLS defaults explicitly.
	if r := osGetenvFallback("RES_OPTIONS", ""); r != "" {
		env = append(env, "RES_OPTIONS="+r)
	}
	return env
}

const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
