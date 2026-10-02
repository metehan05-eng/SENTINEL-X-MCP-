package utils

import (
	"context"
	"testing"
	"time"

	"github.com/sentinel-x/sentinel-x/internal/config"
)

// Installing a package changes PATH contents, so the runner must forget the
// cached lookup or it will report the binary missing for the rest of the
// process even though the package manager just put it on disk.
func TestForgetDropsCachedLookup(t *testing.T) {
	cfg := realConfig(t)
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.lookPath("sh"); err != nil {
		t.Fatal("sh should resolve")
	}
	r.Forget("sh")
	r.mu.RLock()
	_, cached := r.resolved["sh"]
	r.mu.RUnlock()
	if cached {
		t.Fatal("Forget did not drop the cached lookup")
	}
}

// Negative lookups are cached too, which is what makes Forget necessary.
func TestNegativeLookupIsCached(t *testing.T) {
	cfg := realConfig(t)
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.lookPath("definitely-not-a-real-binary-xyz"); err == nil {
		t.Fatal("expected a miss")
	}
	r.mu.RLock()
	v, cached := r.resolved["definitely-not-a-real-binary-xyz"]
	r.mu.RUnlock()
	if !cached {
		t.Fatal("a negative lookup was not cached, so Forget would be pointless")
	}
	if v != "" {
		t.Fatalf("expected an empty cached path, got %q", v)
	}
}

// The budget is checked before any process is started, so a refused request
// costs nothing on the target.
func TestBudgetRefusesBeforeRunning(t *testing.T) {
	cfg := realConfig(t)
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINELX_BUDGET_TOTAL", "1")
	r2, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r2.budget == nil {
		t.Fatal("no budget attached by default")
	}
	if _, err := r2.Run(context.Background(), Spec{Binary: "curl", Args: []string{"-sSI", "https://example.com"}}); err != nil {
		t.Fatalf("first call should succeed: %v", err)
	}
	_, err = r2.Run(context.Background(), Spec{Binary: "curl", Args: []string{"-sSI", "https://example.com"}})
	if err == nil {
		t.Fatal("budget did not refuse the second call")
	}
	var be *BudgetExhaustedError
	if !asBudgetErr(err, &be) {
		t.Fatalf("error is not a BudgetExhaustedError: %T %v", err, err)
	}
	if be.Limit != "SENTINELX_BUDGET_TOTAL" {
		t.Fatalf("limit %q", be.Limit)
	}
	_ = r
	_ = time.Second
}

// realConfig loads the real allowlist; a hand-built Config would reject every
// binary and the test would pass for the wrong reason.
func realConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func asBudgetErr(err error, target **BudgetExhaustedError) bool {
	if be, ok := err.(*BudgetExhaustedError); ok {
		*target = be
		return true
	}
	return false
}
