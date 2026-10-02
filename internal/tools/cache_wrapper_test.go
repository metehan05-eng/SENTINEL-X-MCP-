package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sentinel-x/sentinel-x/internal/cache"
	"github.com/sentinel-x/sentinel-x/internal/config"
)

func cachedDeps(t *testing.T, ttl time.Duration) Deps {
	t.Helper()
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Cfg: cfg, Cache: cache.New(64, ttl, "test")}
}

func callEnv(t *testing.T, h Handler, args map[string]any) map[string]any {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	txt := res.Content[0].(mcp.TextContent).Text
	var env map[string]any
	if err := json.Unmarshal([]byte(txt), &env); err != nil {
		t.Fatalf("bad envelope: %s", txt)
	}
	return env
}

var errProbe = errors.New("probe failed")

// probeTool is a stand-in that always succeeds, so the wrapper can be tested
// without depending on which scanners happen to be installed.
func probeTool(d Deps, calls *int) Tool {
	return Tool{
		Tool: mcp.NewTool("sentinelx_probe",
			mcp.WithDescription("test double"),
			mcp.WithString("q", mcp.Description("query")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			*calls++
			var data struct {
				Value string `json:"value"`
			}
			data.Value = req.GetString("q", "")
			return ok(d, "sentinelx_probe", "127.0.0.1", time.Now(), nil, data)
		},
	}
}

// A hit has to be visible at the top level, or a model reads it as a fresh
// observation and reports a stale scan as current.
func TestCachedHitIsDisclosedAtTopLevel(t *testing.T) {
	calls := 0
	d := cachedDeps(t, time.Minute)
	h := cachedHandler(d, probeTool(d, &calls))
	args := map[string]any{"q": "x"}

	first := callEnv(t, h, args)
	if first["cache_hit"] == true {
		t.Fatal("the first call was reported as cached")
	}
	second := callEnv(t, h, args)
	if second["cache_hit"] != true {
		t.Fatalf("the second call was not reported as cached: %v", second)
	}
	if calls != 1 {
		t.Fatalf("the tool ran %d times; a hit did not collapse the call", calls)
	}
	age, ok := second["cache_age_ms"].(float64)
	if !ok || age < 0 {
		t.Fatalf("cache_age_ms is %v", second["cache_age_ms"])
	}
	note, _ := second["cache_note"].(string)
	if !strings.Contains(note, "Re-run") {
		t.Fatalf("note does not tell the model what to do: %q", note)
	}
}

// Rewriting the observation time on a hit is how a ten-minute-old scan gets
// reported as if it just ran.
func TestCachedHitKeepsOriginalTimestamp(t *testing.T) {
	calls := 0
	d := cachedDeps(t, time.Minute)
	h := cachedHandler(d, probeTool(d, &calls))
	args := map[string]any{"q": "x"}

	first := callEnv(t, h, args)
	time.Sleep(1100 * time.Millisecond)
	second := callEnv(t, h, args)
	if second["cache_hit"] != true {
		t.Fatal("expected a hit")
	}
	if second["timestamp"] != first["timestamp"] {
		t.Fatalf("timestamp moved from %v to %v on a hit", first["timestamp"], second["timestamp"])
	}
}

func TestDifferentArgumentsDoNotShareAnEntry(t *testing.T) {
	calls := 0
	d := cachedDeps(t, time.Minute)
	h := cachedHandler(d, probeTool(d, &calls))
	callEnv(t, h, map[string]any{"q": "a"})
	env := callEnv(t, h, map[string]any{"q": "b"})
	if env["cache_hit"] == true {
		t.Fatal("a scan of one target was served for another")
	}
	if calls != 2 {
		t.Fatalf("the tool ran %d times", calls)
	}
}

func TestNilCacheCallsThroughEveryTime(t *testing.T) {
	cfg, err := config.Get()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	nilDeps := Deps{Cfg: cfg}
	h := cachedHandler(nilDeps, probeTool(nilDeps, &calls))
	for i := 0; i < 3; i++ {
		env := callEnv(t, h, map[string]any{"q": "x"})
		if env["cache_hit"] == true {
			t.Fatal("a hit was reported with no cache configured")
		}
	}
	if calls != 3 {
		t.Fatalf("the tool ran %d times with caching unavailable", calls)
	}
}

// The tools that change something must run every time. A replayed "wrote
// /tmp/x.sarif" that never touches the disk is a success for an action that did
// not happen.
func TestStatefulToolsAreNotCached(t *testing.T) {
	for _, name := range []string{"sentinelx_setup", "sentinelx_baseline", "sentinelx_sarif_report",
		"sentinelx_nuclei_scan", "sentinelx_xss_probe"} {
		if !uncacheable[name] {
			t.Errorf("%s is not marked uncacheable", name)
		}
	}
	// The registry has to honour the marker rather than wrapping anyway.
	d := cachedDeps(t, time.Minute)
	var live int
	for _, tl := range AllTools(d) {
		if !uncacheable[tl.Tool.Name] {
			live++
		}
	}
	if live == 0 {
		t.Fatal("every tool is uncacheable, so the cache does nothing")
	}
	if live >= len(AllTools(d)) {
		t.Fatal("nothing is cacheable, so the cache cannot be observed")
	}
}

// A failed call must not be cached: caching an error turns a transient
// missing binary into a permanent one for the whole TTL.
func TestErrorsAreNotCached(t *testing.T) {
	d := cachedDeps(t, time.Minute)
	failing := Tool{
		Tool: mcp.NewTool("sentinelx_probe", mcp.WithDescription("test double")),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return fail("sentinelx_probe", "127.0.0.1", time.Now(), errProbe)
		},
	}
	h := cachedHandler(d, failing)
	for i := 0; i < 2; i++ {
		env := callEnv(t, h, map[string]any{"q": "x"})
		if env["cache_hit"] == true {
			t.Fatal("a failure was served from cache")
		}
	}
	if s := d.Cache.Stats(); s.Entries != 0 {
		t.Fatalf("%d failures were cached", s.Entries)
	}
}
