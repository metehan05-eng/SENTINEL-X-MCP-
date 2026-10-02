package cache

import (
	"encoding/json"
	"testing"
	"time"
)

func TestKeyIsOrderIndependent(t *testing.T) {
	// A model producing the same call with keys in a different order is the
	// common case, not a rare one.
	a := Key("t", map[string]any{"host": "x", "port": 1, "deep": true})
	b := Key("t", map[string]any{"deep": true, "port": 1, "host": "x"})
	if a != b {
		t.Fatalf("key depends on argument order: %s vs %s", a, b)
	}
	if a == Key("other", map[string]any{"host": "x", "port": 1, "deep": true}) {
		t.Fatal("different tools share a key")
	}
	if a == Key("t", map[string]any{"host": "y", "port": 1, "deep": true}) {
		t.Fatal("different arguments share a key")
	}
}

func TestGetMissThenHit(t *testing.T) {
	c := New(10, time.Minute, "v1")
	args := map[string]any{"host": "x"}
	if _, hit, _ := c.Get("t", args); hit {
		t.Fatal("empty cache reported a hit")
	}
	c.Put("t", args, json.RawMessage(`{"ok":true}`))
	e, hit, age := c.Get("t", args)
	if !hit {
		t.Fatal("stored entry not found")
	}
	if age < 0 {
		t.Fatalf("negative age %v", age)
	}
	if string(e.Result) != `{"ok":true}` {
		t.Fatalf("result %s", e.Result)
	}
}

// An expired entry must never be served, even before the sweep runs.
func TestExpiredEntryIsNotServed(t *testing.T) {
	c := New(10, 20*time.Millisecond, "v1")
	args := map[string]any{"host": "x"}
	c.Put("t", args, json.RawMessage(`{}`))
	time.Sleep(40 * time.Millisecond)
	if _, hit, _ := c.Get("t", args); hit {
		t.Fatal("expired entry served")
	}
	if s := c.Stats(); s.Entries != 0 {
		t.Fatalf("expired entry not removed on access: %d entries", s.Entries)
	}
}

// A tool that changes its output shape must not serve the old shape under the
// new version.
func TestVersionChangeInvalidates(t *testing.T) {
	c := New(10, time.Minute, "v1")
	args := map[string]any{"host": "x"}
	c.Put("t", args, json.RawMessage(`{}`))
	c2 := New(10, time.Minute, "v2")
	// Simulate the same process picking up a new build.
	c2.entries = c.entries
	c2.version = "v2"
	if _, hit, _ := c2.Get("t", args); hit {
		t.Fatal("entry from an older version was served")
	}
}

func TestEvictionDropsExpiredFirst(t *testing.T) {
	c := New(2, time.Minute, "v1")
	old := map[string]any{"host": "old"}
	c.Put("t", old, json.RawMessage(`{}`))
	// Backdate one entry so it is expired without waiting.
	c.mu.Lock()
	e := c.entries[Key("t", old)]
	e.ExpiresAt = time.Now().Add(-time.Second)
	c.entries[Key("t", old)] = e
	c.mu.Unlock()

	c.Put("t", map[string]any{"host": "a"}, json.RawMessage(`{}`))
	c.Put("t", map[string]any{"host": "b"}, json.RawMessage(`{}`))
	if _, hit, _ := c.Get("t", old); hit {
		t.Fatal("expired entry kept while making room for live ones")
	}
	if _, hit, _ := c.Get("t", map[string]any{"host": "a"}); !hit {
		t.Fatal("live entry evicted to make room")
	}
}

func TestEvictionDropsOldestSurvivor(t *testing.T) {
	c := New(2, time.Minute, "v1")
	c.Put("t", map[string]any{"host": "a"}, json.RawMessage(`{}`))
	time.Sleep(5 * time.Millisecond)
	c.Put("t", map[string]any{"host": "b"}, json.RawMessage(`{}`))
	time.Sleep(5 * time.Millisecond)
	c.Put("t", map[string]any{"host": "c"}, json.RawMessage(`{}`))
	if _, hit, _ := c.Get("t", map[string]any{"host": "a"}); hit {
		t.Fatal("the oldest live entry was kept instead of dropped")
	}
	if _, hit, _ := c.Get("t", map[string]any{"host": "c"}); !hit {
		t.Fatal("the newest entry was not stored")
	}
}

func TestBoundsRespected(t *testing.T) {
	c := New(3, time.Minute, "v1")
	for i := 0; i < 20; i++ {
		c.Put("t", map[string]any{"h": i}, json.RawMessage(`{}`))
	}
	if s := c.Stats(); s.Entries > 3 {
		t.Fatalf("cache grew to %d entries with a max of 3", s.Entries)
	}
}

func TestNilCacheIsSafe(t *testing.T) {
	var c *Cache
	c.Put("t", map[string]any{}, nil)
	if _, hit, _ := c.Get("t", map[string]any{}); hit {
		t.Fatal("nil cache reported a hit")
	}
	if s := c.Stats(); s.Enabled {
		t.Fatal("nil cache reported as enabled")
	}
}

// The whole point of the package: a hit must be impossible to mistake for a
// fresh result.
func TestNoticeNamesTheAge(t *testing.T) {
	n := NewNotice(true, 90*time.Second)
	if !n.CacheHit {
		t.Fatal("hit not marked")
	}
	if n.CacheAgeMS != 90000 {
		t.Fatalf("age %d", n.CacheAgeMS)
	}
	for _, want := range []string{"CACHE", "1m30s", "Re-run"} {
		if !contains(n.Note, want) {
			t.Fatalf("notice missing %q: %q", want, n.Note)
		}
	}
}

func TestNoticeWarnsWhenOld(t *testing.T) {
	if n := NewNotice(true, 10*time.Minute); !contains(n.Note, "may well have changed") {
		t.Fatalf("an old entry was not flagged: %q", n.Note)
	}
	if n := NewNotice(true, 30*time.Second); contains(n.Note, "may well have changed") {
		t.Fatalf("a fresh entry was over-warned: %q", n.Note)
	}
}

func TestNoticeForMissIsEmpty(t *testing.T) {
	n := NewNotice(false, 0)
	if n.CacheHit || n.Note != "" {
		t.Fatalf("a miss carried a notice: %+v", n)
	}
}

func TestStatsCounters(t *testing.T) {
	c := New(4, time.Minute, "v1")
	c.Get("t", map[string]any{"a": 1})
	c.Put("t", map[string]any{"a": 1}, json.RawMessage(`{}`))
	c.Get("t", map[string]any{"a": 1})
	s := c.Stats()
	if s.Hits != 1 || s.Misses != 1 {
		t.Fatalf("hits %d misses %d", s.Hits, s.Misses)
	}
	if s.Note == "" {
		t.Fatal("stats do not carry the staleness note")
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

// An operator who writes OFF has not asked for the cache, and an exact-match
// check would have kept it on.
func TestFromEnvRespectsEverySpellingOfOff(t *testing.T) {
	for _, v := range []string{"off", "OFF", "Off", "  off  ", "0", "false", "no", "disabled"} {
		t.Setenv("SENTINELX_CACHE", v)
		if c := FromEnv("v1"); c != nil {
			t.Errorf("SENTINELX_CACHE=%q still produced a cache", v)
		}
	}
}

func TestFromEnvDefaultsOn(t *testing.T) {
	t.Setenv("SENTINELX_CACHE", "")
	c := FromEnv("v1")
	if c == nil {
		t.Fatal("caching is off by default; the whole point is to collapse duplicate calls")
	}
	if s := c.Stats(); s.TTL != DefaultTTL || s.Max != DefaultMaxEntries {
		t.Fatalf("defaults not applied: %+v", s)
	}
}

func TestFromEnvReadsTTLAndMax(t *testing.T) {
	t.Setenv("SENTINELX_CACHE", "on")
	t.Setenv("SENTINELX_CACHE_TTL", "45s")
	t.Setenv("SENTINELX_CACHE_MAX", "12")
	s := FromEnv("v1").Stats()
	if s.TTL != 45*time.Second || s.Max != 12 {
		t.Fatalf("env ignored: %+v", s)
	}
}

// A typo in the TTL should fall back rather than disabling the cache or
// panicking at startup.
func TestFromEnvIgnoresNonsense(t *testing.T) {
	t.Setenv("SENTINELX_CACHE", "on")
	t.Setenv("SENTINELX_CACHE_TTL", "ten minutes")
	t.Setenv("SENTINELX_CACHE_MAX", "-4")
	s := FromEnv("v1").Stats()
	if s.TTL != DefaultTTL || s.Max != DefaultMaxEntries {
		t.Fatalf("nonsense values were applied: %+v", s)
	}
}
