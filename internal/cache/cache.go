// Package cache memoises tool results for a short window.
//
// Re-running a 50-host HTTP probe re-fetches every host, which costs the
// target the traffic and costs the assessment the time, and returns byte-identical
// answers. Caching that is worth it. Caching it silently is not, because a
// model reading a cached result cannot tell it was cached: it will describe a
// two-hour-old response as the current state of the host.
//
// So every entry carries its age, and every hit is labelled. There is no
// configuration where a caller receives a cached result that is not marked as
// one.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMaxEntries bounds the memory a long-running server can hold. Scanning
// one host touches a dozen tools, so this is a few dozen assessments' worth of
// envelopes rather than a whole campaign.
const DefaultMaxEntries = 256

// DefaultTTL is deliberately short. The point is to collapse duplicate calls
// inside one assessment, not to build a historical record; a long TTL would
// turn a cache into a stale-data source that claims to be live.
const DefaultTTL = 10 * time.Minute

// Entry is one memoised result.
type Entry struct {
	Tool      string          `json:"tool"`
	Args      map[string]any  `json:"args"`
	Result    json.RawMessage `json:"result"`
	StoredAt  time.Time       `json:"stored_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	// Version of the tool that produced it. A tool that changes its output
	// shape invalidates its own entries rather than serving the old shape
	// under the new name.
	Version string `json:"version"`
}

// Age returns how long ago the entry was stored, and whether it is still valid.
func (e Entry) Age(now time.Time) (time.Duration, bool) {
	return now.Sub(e.StoredAt), now.Before(e.ExpiresAt)
}

// Cache is a bounded in-memory store.
//
// It is in memory rather than on disk deliberately: a persisted cache is a file
// full of target addresses, response headers and page content that outlives the
// session and gets swept up by backups.
type Cache struct {
	mu      sync.Mutex
	entries map[string]Entry
	max     int
	ttl     time.Duration
	version string
	hits    int
	misses  int
}

// New builds a cache.
func New(max int, ttl time.Duration, version string) *Cache {
	if max <= 0 {
		max = 256
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{entries: map[string]Entry{}, max: max, ttl: ttl, version: version}
}

// Key derives a cache key from a tool name and its arguments. Arguments are
// canonicalised by sorting keys, so {"a":1,"b":2} and {"b":2,"a":1} hit the same
// entry — a model producing the same call in a different key order is the
// common case, not a rare one.
func Key(tool string, args map[string]any) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(tool))
	for _, k := range keys {
		v, err := json.Marshal(args[k])
		if err != nil {
			v = []byte(fmtAny(args[k]))
		}
		h.Write([]byte(k))
		h.Write(v)
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func fmtAny(v any) string {
	if s, isStr := v.(string); isStr {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Get returns a valid entry. An expired entry is removed on access, so a stale
// answer is never served even if the sweep has not run.
func (c *Cache) Get(tool string, args map[string]any) (Entry, bool, time.Duration) {
	if c == nil {
		return Entry{}, false, 0
	}
	k := Key(tool, args)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.entries[k]
	if !found {
		c.misses++
		return Entry{}, false, 0
	}
	age, valid := e.Age(time.Now())
	if !valid || e.Version != c.version {
		delete(c.entries, k)
		c.misses++
		return Entry{}, false, age
	}
	c.hits++
	return e, true, age
}

// Put stores a result, evicting the oldest entries when full.
func (c *Cache) Put(tool string, args map[string]any, result json.RawMessage) {
	if c == nil {
		return
	}
	now := time.Now()
	e := Entry{
		Tool: tool, Args: args, Result: result,
		StoredAt: now, ExpiresAt: now.Add(c.ttl), Version: c.version,
	}
	k := Key(tool, args)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[k] = e
}

// evictLocked drops expired entries first, then the oldest survivors. The cache
// has to make room for a live entry, and dropping a fresh one to keep a
// two-minute-old one would be backwards.
func (c *Cache) evictLocked() {
	now := time.Now()
	oldest := ""
	var oldestAt time.Time
	for k, e := range c.entries {
		if now.After(e.ExpiresAt) {
			delete(c.entries, k)
			continue
		}
		if oldestAt.IsZero() || e.StoredAt.Before(oldestAt) {
			oldest, oldestAt = k, e.StoredAt
		}
	}
	if len(c.entries) >= c.max && oldest != "" {
		delete(c.entries, oldest)
	}
}

// Stats describes cache behaviour, for the health tool and for a caller that
// wants to know whether caching is even engaged.
type Stats struct {
	Enabled    bool          `json:"enabled"`
	Entries    int           `json:"entries"`
	Max        int           `json:"max_entries"`
	TTL        time.Duration `json:"-"`
	TTLSeconds int           `json:"ttl_seconds"`
	Hits       int           `json:"hits"`
	Misses     int           `json:"misses"`
	Note       string        `json:"note,omitempty"`
}

// Stats snapshots the counters.
func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{Enabled: false, Note: "caching is disabled; every call goes to the target"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Enabled: true, Entries: len(c.entries), Max: c.max, TTL: c.ttl,
		TTLSeconds: int(c.ttl.Seconds()), Hits: c.hits, Misses: c.misses,
		Note: "Cached results are always labelled with their age. A cached response is not a current one.",
	}
}

// Notice is the disclosure attached to a cache hit. It is deliberately
// unmissable: it names the age in the top-level field, not in a nested
// structure a model might skip.
type Notice struct {
	CacheHit   bool   `json:"cache_hit"`
	CacheAgeMS int64  `json:"cache_age_ms,omitempty"`
	Stale      bool   `json:"stale,omitempty"`
	Note       string `json:"note,omitempty"`
}

// NewNotice builds the disclosure for a hit. A hit is by definition within TTL,
// so Stale is false; it exists so the field set is stable and a future
// "serve expired under pressure" mode is visible rather than silent.
func NewNotice(hit bool, age time.Duration) Notice {
	if !hit {
		return Notice{CacheHit: false}
	}
	ageText := age.Round(time.Second).String()
	fresh := "still probably current"
	if age >= 5*time.Minute {
		fresh = "older than five minutes; the target may well have changed since"
	}
	return Notice{
		CacheHit:   true,
		CacheAgeMS: age.Milliseconds(),
		Note: "RESULT SERVED FROM CACHE, " + ageText + " old (" + fresh +
			"). Do not describe this as the current state of the target. Re-run this tool to refresh.",
	}
}

// FromEnv builds the process cache from the environment, or returns nil when
// caching is switched off. It lives here rather than in main so the switch can
// be tested; an exact-match check on "off" is easy to defeat with "OFF", and a
// cache that stays on when an operator asked for it off is a bug nobody
// notices.
func FromEnv(version string) *Cache {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SENTINELX_CACHE"))) {
	case "off", "0", "false", "no", "disabled":
		return nil
	}
	ttl := DefaultTTL
	if v := os.Getenv("SENTINELX_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			ttl = d
		}
	}
	max := DefaultMaxEntries
	if v := os.Getenv("SENTINELX_CACHE_MAX"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			max = n
		}
	}
	return New(max, ttl, version)
}
