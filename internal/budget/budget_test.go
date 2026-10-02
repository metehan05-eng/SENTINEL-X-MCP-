package budget

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPerTargetLimitRefuses(t *testing.T) {
	s := New(Limits{MaxPerTarget: 3, Window: time.Hour})
	for i := 0; i < 3; i++ {
		if d := s.Check("a.example", "curl"); !d.Allowed {
			t.Fatalf("request %d refused early: %s", i, d.Reason)
		}
	}
	d := s.Check("a.example", "curl")
	if d.Allowed {
		t.Fatal("limit not enforced")
	}
	if !strings.Contains(d.Reason, "a.example") {
		t.Fatalf("refusal does not name the target: %s", d.Reason)
	}
	// The refusal must say which knob to turn, not just "no".
	if d.Limit != "SENTINELX_BUDGET_PER_TARGET" {
		t.Fatalf("limit named %q", d.Limit)
	}
}

// A per-target limit that a second host walks straight past is not a per-target
// limit.
func TestPerTargetLimitIsPerHost(t *testing.T) {
	s := New(Limits{MaxPerTarget: 2, Window: time.Hour})
	s.Check("a", "curl")
	s.Check("a", "curl")
	if d := s.Check("a", "curl"); d.Allowed {
		t.Fatal("a not limited")
	}
	if d := s.Check("b", "curl"); !d.Allowed {
		t.Fatalf("b refused by a's budget: %s", d.Reason)
	}
}

func TestPerToolLimitRefusesAndNamesTool(t *testing.T) {
	s := New(Limits{MaxPerTool: 2, MaxPerTarget: 100, Window: time.Hour})
	s.Check("a", "nmap")
	s.Check("b", "nmap")
	d := s.Check("c", "nmap")
	if d.Allowed {
		t.Fatal("per-tool limit not enforced")
	}
	if !strings.Contains(d.Reason, "nmap") {
		t.Fatalf("refusal does not name the tool: %s", d.Reason)
	}
	if d.Limit != "SENTINELX_BUDGET_PER_TOOL" {
		t.Fatalf("limit %q", d.Limit)
	}
}

func TestTotalLimitRefuses(t *testing.T) {
	s := New(Limits{MaxTotal: 5, MaxPerTarget: 100, Window: time.Hour})
	for i := 0; i < 5; i++ {
		s.Check("a", "curl")
	}
	if d := s.Check("a", "curl"); d.Allowed {
		t.Fatal("total limit not enforced")
	}
}

// A caller looping on a refusal must not be able to spin either.
func TestRefusedRequestsStillCount(t *testing.T) {
	s := New(Limits{MaxPerTarget: 2, MaxTotal: 4, Window: time.Hour})
	for i := 0; i < 10; i++ {
		s.Check("a", "curl")
	}
	if snap := s.Snapshot(); snap.Total < 4 {
		t.Fatalf("refusals were not counted: total %d", snap.Total)
	}
}

func TestZeroLimitMeansUnlimited(t *testing.T) {
	s := New(Limits{Window: time.Hour})
	for i := 0; i < 200; i++ {
		if d := s.Check("a", "curl"); !d.Allowed {
			t.Fatalf("an unset limit refused at %d: %s", i, d.Reason)
		}
	}
}

// A server left running overnight must not refuse everything at hour two.
func TestWindowResets(t *testing.T) {
	s := New(Limits{MaxPerTarget: 2, Window: 40 * time.Millisecond})
	s.Check("a", "curl")
	s.Check("a", "curl")
	if d := s.Check("a", "curl"); d.Allowed {
		t.Fatal("limit ignored before the window elapsed")
	}
	time.Sleep(60 * time.Millisecond)
	if d := s.Check("a", "curl"); !d.Allowed {
		t.Fatalf("not allowed after the window: %s", d.Reason)
	}
}

func TestWarningAppearsBeforeTheLimit(t *testing.T) {
	s := New(Limits{MaxPerTarget: 4, Window: time.Hour})
	var warned string
	for i := 0; i < 3; i++ {
		s.Check("a", "curl")
		warned = s.Warning("a", "curl")
	}
	if warned == "" {
		t.Fatal("no warning while three quarters of the budget was gone")
	}
	if !strings.Contains(warned, "3 of 4") {
		t.Fatalf("warning does not quantify: %q", warned)
	}
}

func TestSnapshotReportsExhaustion(t *testing.T) {
	s := New(Limits{MaxPerTarget: 1, Window: time.Hour})
	s.Check("a", "curl")
	s.Check("a", "curl")
	snap := s.Snapshot()
	if !snap.Exhausted {
		t.Fatal("exhaustion not reported after a refusal")
	}
	if snap.Denied != 1 {
		t.Fatalf("denied %d", snap.Denied)
	}
	if snap.Note == "" {
		t.Fatal("no note on the snapshot")
	}
}

func TestSnapshotTruncatesTargetList(t *testing.T) {
	s := New(Limits{MaxPerTarget: 10, Window: time.Hour})
	for i := 0; i < 20; i++ {
		s.Check(string(rune('a'+i%26))+string(rune('a'+i/26)), "curl")
	}
	if n := len(s.Snapshot().TopTargets); n > 5 {
		t.Fatalf("snapshot lists %d targets; a hundred-host scan should not bury the summary", n)
	}
}

// The host extraction has to be good enough that a flag value is not counted as
// a host, and bad enough that an unrecognised invocation still shares a counter.
func TestHostOf(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-sV", "-p", "1-1024", "10.0.0.1"}, "10.0.0.1"},
		{[]string{"-sV", "--", "example.com"}, "example.com"},
		{[]string{"https://example.com/path"}, "example.com"},
		{[]string{"--url", "https://Example.com/x"}, "example.com"},
		{[]string{"-oX", "/tmp/out.xml", "10.0.0.5"}, "10.0.0.5"},
		{[]string{"-o", "report.nmap", "10.0.0.5"}, "10.0.0.5"},
		{[]string{"-p80", "10.0.0.9"}, "10.0.0.9"},
		{[]string{"--no-host", "true"}, ""},
		{[]string{}, ""},
	}
	for _, c := range cases {
		if got := HostOf(c.args); got != c.want {
			t.Errorf("HostOf(%v) = %q, want %q", c.args, got, c.want)
		}
	}
}

// Requests the host extractor cannot attribute share one counter, so an
// unrecognised invocation is still bounded.
func TestUnattributedRequestsShareOneCounter(t *testing.T) {
	s := New(Limits{MaxPerTarget: 3, Window: time.Hour})
	for i := 0; i < 3; i++ {
		if d := s.Check(HostOf([]string{"--some", "unrecognised"}), "curl"); !d.Allowed {
			t.Fatalf("refused early at %d", i)
		}
	}
	if d := s.Check("", "curl"); d.Allowed {
		t.Fatal("unattributed requests were not bounded")
	}
}

func TestSnapshotOnlyCountsAttributedTargets(t *testing.T) {
	s := New(Limits{MaxPerTarget: 100, Window: time.Hour})
	s.Check("a.example", "curl")
	snap := s.Snapshot()
	if snap.TopTargets["a.example"] != 1 {
		t.Fatalf("target not counted: %v", snap.TopTargets)
	}
	if _, stray := snap.TopTargets[""]; stray {
		t.Fatal("the empty key leaked into the reported targets")
	}
}

func TestSnapshotIsRaceFree(t *testing.T) {
	s := New(Limits{MaxPerTarget: 1000, MaxTotal: 100000, Window: time.Hour})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			s.Check("a", "curl")
		}
		close(done)
	}()
	for i := 0; i < 200; i++ {
		_ = s.Snapshot()
	}
	<-done
}

var _ = context.Background
