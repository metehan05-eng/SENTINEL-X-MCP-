package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKubeconfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKubeconfigParsingAndFindings(t *testing.T) {
	body := `apiVersion: v1
kind: Config
current-context: prod-admin
clusters:
- name: prod
  cluster:
    server: https://prod.example.com:6443
    certificate-authority-data: Q0E=
- name: legacy
  cluster:
    server: http://legacy.example.com:8080
    insecure-skip-tls-verify: true
contexts:
- name: prod-admin
  context: {cluster: prod, user: admin, namespace: default}
- name: prod-dev
  context: {cluster: prod, user: dev, namespace: kube-system}
users:
- name: admin
  user:
    client-key-data: LS0t
- name: dev
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: aws
      args: ["eks", "get-token"]
`
	p := writeKubeconfig(t, body)
	kc, err := parseKubeconfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if kc.Kind != "Config" {
		t.Errorf("kind = %q", kc.Kind)
	}
	if len(kc.Clusters) != 2 || len(kc.Contexts) != 2 || len(kc.Users) != 2 {
		t.Errorf("counts: %d clusters, %d contexts, %d users",
			len(kc.Clusters), len(kc.Contexts), len(kc.Users))
	}

	findings := k8sFindings(kc)
	joined := flattenFindings(findings)

	// Plaintext HTTP must be the loudest thing in the report.
	if !strings.Contains(joined, "plaintext HTTP") {
		t.Errorf("plaintext API server not flagged: %s", joined)
	}
	if !strings.Contains(joined, "disables TLS verification") {
		t.Errorf("insecure-skip-tls-verify not flagged: %s", joined)
	}
	if !strings.Contains(joined, "client private key") {
		t.Errorf("embedded private key not flagged: %s", joined)
	}
	// An exec-based user must NOT be told to drop exec auth.
	for _, f := range findings {
		if strings.Contains(f.Summary, "dev") && strings.Contains(f.Remediate, "exec-based auth") {
			t.Errorf("exec-based auth should not be criticised: %+v", f)
		}
	}
	// The critical finding must sort out as critical.
	var sawCritical bool
	for _, f := range findings {
		if strings.Contains(f.Summary, "plaintext HTTP") && f.Severity == "critical" {
			sawCritical = true
		}
	}
	if !sawCritical {
		t.Error("a plaintext API server must be reported as critical, since bearer tokens would be sent in cleartext")
	}
}

func TestKubeconfigNoCertificateAuthority(t *testing.T) {
	body := `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://c.example.com
contexts: []
users: []
`
	kc, err := parseKubeconfig(writeKubeconfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(flattenFindings(k8sFindings(kc)), "trusts no certificate authority") {
		t.Error("a cluster with no CA must be flagged")
	}
}

func TestKubeconfigPasswordFinding(t *testing.T) {
	body := `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster: {server: "https://c.example.com", certificate-authority-data: Q0E=}
users:
- name: legacy
  user: {username: admin, password: hunter2}
`
	kc, err := parseKubeconfig(writeKubeconfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(flattenFindings(k8sFindings(kc)), "plaintext password") {
		t.Error("a stored password must be flagged")
	}
}

// A log full of noise must not produce a finding; that is what teaches a model
// to ignore the tool's output.
func TestLogAnalysisIgnoresNoise(t *testing.T) {
	a := newLogAggregator()
	a.consume("auth.log", strings.Join([]string{
		"Sep 25 10:00:01 host sshd[1]: Server listening on 0.0.0.0 port 22.",
		"Sep 25 10:00:02 host cron[2]: (root) CMD (test -x /usr/sbin/anacron)",
		"Sep 25 10:00:03 host systemd[1]: Started Session 1 of user root.",
	}, "\n"))
	res := a.result(5, []string{"auth.log"}, 1)
	if len(res.Bursts) != 0 {
		t.Errorf("benign lines produced %d bursts: %+v", len(res.Bursts), res.Bursts)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != "info" {
		t.Errorf("expected a single info finding, got %+v", res.Findings)
	}
}

// The finding that matters most: a login that succeeds only after a burst of
// failures against the same account.
func TestLogAnalysisDetectsSuccessfulGuess(t *testing.T) {
	a := newLogAggregator()
	var lines []string
	for i := 0; i < 12; i++ {
		lines = append(lines, "Sep 25 10:0"+string(rune('0'+i%10))+" host sshd[1]: Failed password for deploy from 10.0.0.9 port 5000 ssh2")
	}
	lines = append(lines, "Sep 25 10:05:00 host sshd[1]: Accepted password for deploy from 10.0.0.9 port 5001 ssh2")
	a.consume("auth.log", strings.Join(lines, "\n"))

	res := a.result(5, []string{"auth.log"}, 1)
	if len(res.Bursts) != 1 {
		t.Fatalf("want 1 burst, got %+v", res.Bursts)
	}
	b := res.Bursts[0]
	if b.Account != "deploy" {
		t.Errorf("account = %q", b.Account)
	}
	if b.Accepted != 1 {
		t.Errorf("accepted = %d, want 1", b.Accepted)
	}
	if b.Severity != "critical" {
		t.Errorf("severity = %q, want critical", b.Severity)
	}
	if !strings.Contains(res.Assessment, "POSSIBLE COMPROMISE") {
		t.Errorf("assessment should escalate: %q", res.Assessment)
	}
}

// A spray from many hosts is a different event from one noisy host, and the
// tool should say so.
func TestLogAnalysisDistinguishesSprayFromNoise(t *testing.T) {
	spray := newLogAggregator()
	var lines []string
	for h := 0; h < 8; h++ {
		for i := 0; i < 10; i++ {
			lines = append(lines,
				"Sep 25 11:00:00 10.0.0."+string(rune('0'+h))+" sshd[1]: Failed password for admin from 10.0.0."+string(rune('0'+h))+" port 22 ssh2")
		}
	}
	spray.consume("auth.log", strings.Join(lines, "\n"))
	res := spray.result(5, []string{"auth.log"}, 1)
	if len(res.Bursts) != 1 {
		t.Fatalf("want 1 burst, got %d", len(res.Bursts))
	}
	if !strings.Contains(res.Bursts[0].Assessment, "spray") {
		t.Errorf("many source hosts should read as a spray: %q", res.Bursts[0].Assessment)
	}
	if res.Bursts[0].Severity != "critical" {
		t.Errorf("spray severity = %q, want critical", res.Bursts[0].Severity)
	}

	noisy := newLogAggregator()
	var one []string
	for i := 0; i < 60; i++ {
		one = append(one, "Sep 25 11:00:00 host1 sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2")
	}
	noisy.consume("auth.log", strings.Join(one, "\n"))
	nres := noisy.result(5, []string{"auth.log"}, 1)
	if strings.Contains(nres.Bursts[0].Assessment, "spray") {
		t.Error("a single source host is not a spray")
	}
}

func TestLogAnalysisUnknownAccountsLowerSeverity(t *testing.T) {
	a := newLogAggregator()
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, "Sep 25 12:00:00 host sshd[1]: Invalid user oracle from 10.0.0.1 port 22")
		lines = append(lines, "Sep 25 12:00:01 host sshd[1]: Failed password for invalid user oracle from 10.0.0.1 port 22 ssh2")
	}
	a.consume("auth.log", strings.Join(lines, "\n"))
	res := a.result(5, []string{"auth.log"}, 1)
	if len(res.Bursts) != 1 {
		t.Fatalf("want 1 burst, got %+v", res.Bursts)
	}
	// Attempting accounts that do not exist is enumeration, not a breach.
	if res.Bursts[0].Severity != "low" {
		t.Errorf("severity = %q, want low for a non-existent account", res.Bursts[0].Severity)
	}
	if !strings.Contains(res.Bursts[0].Assessment, "does not exist") {
		t.Errorf("assessment should explain why severity was lowered: %q", res.Bursts[0].Assessment)
	}
}

func TestLogAnalysisFlagsNewUsersAndSudo(t *testing.T) {
	a := newLogAggregator()
	a.consume("syslog", strings.Join([]string{
		"Sep 25 13:00:00 host useradd[9]: new user: name=svcbackup, UID=0, GID=0, home=/var/backups",
		"Sep 25 13:00:01 host useradd[9]: new group: name=wheel",
		"Sep 25 13:01:00 host sudo: pam_unix(sudo:auth): authentication failure; logname=ops uid=501 euid=0 tty=/dev/pts/0 user=ops ruser=ops command=/bin/bash",
	}, "\n"))
	res := a.result(5, []string{"syslog"}, 1)

	if len(res.NewUsers) != 1 || res.NewUsers[0] != "svcbackup" {
		t.Errorf("new users = %v, want [svcbackup]", res.NewUsers)
	}
	if len(res.NewGroups) != 1 {
		t.Errorf("new groups = %v", res.NewGroups)
	}
	if res.SudoDenials != 1 {
		t.Errorf("sudo denials = %d, want 1", res.SudoDenials)
	}
	// A UID 0 account is the most dangerous thing in that log line and the
	// summary must not bury it.
	joined := flattenFindings(res.Findings)
	if !strings.Contains(joined, "account(s) were created") {
		t.Errorf("new-account finding missing: %s", joined)
	}
}

func TestLogThresholdIsRespected(t *testing.T) {
	a := newLogAggregator()
	a.consume("auth.log", strings.Join([]string{
		"Sep 25 14:00:00 host sshd[1]: Failed password for bob from 10.0.0.1 port 22 ssh2",
		"Sep 25 14:00:01 host sshd[1]: Failed password for bob from 10.0.0.1 port 22 ssh2",
	}, "\n"))
	if got := a.result(5, []string{"auth.log"}, 1); len(got.Bursts) != 0 {
		t.Errorf("2 failures should not trip a threshold of 5: %+v", got.Bursts)
	}
	if got := a.result(2, []string{"auth.log"}, 1); len(got.Bursts) != 1 {
		t.Errorf("2 failures should trip a threshold of 2: %+v", got.Bursts)
	}
}

func TestLogSourceExtraction(t *testing.T) {
	cases := map[string]string{
		"Sep 25 10:00:00 web01 sshd[1]: Accepted password for x from 1.2.3.4 port 2 ssh2": "web01",
		"short line": "unknown",
	}
	for line, want := range cases {
		if got := logSourceOf(line); got != want {
			t.Errorf("logSourceOf(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestLogFilesInDirSkipsCompressed(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"auth.log", "auth.log.1.gz", "messages", "kern.log.xz"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := logFilesInDir(dir, 10)
	if len(got) != 2 {
		t.Fatalf("want auth.log and messages only, got %v", got)
	}
	for _, g := range got {
		if strings.Contains(g, ".gz") || strings.Contains(g, ".xz") {
			t.Errorf("compressed rotation should be skipped: %s", g)
		}
	}
}

func flattenFindings(in []Finding) string {
	var b strings.Builder
	for _, f := range in {
		b.WriteString(f.Summary)
		b.WriteString(" | ")
		b.WriteString(f.Remediate)
		b.WriteString(" ; ")
	}
	return b.String()
}
