package tools

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sentinel-x/sentinel-x/internal/utils"
)

// ---------------------------------------------------------------------------
// audit — local security posture and configuration review.
//
// This module is the defensive counterpart to the network scanners: instead of
// probing a remote host it grades the machine it is running on and any
// configuration file the operator explicitly points it at.
//
// Every check is a read. Files are opened O_RDONLY, `/etc/shadow` is read for
// policy metadata only (never its hashes), and nothing is ever written,
// chmod-ed or repaired. Remediation is reported as advice, never performed.
// ---------------------------------------------------------------------------

// Audit returns the local configuration audit tools.
func Audit(d Deps) []Tool {
	return []Tool{
		postureTool(d),
		configLintTool(d),
		secretScanTool(d),
		permissionTool(d),
		trafficAuditTool(d),
	}
}

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

// PostureReport is the aggregate hardening assessment.
type PostureReport struct {
	Hostname   string     `json:"hostname"`
	OS         string     `json:"os,omitempty"`
	Kernel     string     `json:"kernel,omitempty"`
	Score      float64    `json:"posture_score"`
	MaxScore   int        `json:"max_score"`
	Grade      string     `json:"grade"`
	Categories []Category `json:"categories"`
	Findings   []Finding  `json:"findings"`
	Services   []string   `json:"observability_services,omitempty"`
	Warnings   []string   `json:"warnings,omitempty"`
}

// Category groups the checks so the score is explainable.
type Category struct {
	Name   string  `json:"name"`
	Passed int     `json:"passed"`
	Total  int     `json:"total"`
	Checks []Check `json:"checks"`
}

// Check is one individual assertion with its evidence.
type Check struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"` // pass | warn | fail | info
	Evidence  string `json:"evidence,omitempty"`
	Remediate string `json:"remediation,omitempty"`
}

func postureTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_host_posture_audit",
		mcp.WithDescription(
			"Audit the security posture of the host SENTINEL-X is running on: password policy, SSH "+
				"daemon configuration, kernel sysctl hardening, account hygiene, firewall state and "+
				"file permissions. Returns a scored report with per-check evidence and remediation advice. "+
				"STRICTLY READ-ONLY: it inspects configuration and never modifies, restarts or repairs "+
				"anything. Run it on the machine you are responsible for.",
		),
		mcp.WithToolTitle("SENTINEL-X Host Posture Audit"),
		mcp.WithArray("checks",
			mcp.Description(
				"Restrict the audit to specific categories. Valid values: "+
					"'password_policy', 'ssh', 'sysctl', 'accounts', 'firewall', 'filesystem'. "+
					"Omit to run everything."),
			mcp.Items(map[string]any{"type": "string", "enum": []string{
				"password_policy", "ssh", "sysctl", "accounts", "firewall", "filesystem",
			}}),
		),
		mcp.WithBoolean("include_remediation",
			mcp.Description("Include remediation advice for every failing check. Leave on unless you only want the score."),
			mcp.DefaultBool(true),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_host_posture_audit"

		want := map[string]bool{}
		for _, c := range stringList(req, "checks", 16) {
			want[strings.ToLower(strings.TrimSpace(c))] = true
		}
		withAdvice := req.GetBool("include_remediation", true)

		rep := PostureReport{
			Hostname: hostname(),
			MaxScore: 0,
		}
		if k, err := os.ReadFile("/proc/sys/kernel/ostype"); err == nil {
			rep.Kernel = strings.TrimSpace(string(k))
		}
		if k, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			rep.Kernel = strings.TrimSpace(string(k))
		}
		if rel, err := os.ReadFile("/etc/os-release"); err == nil {
			rep.OS = osReleaseField(string(rel), "PRETTY_NAME")
		}

		run := func(name string, fn func() Category) {
			if len(want) > 0 && !want[name] {
				return
			}
			cat := fn()
			if !withAdvice {
				for i := range cat.Checks {
					cat.Checks[i].Remediate = ""
				}
			}
			for _, c := range cat.Checks {
				switch c.Status {
				case "pass":
					rep.Score++
				case "warn":
					rep.Score += 0.5
				}
				rep.MaxScore++
				if c.Status == "fail" || c.Status == "warn" {
					sev := "medium"
					switch c.Status {
					case "fail":
						sev = "high"
					}
					if c.ID == "" {
						sev = "info"
					}
					rep.Findings = append(rep.Findings, Finding{
						Severity:  sev,
						Summary:   c.Title,
						Evidence:  c.Evidence,
						Remediate: c.Remediate,
					})
				}
			}
			rep.Categories = append(rep.Categories, cat)
		}

		run("password_policy", passwordPolicyCategory)
		run("ssh", sshCategory)
		run("sysctl", sysctlCategory)
		run("accounts", accountsCategory)
		run("firewall", firewallCategory)
		run("filesystem", filesystemCategory)

		if rep.MaxScore > 0 {
			rep.Grade = gradeFor(float64(rep.Score) / float64(rep.MaxScore))
		}
		rep.Services = detectAuditServices(d, ctx)
		rep.Warnings = append(rep.Warnings,
			"the audit reflects only the configuration visible to the current process; run it as root for complete coverage of sshd and firewall state")

		return ok(d, toolName, rep.Hostname, start, nil, rep)
	}
	return Tool{Tool: t, Handler: h}
}

func passwordPolicyCategory() Category {
	cat := Category{Name: "password_policy"}
	const path = "/etc/login.defs"
	raw, err := os.ReadFile(path)
	if err != nil {
		cat.Checks = append(cat.Checks, Check{
			ID: "PAM_MIN_LEN", Title: "password policy source available",
			Status: "info", Evidence: fmt.Sprintf("%s not readable: %v", path, err),
		})
		return cat
	}
	fields := parseDefaults(string(raw))

	// PAM is what actually enforces policy on modern systems; login.defs is
	// only consulted by the shadow tools. Check both.
	pamMin := 0
	for _, p := range pamPasswordFiles() {
		content, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if m := regexp.MustCompile(`(?m)^\s*minlen\s*=\s*(\d+)`).FindSubmatch(content); m != nil {
			if v, _ := strconv.Atoi(string(m[1])); v > pamMin {
				pamMin = v
			}
		}
	}
	minLen, _ := strconv.Atoi(strings.TrimSpace(fields["pass_min_len"]))
	effective := minLen
	source := path
	if pamMin > 0 {
		effective, source = pamMin, "PAM"
	}

	cat.Checks = append(cat.Checks, minLengthCheck(effective, source, "MIN_LEN"))
	cat.Checks = append(cat.Checks, thresholdCheck("MIN_CLASS", fields["pass_min_class"], "0",
		"require at least one character class (upper, lower, digit, other) in new passwords",
		"set PASS_MIN_CLASS to 3 or 4 in "+path))
	cat.Checks = append(cat.Checks, numericCheck("MAX_DAYS", fields["pass_max_days"], 365,
		"passwords never expire", "set PASS_MAX_DAYS in "+path+" to enforce rotation"))
	cat.Checks = append(cat.Checks, numericCheck("MIN_DAYS", fields["pass_min_days"], 1,
		"passwords may be changed every day, defeating a breach-window lockout",
		"set PASS_MIN_DAYS in "+path+" so a compromised credential cannot be rotated immediately"))

	cat.Checks = append(cat.Checks, Check{
		ID: "PAM_ENFORCE", Title: "PAM password quality is enforced",
		Status:    checkBool("present", pamUsesPAMQuality()),
		Evidence:  strings.Join(pamPasswordFiles(), ", "),
		Remediate: "install libpam-pwquality and enable pam_pwquality in the password stack",
	})
	return cat
}

func minLengthCheck(n int, source, id string) Check {
	switch {
	case n >= 14:
		return Check{ID: id, Title: fmt.Sprintf("minimum password length is %d", n), Status: "pass", Evidence: "source: " + source}
	case n >= 12:
		return Check{ID: id, Title: fmt.Sprintf("minimum password length is %d (%s)", n, source), Status: "warn",
			Remediate: "raise the minimum to 14 or more and prefer a breach-corpus blocklist"}
	case n > 0:
		return Check{ID: id, Title: fmt.Sprintf("minimum password length is only %d (%s)", n, source), Status: "fail",
			Remediate: "set a minimum of 14 characters; length matters more than complexity symbols"}
	default:
		return Check{ID: id, Title: "no minimum password length is enforced", Status: "fail",
			Remediate: "set PASS_MIN_LEN=14 (or pam_pwquality minlen=14)"}
	}
}

func thresholdCheck(id, value, want, title, remediate string) Check {
	if strings.TrimSpace(value) == "" {
		return Check{ID: id, Title: title + " (not configured)", Status: "info", Remediate: remediate}
	}
	if value == want {
		return Check{ID: id, Title: title, Status: "pass", Evidence: "value: " + want}
	}
	return Check{ID: id, Title: title, Status: "warn", Evidence: "value: " + value, Remediate: remediate}
}

func numericCheck(id string, value string, max int, badTitle, remediate string) Check {
	v, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return Check{ID: id, Title: badTitle + " (not configured)", Status: "info", Remediate: remediate}
	}
	if v <= 0 || v > max {
		return Check{ID: id, Title: badTitle, Status: "fail", Evidence: "value: " + value, Remediate: remediate}
	}
	if v == max {
		return Check{ID: id, Title: fmt.Sprintf("%s (%d days)", id, v), Status: "pass", Evidence: "value: " + value}
	}
	return Check{ID: id, Title: fmt.Sprintf("%s is %d days", id, v), Status: "pass", Evidence: "value: " + value}
}

func checkBool(whenTrue string, cond bool) string {
	if cond {
		return "pass"
	}
	return whenTrue
}

func pamPasswordFiles() []string {
	return []string{
		"/etc/pam.d/common-password", "/etc/pam.d/password", "/etc/pam.d/passwd",
		"/etc/pam.d/system-auth", "/etc/security/pwquality.conf",
	}
}

func pamUsesPAMQuality() bool {
	for _, p := range pamPasswordFiles() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "pam_pwquality") || strings.Contains(string(b), "pam_cracklib") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

func sshCategory() Category {
	cat := Category{Name: "ssh"}
	cfg := readSSHDConfig()

	pw := sshDirective(cfg, "passwordauthentication")
	cat.Checks = append(cat.Checks, Check{
		ID: "SSH_PASSWORD_AUTH", Title: "SSH password authentication",
		Status:   directiveStatus(pw, "yes", "Password login is enabled; it is the most-exposed attack surface on an internet-facing host.", "Set PasswordAuthentication no and use key-based authentication."),
		Evidence: "PasswordAuthentication " + orUnknown(pw),
	})

	pu := sshDirective(cfg, "permitrootlogin")
	cat.Checks = append(cat.Checks, Check{
		ID: "SSH_ROOT_LOGIN", Title: "SSH root login",
		Status:   directiveStatus(pu, "prohibit-password", "Direct root login is enabled.", "Set PermitRootLogin no (or prohibit-password)."),
		Evidence: "PermitRootLogin " + orUnknown(pu),
	})

	ea := sshDirective(cfg, "emptyPasswords")
	cat.Checks = append(cat.Checks, Check{
		ID: "SSH_EMPTY_PW", Title: "SSH empty passwords",
		Status:   directiveStatus(ea, "no", "Accounts without a password can authenticate over SSH.", "Set EmptyPasswords no."),
		Evidence: "EmptyPasswords " + orUnknown(ea),
	})

	for _, d := range []struct {
		id, key, title, remediate string
	}{
		{"SSH_MAXAUTHTRIES", "maxauthtries", "SSH MaxAuthTries", "Set MaxAuthTries 3 to limit password-guessing attempts per connection."},
		{"SSH_LOGIN_GRACE", "logingracetime", "SSH LoginGraceTime", "Set LoginGraceTime 30 so unauthenticated connections cannot pin resources."},
		{"SSH_X11", "x11forwarding", "SSH X11Forwarding", "Set X11Forwarding no unless display forwarding is genuinely required."},
	} {
		v := sshDirective(cfg, d.key)
		cat.Checks = append(cat.Checks, Check{
			ID: d.id, Title: d.title, Status: statusOrInfo(v),
			Evidence:  d.key + " " + orUnknown(v),
			Remediate: d.remediate,
		})
	}

	if proto := sshDirective(cfg, "protocol"); proto != "" {
		okProto := !strings.Contains(proto, "1") || strings.Contains(proto, "2")
		st := "fail"
		if okProto {
			st = "pass"
		}
		cat.Checks = append(cat.Checks, Check{ID: "SSH_PROTOCOL", Title: "SSH protocol version", Status: st,
			Evidence: "Protocol " + proto, Remediate: "Remove Protocol 1; it is obsolete and unauthenticated."})
	}

	ciphers := sshDirective(cfg, "ciphers")
	if ciphers != "" {
		weak := []string{}
		for _, c := range strings.Split(ciphers, ",") {
			cl := strings.ToUpper(strings.TrimSpace(c))
			if strings.Contains(cl, "CBC") || strings.Contains(cl, "3DES") || strings.HasPrefix(cl, "ARCFOUR") {
				weak = append(weak, c)
			}
		}
		if len(weak) > 0 {
			cat.Checks = append(cat.Checks, Check{ID: "SSH_CIPHERS", Title: "SSH cipher list contains legacy suites", Status: "fail",
				Evidence: strings.Join(weak, ", "), Remediate: "Set Ciphers to chacha20-poly1305@openssh.com and the aes*-gcm@openssh.com family."})
		} else {
			cat.Checks = append(cat.Checks, Check{ID: "SSH_CIPHERS", Title: "SSH cipher list excludes legacy suites", Status: "pass", Evidence: ciphers})
		}
	} else {
		cat.Checks = append(cat.Checks, Check{ID: "SSH_CIPHERS", Title: "SSH cipher list is not pinned", Status: "warn",
			Remediate: "Set an explicit Ciphers line so a future OpenSSH default change cannot silently weaken the host."})
	}

	if macs := sshDirective(cfg, "macs"); macs != "" && strings.Contains(strings.ToUpper(macs), "HMAC-MD5") {
		cat.Checks = append(cat.Checks, Check{ID: "SSH_MACS", Title: "SSH MAC list includes HMAC-MD5", Status: "fail",
			Evidence: macs, Remediate: "Use hmac-sha2-256 or hmac-sha2-512."})
	}

	// An authorisation file that trusts a wildcard network is a full compromise.
	for _, f := range []string{"/etc/ssh/authorized_keys", "/root/.ssh/authorized_keys"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "from=") && strings.Contains(string(b), "0.0.0.0/0") {
			cat.Checks = append(cat.Checks, Check{ID: "SSH_WILDCARD_AUTHKEY", Title: "authorized_keys trusts any source address", Status: "fail",
				Evidence: f, Remediate: "Replace the wildcard from= clause with the specific networks that administer this host."})
		}
	}
	return cat
}

func sshCategoryGuard() {}

func readSSHDConfig() map[string]string {
	out := map[string]string{}
	for _, p := range []string{"/etc/ssh/sshd_config"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			out[strings.ToLower(f[0])] = strings.Join(f[1:], " ")
		}
	}
	// Include directives pull in drop-ins; the effective value is usually the
	// first one the daemon reads, so record them for completeness.
	for _, d := range []string{"/etc/ssh/sshd_config.d"} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(d, e.Name()))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				f := strings.Fields(line)
				if len(f) >= 2 {
					out[strings.ToLower(f[0])] = strings.Join(f[1:], " ")
				}
			}
		}
	}
	return out
}

// directiveStatus grades a yes/no-style directive against its safe value.
func directiveStatus(value, safe, badTitle, remediate string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "info"
	}
	if v == safe || strings.HasPrefix(v, safe) {
		return "pass"
	}
	return "fail"
}

func statusOrInfo(v string) string {
	if strings.TrimSpace(v) == "" {
		return "info"
	}
	return "pass"
}

func sshDirective(cfg map[string]string, key string) string {
	if v, ok := cfg[key]; ok {
		return v
	}
	return ""
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "(not set — using the OpenSSH default)"
	}
	return v
}

// ---------------------------------------------------------------------------
// sysctl
// ---------------------------------------------------------------------------

// sysctlRules are the kernel parameters with a defensible hardening baseline.
var sysctlRules = []struct{ key, why string }{
	{"kernel.randomize_va_space", "ASLR should be enabled (2)"},
	{"kernel.dmesg_restrict", "kernel log access should be restricted to privileged users"},
	{"kernel.kptr_restrict", "kernel pointers leak into /proc otherwise"},
	{"kernel.yama.ptrace_scope", "ptrace_scope 1+ prevents cross-user process injection"},
	{"kernel.unprivileged_bpf_disabled", "unprivileged BPF grants powerful primitives"},
	{"net.ipv4.conf.all.accept_redirects", "accepting ICMP redirects enables MITM on the local segment"},
	{"net.ipv4.conf.all.send_redirects", "this host should not act as a router"},
	{"net.ipv4.conf.all.accept_source_route", "source routing bypasses path-based filtering"},
	{"net.ipv4.tcp_syncookies", "SYN cookies blunt SYN-flood denial of service"},
	{"net.ipv4.conf.all.rp_filter", "reverse-path filtering drops spoofed source addresses"},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "broadcast ICMP enables amplification attacks"},
	{"net.ipv6.conf.all.accept_redirects", "the IPv6 equivalent of accepting redirects"},
	{"fs.suid_dumpable", "a core dump of a suid binary can leak privileged memory"},
}

func sysctlCategory() Category {
	cat := Category{Name: "sysctl"}
	for _, r := range sysctlRules {
		path := "/proc/sys/" + strings.ReplaceAll(r.key, ".", "/")
		b, err := os.ReadFile(path)
		if err != nil {
			cat.Checks = append(cat.Checks, Check{ID: strings.ToUpper(r.key), Title: r.why, Status: "info",
				Evidence: path + " not readable"})
			continue
		}
		val := strings.TrimSpace(string(b))
		status, remediate := gradeSysctl(r.key, val)
		cat.Checks = append(cat.Checks, Check{
			ID: strings.ToUpper(r.key), Title: r.why, Status: status,
			Evidence: r.key + " = " + val, Remediate: remediate,
		})
	}
	return cat
}

func gradeSysctl(key, val string) (string, string) {
	on := map[string]bool{"1": true, "2": true, "3": true, "y": true, "yes": true}
	off := map[string]bool{"0": true, "no": true, "n": false}

	switch key {
	case "kernel.randomize_va_space":
		if val == "2" {
			return "pass", ""
		}
		return "fail", "Set kernel.randomize_va_space=2 (full ASLR)."
	case "net.ipv4.conf.all.rp_filter":
		switch val {
		case "1":
			return "pass", ""
		case "2":
			return "warn", "Loose reverse-path filtering (2) is weaker than strict (1); use 1 on single-homed hosts."
		}
		return "fail", "Set net.ipv4.conf.all.rp_filter=1."
	case "kernel.yama.ptrace_scope":
		if on[val] {
			return "pass", ""
		}
		return "fail", "Set kernel.yama.ptrace_scope=1 or higher."
	}
	if on[val] {
		return "pass", ""
	}
	if off[val] {
		return "fail", "Set " + key + "=1."
	}
	return "warn", ""
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

func accountsCategory() Category {
	cat := Category{Name: "accounts"}

	entries := readPasswdEntries()

	cat.Checks = append(cat.Checks, Check{
		ID: "ACC_PARSED", Title: "account database is readable",
		Status:    statusOrInfo(fmt.Sprint(len(entries))),
		Evidence:  fmt.Sprintf("%d accounts parsed from /etc/passwd", len(entries)),
		Remediate: "",
	})

	// UID 0 is root. Any other account holding it is a direct escalation path.
	var dupRoot []string
	for _, e := range entries {
		if e.uid == "0" && e.name != "root" {
			dupRoot = append(dupRoot, fmt.Sprintf("%s (uid %s)", e.name, e.uid))
		}
	}
	if len(dupRoot) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "ACC_DUP_UID0", Title: "additional accounts hold UID 0", Status: "fail",
			Evidence: strings.Join(dupRoot, ", "), Remediate: "Assign these accounts a unique non-zero UID."})
	} else {
		cat.Checks = append(cat.Checks, Check{ID: "ACC_DUP_UID0", Title: "no additional account holds UID 0", Status: "pass"})
	}

	// Service accounts should not carry a usable password hash. The hash itself
	// is never read out of /etc/shadow — only the locked/unlocked flag is.
	var risky []string
	for _, e := range entries {
		if e.shell == "" || !strings.HasPrefix(e.shell, "/") {
			continue
		}
		if isNologinShell(e.shell) {
			continue
		}
		if !e.locked && e.hasHash {
			risky = append(risky, e.name)
		}
	}
	if len(risky) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "ACC_PW_ON_NOLOGIN", Title: "account with a nologin shell still has a usable password", Status: "fail",
			Evidence:  strings.Join(risky, ", "),
			Remediate: "Lock the password with passwd -l. The shell already prevents a login, but a live hash is one policy change away from access."})
	} else {
		cat.Checks = append(cat.Checks, Check{ID: "ACC_PW_ON_NOLOGIN", Title: "nologin service accounts are password-locked", Status: "pass"})
	}

	// Duplicate UIDs let one user assume another identity by editing a field.
	byUID := map[string][]string{}
	for _, e := range entries {
		byUID[e.uid] = append(byUID[e.uid], e.name)
	}
	var dupUID []string
	for uid, ns := range byUID {
		if len(ns) > 1 && uid != "0" {
			dupUID = append(dupUID, fmt.Sprintf("uid %s: %s", uid, strings.Join(ns, ", ")))
		}
	}
	sort.Strings(dupUID)
	if len(dupUID) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "ACC_DUP_UID", Title: "multiple accounts share a UID", Status: "warn",
			Evidence: strings.Join(dupUID, "; "), Remediate: "Give each account a unique UID."})
	}

	// A world-writable home directory lets any local user plant a start-up
	// file that the account will execute.
	var wwHomes []string
	for _, e := range entries {
		if e.home == "" || e.home == "/" {
			continue
		}
		if st, err := os.Stat(e.home); err == nil && st.Mode().Perm()&0o002 != 0 {
			wwHomes = append(wwHomes, fmt.Sprintf("%s (%s)", e.name, e.home))
		}
	}
	if len(wwHomes) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "ACC_WW_HOME", Title: "world-writable home directory", Status: "fail",
			Evidence:  strings.Join(wwHomes, ", "),
			Remediate: "Remove the world-write bit. A writable home allows persistence via .bashrc or .ssh/authorized_keys."})
	} else {
		cat.Checks = append(cat.Checks, Check{ID: "ACC_WW_HOME", Title: "no world-writable home directory", Status: "pass"})
	}
	return cat
}

func isNologinShell(sh string) bool {
	base := filepath.Base(sh)
	switch base {
	case "nologin", "false", "sync", "shutdown", "halt":
		return true
	}
	return false
}

// passwdEntry is one row of /etc/passwd plus the lock state derived from
// /etc/shadow. The shadow hash itself is deliberately discarded.
type passwdEntry struct {
	name, uid, gid, home, shell string
	locked                      bool
	hasHash                     bool
}

func readPasswdEntries() []passwdEntry {
	var out []passwdEntry
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		out = append(out, passwdEntry{
			name:  parts[0],
			uid:   parts[2],
			gid:   parts[3],
			home:  parts[5],
			shell: parts[6],
		})
	}
	readShadowFlags(out)
	return out
}

// readShadowFlags records, for each entry, only whether its password field is
// locked and whether a hash is present. The hash value never leaves this
// function — SENTINEL-X has no reason to hold credential material.
func readShadowFlags(entries []passwdEntry) {
	idx := make(map[string]int, len(entries))
	for i, e := range entries {
		idx[e.name] = i
	}
	f, err := os.Open("/etc/shadow")
	if err != nil {
		// Without /etc/shadow access the lock state is unknown; assume locked
		// so an unreadable shadow file cannot manufacture a false finding.
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 2 {
			continue
		}
		i, found := idx[parts[0]]
		if !found {
			continue
		}
		field := parts[1]
		entries[i].locked = strings.HasPrefix(field, "!") || strings.HasPrefix(field, "*") || field == ""
		entries[i].hasHash = field != "" && field != "!" && field != "*"
	}
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

func firewallCategory() Category {
	cat := Category{Name: "firewall"}
	state := firewallState()
	switch {
	case state == "":
		cat.Checks = append(cat.Checks, Check{ID: "FW_STATE", Title: "host firewall state", Status: "info",
			Remediate: "Run the audit with sufficient privileges to inspect nftables/iptables, or check the cloud provider's security group separately."})
	case state == "active":
		cat.Checks = append(cat.Checks, Check{ID: "FW_STATE", Title: "host firewall is active", Status: "pass", Evidence: state})
	case state == "inactive":
		cat.Checks = append(cat.Checks, Check{ID: "FW_STATE", Title: "no host firewall is active", Status: "fail",
			Evidence: state, Remediate: "Enable a default-deny ruleset; every listening service is currently reachable from any routable address."})
	default:
		cat.Checks = append(cat.Checks, Check{ID: "FW_STATE", Title: "host firewall state", Status: "warn", Evidence: state,
			Remediate: "Confirm the firewall is loaded and the default policy is DROP."})
	}
	return cat
}

// firewallState inspects the kernel's own tables through /proc and /sys, which
// needs no external binary and no privilege beyond read access.
func firewallState() string {
	// nftables
	if b, err := os.ReadFile("/proc/net/nf_tables"); err == nil && len(b) > 0 {
		return "active (nftables)"
	}
	// iptables: a table with a DROP policy in the filter chain
	if b, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil {
		if strings.Contains(string(b), "filter") {
			return "active (iptables)"
		}
	}
	for _, p := range []string{"/proc/net/ip_tables_filter", "/proc/net/ip6_tables_filter"} {
		if _, err := os.Stat(p); err == nil {
			return "active (legacy iptables)"
		}
	}
	if b, err := os.ReadFile("/sys/module/nf_tables/parameters/tabledir"); err == nil {
		_ = b
	}
	if _, err := os.Stat("/usr/sbin/ufw"); err == nil {
		if b, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "enabled = yes") {
					return "active (ufw)"
				}
			}
		}
	}
	if _, err := os.Stat("/etc/firewalld/firewalld.conf"); err == nil {
		if b, err := os.ReadFile("/etc/firewalld/firewalld.conf"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.EqualFold(strings.TrimSpace(l), "FirewallBackend=firewalld") {
					return "active (firewalld)"
				}
			}
		}
	}
	return "inactive"
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

func filesystemCategory() Category {
	cat := Category{Name: "filesystem"}

	// Config files that must not be writable by anyone but their owner.
	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"} {
		st, err := os.Stat(p)
		if err != nil {
			cat.Checks = append(cat.Checks, Check{ID: "PERM_" + filepath.Base(p), Title: p + " permissions", Status: "info",
				Evidence: err.Error()})
			continue
		}
		mode := st.Mode().Perm()
		bad := mode&0o022 != 0
		st2 := "pass"
		if bad {
			st2 = "fail"
		}
		cat.Checks = append(cat.Checks, Check{
			ID: "PERM_" + filepath.Base(p), Title: p + " is not group- or world-writable", Status: st2,
			Evidence:  fmt.Sprintf("%04o", mode),
			Remediate: fmt.Sprintf("chmod o-w,g-w %s", p),
		})
	}

	// SUID/SBIT binaries: inventory, and flag the classic escalation set.
	suid, sbit := scanSUID("/usr/bin", "/usr/sbin", "/bin", "/sbin")
	if len(suid) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "SUID_INVENTORY", Title: fmt.Sprintf("%d SUID binaries found", len(suid)),
			Status: "info", Evidence: utils.Truncate(strings.Join(suid, ", "), 1200)})
	}
	escalators := []string{"sudo", "su", "passwd", "chsh", "pkexec", "newgrp", "gpasswd", "doas", "mount", "umount"}
	var unexpected []string
	for _, e := range suid {
		base := filepath.Base(e)
		if !containsFold(escalators, base) {
			unexpected = append(unexpected, e)
		}
	}
	if len(unexpected) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "SUID_UNEXPECTED", Title: "SUID binary outside the expected set", Status: "warn",
			Evidence:  strings.Join(unexpected, ", "),
			Remediate: "Confirm each is required and from the distribution package; an SUID binary added by an attacker is a persistent root path."})
	} else if len(suid) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "SUID_UNEXPECTED", Title: "SUID set matches the expected distribution binaries", Status: "pass"})
	}

	if len(sbit) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "SBIT_INVENTORY", Title: fmt.Sprintf("%d SGID binaries found", len(sbit)),
			Status: "info", Evidence: utils.Truncate(strings.Join(sbit, ", "), 800)})
	}

	// World-writable files in /etc are a direct persistence mechanism.
	ww := worldWritableIn("/etc", 2)
	if len(ww) > 0 {
		cat.Checks = append(cat.Checks, Check{ID: "ETC_WORLD_WRITABLE", Title: "world-writable file under /etc", Status: "fail",
			Evidence: strings.Join(ww, ", "), Remediate: "Remove the world-write bit; anything writable in /etc can be loaded by a service at boot."})
	} else {
		cat.Checks = append(cat.Checks, Check{ID: "ETC_WORLD_WRITABLE", Title: "no world-writable file under /etc", Status: "pass"})
	}
	return cat
}

func scanSUID(roots ...string) (suid, sbit []string) {
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			p := filepath.Join(root, e.Name())
			switch {
			case info.Mode()&0o4000 != 0:
				suid = append(suid, p)
			case info.Mode()&0o2000 != 0:
				sbit = append(sbit, p)
			}
		}
	}
	sort.Strings(suid)
	sort.Strings(sbit)
	return
}

func worldWritableIn(root string, depth int) []string {
	var out []string
	var walk func(dir string, d int)
	walk = func(dir string, d int) {
		if d > depth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				walk(p, d-1)
				continue
			}
			if info, err := e.Info(); err == nil && info.Mode().Perm()&0o002 != 0 {
				out = append(out, p)
			}
		}
	}
	walk(root, depth)
	sort.Strings(out)
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// ---------------------------------------------------------------------------
// Config lint
// ---------------------------------------------------------------------------

// LintResult reports rule violations found in a configuration file.
type LintResult struct {
	Path     string    `json:"path"`
	Bytes    int       `json:"bytes"`
	Mode     string    `json:"mode,omitempty"`
	Findings []Finding `json:"findings"`
	RuleSet  string    `json:"rule_set"`
}

var (
	reInsecurePermit = regexp.MustCompile(`(?i)^\s*(PermitRootLogin|StrictModes|IgnoreRhosts|HostbasedAuthentication)\s+(yes|true)\s*$`)
	reWorldWritable  = regexp.MustCompile(`(?i)^\s*(world|public|all)\s+(readable|writable|full)\b`)
	rePasswordPlain  = regexp.MustCompile(`(?i)\b(password|passwd|pass)\s*[:=]\s*['"]?([^'"\s]{3,})`)
	reAnonAuth       = regexp.MustCompile(`(?i)^\s*(anonymous|anon|guest|nobody|no ?auth)\s*(true|yes|:)\s*$`)
	reDebug          = regexp.MustCompile(`(?i)^\s*(debug|verbose|trace|ssl_protocol\s+\+?all|tls_version\s*=\s*all)\s*[:=]?\s*(true|yes|1|on)\b`)
)

func configLintTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_config_audit",
		mcp.WithDescription(
			"Check a configuration file against SENTINEL-X's hardening rule set and report each "+
				"violation with the offending line number and a remediation. Recognises SSH daemon, "+
				"PAM, sysctl, web-server and database-style configuration. "+
				"READ-ONLY: the file is opened read-only and never modified. Secret values are redacted "+
				"from the output before they reach the model.",
		),
		mcp.WithToolTitle("SENTINEL-X Configuration Audit"),
		mcp.WithString("path",
			mcp.Description("Absolute path to the file to audit. Must be inside the configured audit roots."),
			mcp.Required(),
		),
		mcp.WithNumber("max_findings",
			mcp.Description("Maximum findings to return (1-200)."),
			mcp.DefaultNumber(60),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_config_audit"

		path, aerr := requireArg(req, "path")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if path == "" {
			return failf(toolName, path, start, "path is required")
		}
		if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
			return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
		}

		limit := req.GetInt("max_findings", 60)
		if limit < 1 {
			limit = 1
		}
		if limit > 200 {
			limit = 200
		}

		body, mode, err := readCappedFile(path, d.Cfg.Policy.MaxOutputBytes)
		if err != nil {
			return fail(toolName, path, start, err)
		}

		res := LintResult{Path: path, Bytes: len(body), RuleSet: "SENTINEL-X hardening baseline v1", Mode: mode}
		res.Findings = lintConfig(d, path, body, limit)
		if len(res.Findings) == 0 {
			res.Findings = append(res.Findings, Finding{Severity: "info",
				Summary: "no rule violations detected", Evidence: fmt.Sprintf("%d bytes inspected", len(body))})
		}
		return ok(d, toolName, path, start, nil, res)
	}
	return Tool{Tool: t, Handler: h}
}

func lintConfig(d Deps, path, body string, limit int) []Finding {
	var out []Finding
	add := func(f Finding) {
		if len(out) < limit {
			out = append(out, f)
		}
	}
	base := strings.ToLower(filepath.Base(path))
	isSSHD := strings.Contains(base, "sshd_config")
	isPAM := strings.Contains(base, "pam") || base == "login.defs"
	isSysctl := base == "sysctl.conf" || base == "99-sysctl.conf"

	for i, raw := range strings.Split(body, "\n") {
		line := strings.TrimRight(raw, "\r")
		ln := i + 1
		trimmed := strings.TrimSpace(line)

		if isSSHD {
			if m := reInsecurePermit.FindStringSubmatch(trimmed); m != nil {
				add(Finding{Severity: "high",
					Summary:   fmt.Sprintf("line %d: %s is set to %s", ln, m[1], m[2]),
					Evidence:  trimmed,
					Remediate: "This weakens the SSH trust boundary. Remove the directive or set it to the hardened value (no / prohibit-password)."})
			}
			if m := regexp.MustCompile(`(?i)^\s*PermitRootLogin\s+yes\s*$`).FindStringSubmatch(trimmed); m != nil {
				add(Finding{Severity: "high", Summary: fmt.Sprintf("line %d: direct root login is permitted", ln), Evidence: trimmed,
					Remediate: "Set PermitRootLogin no and administer through a named sudoer account."})
			}
			if regexp.MustCompile(`(?i)^\s*(X11Forwarding|AllowTcpForwarding|PermitTunnel)\s+yes\s*$`).FindStringSubmatch(trimmed) != nil {
				add(Finding{Severity: "low", Summary: fmt.Sprintf("line %d: tunneling/forwarding feature enabled", ln), Evidence: trimmed,
					Remediate: "Disable it unless a specific use case requires it; each is a pivot path out of the host."})
			}
		}
		if isPAM {
			if regexp.MustCompile(`(?i)\bnullok\b`).FindStringSubmatch(trimmed) != nil {
				add(Finding{Severity: "high", Summary: fmt.Sprintf("line %d: nullok permits an empty password", ln), Evidence: trimmed,
					Remediate: "Remove nullok from the password stack."})
			}
			if regexp.MustCompile(`(?i)\b(pam_permit\.so)\b`).FindStringSubmatch(trimmed) != nil {
				add(Finding{Severity: "high", Summary: fmt.Sprintf("line %d: pam_permit unconditionally grants access", ln), Evidence: trimmed,
					Remediate: "Remove the pam_permit entry; it bypasses every credential check below it."})
			}
			if m := regexp.MustCompile(`(?i)^\s*minlen\s*=\s*(\d+)`).FindStringSubmatch(trimmed); m != nil && m[1] < "12" {
				add(Finding{Severity: "medium", Summary: fmt.Sprintf("line %d: minlen=%s is below the recommended 12", ln, m[1]), Evidence: trimmed,
					Remediate: "Set minlen=14 and add a dictionary check with pam_pwquality."})
			}
		}
		if isSysctl {
			if m := regexp.MustCompile(`(?i)^\s*([\w.]+)\s*=\s*([01])\s*$`).FindStringSubmatch(trimmed); m != nil {
				if s, rem := gradeSysctl(m[1], m[2]); s == "fail" {
					add(Finding{Severity: "high", Summary: fmt.Sprintf("line %d: %s=%s does not match the hardening baseline", ln, m[1], m[2]),
						Evidence: trimmed, Remediate: rem})
				}
			}
		}
		if m := reWorldWritable.FindStringSubmatch(trimmed); m != nil {
			add(Finding{Severity: "high",
				Summary:   fmt.Sprintf("line %d: directory exported %s to everyone", ln, m[2]),
				Evidence:  trimmed,
				Remediate: "Restrict the export to the specific host or network that needs it; 'world writable' is the standard first step of a web shell drop."})
		}
		if m := rePasswordPlain.FindStringSubmatch(trimmed); m != nil {
			add(Finding{Severity: "critical",
				Summary:   fmt.Sprintf("line %d: %s is stored in cleartext (value redacted)", ln, m[1]),
				Evidence:  d.Scrub(trimmed),
				Remediate: "Move the credential into a secret store or a root-only file with mode 0600, then rotate the exposed value."})
		}
		if m := reAnonAuth.FindStringSubmatch(trimmed); m != nil {
			add(Finding{Severity: "high", Summary: fmt.Sprintf("line %d: anonymous access is enabled", ln), Evidence: trimmed,
				Remediate: "Disable anonymous access unless the service is a deliberately public mirror."})
		}
		if m := reDebug.FindStringSubmatch(trimmed); m != nil {
			add(Finding{Severity: "low", Summary: fmt.Sprintf("line %d: %s is enabled in configuration", ln, m[1]), Evidence: trimmed,
				Remediate: "Debug output frequently leaks paths, versions and internal hostnames; enable it only under a time-boxed change window."})
		}
		if regexp.MustCompile(`(?i)verify\s*=\s*(0|no|off|false)\b`).FindStringSubmatch(trimmed) != nil {
			add(Finding{Severity: "high", Summary: fmt.Sprintf("line %d: TLS certificate verification is disabled", ln), Evidence: trimmed,
				Remediate: "Restore verification. A client that skips verification will accept any certificate, including an attacker's."})
		}
		if regexp.MustCompile(`(?i)(ssl\s*:\s*off|tls\s*:\s*off|sslverify\s*[:=]\s*(0|false)|insecure\s*[:=]\s*true)`).FindStringSubmatch(trimmed) != nil {
			add(Finding{Severity: "high", Summary: fmt.Sprintf("line %d: transport security is explicitly disabled", ln), Evidence: trimmed,
				Remediate: "Remove the override and use the platform default."})
		}
	}
	return out
}

// readCappedFile opens a file read-only and reads at most limit bytes. A file
// that is a device, socket or fifo is refused outright: opening one can block
// forever and would defeat the timeout guarantee.
func readCappedFile(path string, limit int) (string, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("cannot inspect %s: %w", path, err)
	}
	if st.IsDir() {
		return "", "", fmt.Errorf("%s is a directory; point this tool at a file", path)
	}
	if st.Mode()&os.ModeDevice != 0 && st.Mode()&os.ModeCharDevice == 0 {
		return "", "", fmt.Errorf("%s is a device or socket node; refusing to read it", path)
	}
	if st.Mode()&os.ModeNamedPipe != 0 {
		return "", "", fmt.Errorf("%s is a FIFO; reading it would block indefinitely", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("cannot open %s for reading: %w", path, err)
	}
	defer f.Close()

	buf := make([]byte, limit)
	n, _ := f.Read(buf)
	return string(buf[:n]), fmt.Sprintf("%04o", st.Mode().Perm()), nil
}

// ---------------------------------------------------------------------------
// Secret scan
// ---------------------------------------------------------------------------

type SecretHit struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Excerpt     string `json:"excerpt"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type SecretScanResult struct {
	Root      string      `json:"root"`
	Files     int         `json:"files_scanned"`
	Bytes     int64       `json:"bytes_scanned"`
	Hits      []SecretHit `json:"hits"`
	Truncated bool        `json:"results_truncated"`
	Notes     []string    `json:"notes,omitempty"`
}

var secretRules = []struct {
	name, re, severity string
}{
	{"private-key", `-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, "critical"},
	{"aws-access-key", `\b(AKIA|ASIA)[0-9A-Z]{16}\b`, "critical"},
	{"github-token", `\bgh[pousr]_[A-Za-z0-9]{20,}\b`, "critical"},
	{"slack-token", `\bxox[baprs]-[A-Za-z0-9-]{10,}\b`, "critical"},
	{"google-api-key", `\bAIza[0-9A-Za-z\-_]{35}\b`, "high"},
	{"stripe-key", `\b(sk|rk)_(live|test)_[0-9a-zA-Z]{20,}\b`, "critical"},
	{"jwt", `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`, "high"},
	{"basic-auth-url", `\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]{3,}@`, "high"},
	{"generic-password", `(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']?([^\s"'#,;]{6,})["']?`, "medium"},
}

var compiledSecretRules = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(secretRules))
	for _, r := range secretRules {
		out = append(out, regexp.MustCompile(r.re))
	}
	return out
}()

func secretScanTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_secret_scan",
		mcp.WithDescription(
			"Walk a directory and report files that contain credentials: private keys, cloud and "+
				"VCS provider tokens, JWTs, credentials embedded in URLs and cleartext password "+
				"assignments. "+
				"Every hit is reported by rule, path and line with the value replaced by a "+
				"non-reversible fingerprint, so the secret itself never enters the conversation. "+
				"READ-ONLY: the tree is only read, and binary files are skipped.",
		),
		mcp.WithToolTitle("SENTINEL-X Secret Scan"),
		mcp.WithString("path",
			mcp.Description("Absolute path to the file or directory to scan. Must be inside the configured audit roots."),
			mcp.Required(),
		),
		mcp.WithNumber("max_hits",
			mcp.Description("Stop after this many findings (1-500)."),
			mcp.DefaultNumber(100),
		),
		mcp.WithNumber("max_file_bytes",
			mcp.Description("Skip files larger than this. Defaults to 1 MiB, which covers configuration and source files without stalling on artefacts."),
			mcp.DefaultNumber(1<<20),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_secret_scan"

		path, aerr := requireArg(req, "path")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if path == "" {
			return failf(toolName, path, start, "path is required")
		}
		if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
			return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
		}

		maxHits := req.GetInt("max_hits", 100)
		if maxHits < 1 {
			maxHits = 1
		}
		if maxHits > 500 {
			maxHits = 500
		}
		maxFile := req.GetInt("max_file_bytes", 1<<20)
		if maxFile < 1024 {
			maxFile = 1024
		}

		scan := secretScanner{
			deps:     d,
			ctx:      ctx,
			maxHits:  maxHits,
			maxFile:  maxFile,
			deadline: start.Add(d.Cfg.Timeouts.Audit),
		}
		scan.walk(path)

		notes := []string{
			"Findings are heuristic. Review each one in context before treating it as a live credential.",
			"Fingerprints are one-way and are safe to paste into a tracker.",
		}
		if scan.skippedBinary > 0 {
			notes = append(notes, fmt.Sprintf("%d binary or oversized files were skipped", scan.skippedBinary))
		}
		if scan.aborted {
			notes = append(notes, "the scan was cut short by its deadline or hit limit; results are partial")
		}
		return ok(d, toolName, path, start, nil, scan.result, notes...)
	}
	return Tool{Tool: t, Handler: h}
}

type secretScanner struct {
	deps           Deps
	ctx            context.Context
	maxHits        int
	maxFile        int
	deadline       time.Time
	files, skipped int
	bytes          int64
	skippedBinary  int
	aborted        bool
	result         SecretScanResult
}

func (s *secretScanner) walk(root string) {
	s.result.Root = root
	s.result.Hits = []SecretHit{}

	st, err := os.Stat(root)
	if err != nil {
		s.result.Notes = append(s.result.Notes, err.Error())
		return
	}
	if !st.IsDir() {
		s.scanFile(root)
		s.finish()
		return
	}

	// Deterministic order makes results reproducible across runs.
	var stack = []string{root}
	for len(stack) > 0 && !s.aborted {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if s.aborted {
				return
			}
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if skipDirName(e.Name()) {
					continue
				}
				stack = append(stack, p)
				continue
			}
			s.scanFile(p)
			if s.aborted {
				return
			}
		}
	}
	s.finish()
}

func (s *secretScanner) scanFile(path string) {
	if time.Now().After(s.deadline) {
		s.aborted = true
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if info.Size() > int64(s.maxFile) {
		s.skippedBinary++
		return
	}
	body, _, err := readCappedFile(path, s.maxFile)
	if err != nil {
		return
	}
	// Binary content: a NUL byte in the first block.
	if idx := strings.IndexByte(body, 0); idx >= 0 && idx < 512 {
		s.skippedBinary++
		return
	}

	s.files++
	s.bytes += int64(len(body))

	for i, line := range strings.Split(body, "\n") {
		if len(line) > 4000 {
			line = line[:4000]
		}
		for ri, re := range compiledSecretRules {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			hit := SecretHit{
				Path:     path,
				Line:     i + 1,
				Rule:     secretRules[ri].name,
				Severity: secretRules[ri].severity,
				Excerpt:  redactLine(line),
			}
			if len(m) > 1 {
				hit.Fingerprint = fingerprint(m[1])
			}
			s.result.Hits = append(s.result.Hits, hit)
			if len(s.result.Hits) >= s.maxHits {
				s.result.Truncated = true
				s.aborted = true
				return
			}
		}
	}
}

func (s *secretScanner) finish() {
	s.result.Files = s.files
	s.result.Bytes = s.bytes
}

// redactLine blanks the value that matched so the report is safe to share.
func redactLine(line string) string {
	out := line
	for _, re := range compiledSecretRules {
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			if len(m) < 12 {
				return "[REDACTED]"
			}
			return "[REDACTED:" + fingerprint(m) + "]"
		})
	}
	out = strings.TrimSpace(out)
	if len(out) > 200 {
		out = out[:200] + "…"
	}
	return out
}

// fingerprint is a short, non-reversible identifier so the same secret can be
// correlated across findings without the value ever being exposed.
func fingerprint(s string) string {
	// FNV-1a keeps this dependency-free and fast; the value is a correlation
	// aid, not a security primitive.
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%08x%08x", uint32(h>>32), uint32(h))
}

func skipDirName(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "target", "dist", "build", ".venv", "venv",
		"__pycache__", ".cache", ".terraform", ".mypy_cache", ".pytest_cache", "site-packages":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

type PermFinding struct {
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	Owner     string `json:"owner"`
	Group     string `json:"group"`
	Issue     string `json:"issue"`
	Severity  string `json:"severity"`
	Remediate string `json:"remediation"`
}

type PermResult struct {
	Root     string         `json:"root"`
	Entries  int            `json:"entries_examined"`
	Findings []PermFinding  `json:"findings"`
	Summary  map[string]int `json:"summary"`
}

func permissionTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_permission_audit",
		mcp.WithDescription(
			"Examine ownership and permission bits for a file, directory or tree and flag the "+
				"combinations that lead to privilege escalation: world-writable files inside a "+
				"directory on the executable path, writable-by-others script and unit files, "+
				"setuid/setgid bits outside the distribution set, and configuration readable by "+
				"non-owners. READ-ONLY: stat(2) and directory reads only.",
		),
		mcp.WithToolTitle("SENTINEL-X Permission Audit"),
		mcp.WithString("path",
			mcp.Description("Absolute path to audit. Must be inside the configured audit roots."),
			mcp.Required(),
		),
		mcp.WithNumber("max_depth",
			mcp.Description("How deep to recurse when path is a directory (0-10)."),
			mcp.DefaultNumber(2),
		),
		mcp.WithNumber("max_entries",
			mcp.Description("Stop after examining this many entries (1-20000)."),
			mcp.DefaultNumber(5000),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_permission_audit"

		path, aerr := requireArg(req, "path")
		if aerr != nil {
			return fail(toolName, "", start, aerr)
		}
		if path == "" {
			return failf(toolName, path, start, "path is required")
		}
		if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
			return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
		}

		depth := req.GetInt("max_depth", 2)
		if depth < 0 {
			depth = 0
		}
		if depth > 10 {
			depth = 10
		}
		maxEntries := req.GetInt("max_entries", 5000)
		if maxEntries < 1 {
			maxEntries = 1
		}
		if maxEntries > 20000 {
			maxEntries = 20000
		}

		res := PermResult{Root: path, Summary: map[string]int{}}
		st, err := os.Lstat(path)
		if err != nil {
			return fail(toolName, path, start, fmt.Errorf("cannot stat %s: %w", path, err))
		}
		res.Findings = examinePerm(path, st, res.Summary, &res.Entries, maxEntries)

		if st.IsDir() {
			res.Entries = 0
			permWalk(path, depth, maxEntries, res.Summary, &res.Entries, &res.Findings)
		}
		sort.Slice(res.Findings, func(i, j int) bool {
			if res.Findings[i].Severity != res.Findings[j].Severity {
				return res.Findings[i].Severity > res.Findings[j].Severity
			}
			return res.Findings[i].Path < res.Findings[j].Path
		})
		if len(res.Findings) == 0 {
			res.Findings = append(res.Findings, PermFinding{
				Path: path, Issue: "no permission anomalies detected", Severity: "info",
			})
		}
		return ok(d, toolName, path, start, nil, res)
	}
	return Tool{Tool: t, Handler: h}
}

func permWalk(dir string, depth, maxEntries int, summary map[string]int, count *int, out *[]PermFinding) {
	if depth < 0 || *count >= maxEntries {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if *count >= maxEntries {
			return
		}
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		*count++
		*out = append(*out, examinePerm(p, info, summary, count, maxEntries)...)
		if e.IsDir() {
			permWalk(p, depth-1, maxEntries, summary, count, out)
		}
	}
}

func examinePerm(path string, info os.FileInfo, summary map[string]int, count *int, maxEntries int) []PermFinding {
	if *count >= maxEntries {
		return nil
	}
	mode := info.Mode()
	perm := mode.Perm()
	var out []PermFinding

	pf := PermFinding{
		Path:  path,
		Mode:  fmt.Sprintf("%04o", perm),
		Owner: ownerOf(info),
		Group: groupOf(info),
	}
	if mode&os.ModeSymlink != 0 {
		return nil // the link target is audited separately
	}

	isConf := strings.HasSuffix(path, ".conf") || strings.Contains(filepath.Base(path), "sshd_config") ||
		strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") ||
		strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".toml")
	isExecPath := strings.HasSuffix(path, ".sh") || strings.HasSuffix(path, ".py") ||
		strings.HasSuffix(path, ".service") || strings.HasSuffix(path, ".timer") || mode&0o111 != 0
	isKey := strings.Contains(path, "id_rsa") || strings.Contains(path, "id_ed25519") ||
		strings.HasSuffix(path, ".pem") || strings.Contains(filepath.Base(path), "authorized_keys")

	switch {
	case perm&0o002 != 0:
		sev := "high"
		issue := "world-writable"
		rem := fmt.Sprintf("chmod o-w %s", path)
		if isExecPath {
			issue = "world-writable and on an executable path"
			sev = "critical"
			rem = "Remove the world-write bit immediately. Any local user can place content here that a privileged process will run."
		}
		out = append(out, PermFinding{Path: path, Mode: pf.Mode, Owner: pf.Owner, Group: pf.Group,
			Issue: issue, Severity: sev, Remediate: rem})
		summary["world_writable"]++
	case perm&0o020 != 0 && isConf:
		out = append(out, PermFinding{Path: path, Mode: pf.Mode, Owner: pf.Owner, Group: pf.Group,
			Issue: "group-writable configuration file", Severity: "medium",
			Remediate: "Remove the group-write bit unless a specific deployment process requires it."})
		summary["group_writable_config"]++
	}
	if isKey && perm&0o077 != 0 {
		out = append(out, PermFinding{Path: path, Mode: pf.Mode, Owner: pf.Owner, Group: pf.Group,
			Issue: "key material is readable beyond its owner", Severity: "critical",
			Remediate: fmt.Sprintf("chmod 600 %s and rotate the key — it has been readable by other accounts", path)})
		summary["exposed_key"]++
	}
	if mode&0o4000 != 0 {
		out = append(out, PermFinding{Path: path, Mode: pf.Mode, Owner: pf.Owner, Group: pf.Group,
			Issue: "setuid bit set", Severity: "info",
			Remediate: "Confirm the file is a known distribution SUID binary; an unexpected one is a root-equivalent backdoor."})
		summary["setuid"]++
	}
	if mode&0o1000 != 0 {
		out = append(out, PermFinding{Path: path, Mode: pf.Mode, Owner: pf.Owner, Group: pf.Group,
			Issue: "sticky bit on a non-world-writable directory", Severity: "low",
			Remediate: "Usually harmless; remove it if it is not intentional."})
		summary["sticky"]++
	}
	return out
}

// ownerOf reports the owning UID. It delegates to the per-platform helpers
// rather than asserting on syscall.Stat_t here, because that type does not
// exist on Windows and a bare assertion here would not compile there.
func ownerOf(fi os.FileInfo) string {
	if uid, ok := fileUID(fi); ok {
		return strconv.Itoa(uid)
	}
	return "unknown"
}

func groupOf(fi os.FileInfo) string {
	if gid, ok := fileGID(fi); ok {
		return strconv.Itoa(gid)
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// parseDefaults reads the shell-style KEY=value file used by login.defs.
func parseDefaults(body string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		i := strings.IndexAny(line, " \t=")
		if i <= 0 {
			continue
		}
		out[strings.ToUpper(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
	}
	return out
}

func osReleaseField(body, key string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, key+"=") {
			return strings.Trim(strings.TrimPrefix(l, key+"="), `"`)
		}
	}
	return ""
}

func gradeFor(ratio float64) string {
	switch {
	case ratio >= 0.95:
		return "A — hardened"
	case ratio >= 0.85:
		return "B — good"
	case ratio >= 0.7:
		return "C — needs work"
	case ratio >= 0.5:
		return "D — weak"
	default:
		return "F — critical gaps"
	}
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}

// detectAuditServices reports which external tools the audit could use, so the
// operator can tell a clean result from a blind one.
func detectAuditServices(d Deps, ctx context.Context) []string {
	var present []string
	for _, b := range []string{"nmap", "dig", "whois", "curl", "openssl", "searchsploit"} {
		if ok, _ := d.Runner.Available(b); ok {
			present = append(present, b)
		}
	}
	if _, err := exec.LookPath("lynis"); err == nil {
		present = append(present, "lynis")
	}
	sort.Strings(present)
	return present
}
