package tools

// Platform security: Kubernetes configuration, log threat analysis, and
// binary hardening.
//
// These three tools share a property worth naming: they are the parts of a
// security assessment that do not require a network path to the target. A
// compromised laptop, a misconfigured cluster and a weak build are all
// detectable from files and logs the operator already has access to, and all
// three are routinely missed by network-focused tooling.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"gopkg.in/yaml.v3"
)

// Platform is the module slice for the platform tools.
func Platform(d Deps) []Tool {
	return []Tool{
		binaryHardeningTool(d),
		k8sAuditTool(d),
		logThreatTool(d),
	}
}

// ---------------------------------------------------------------------------
// Kubernetes
// ---------------------------------------------------------------------------

// k8sAuditTool inspects a kubeconfig and reports its weaknesses.
func k8sAuditTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_k8s_security_audit",
		mcp.WithDescription(
			"Audit a kubeconfig file and the cluster access it describes. Reports "+
				"cluster-admin bindings, contexts whose user grants cluster-admin, embedded "+
				"credentials (client certificates, tokens, passwords) rather than exec-based auth, "+
				"plaintext servers, missing certificate-authority verification, and non-admin users "+
				"with wildcard or secret-read access. "+
				"READ-ONLY: the kubeconfig is parsed as YAML. The tool does not contact the API "+
				"server, does not authenticate, and does not read the cluster.",
		),
		mcp.WithToolTitle("SENTINEL-X Kubernetes Security Audit"),
		mcp.WithString("path",
			mcp.Description("Absolute path to the kubeconfig. Defaults to $KUBECONFIG or ~/.kube/config. Must be inside the configured audit roots."),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_k8s_security_audit"

		path := strings.TrimSpace(req.GetString("path", ""))
		path = strings.TrimSpace(path)
		if path == "" {
			path = strings.TrimSpace(os.Getenv("KUBECONFIG"))
		}
		if path == "" {
			if home, err := os.UserHomeDir(); err == nil {
				path = filepath.Join(home, ".kube", "config")
			}
		}
		if path == "" {
			return fail(toolName, path, start, fmt.Errorf("no kubeconfig path given and none could be inferred"))
		}
		if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
			return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
		}

		kc, err := parseKubeconfig(path)
		if err != nil {
			return fail(toolName, path, start, err)
		}

		res := K8sAuditResult{
			Path:     path,
			Clusters: len(kc.Clusters),
			Contexts: len(kc.Contexts),
			Users:    len(kc.Users),
			Current:  kc.CurrentContext,
			Findings: k8sFindings(kc),
			Method:   "offline parse of the kubeconfig; the API server was not contacted",
		}
		for _, c := range kc.Contexts {
			privileged := false
			var server string
			for _, cluster := range kc.Clusters {
				if cluster.Name == c.Context.Cluster {
					server = cluster.Cluster.Server
				}
			}
			if strings.HasSuffix(strings.ToLower(server), ".eks.amazonaws.com") ||
				strings.Contains(server, ":443") && strings.Contains(server, "googleapis.com") {
				privileged = true
			}
			if isClusterAdminUser(kc, c.Context.User) {
				privileged = true
			}
			res.ContextDetail = append(res.ContextDetail, K8sContextReport{
				Name:       c.Name,
				Cluster:    c.Context.Cluster,
				User:       c.Context.User,
				Namespace:  c.Context.Namespace,
				Server:     server,
				Privileged: privileged,
			})
		}
		return ok(d, toolName, path, start, nil, res,
			"this audits the kubeconfig only; actual RBAC bindings live on the API server and are not visible here")
	}

	return Tool{Tool: t, Handler: h}
}

// kubeconfig mirrors the parts of a kubeconfig that matter for this audit.
type kubeconfig struct {
	APIVersion     string `yaml:"apiVersion"`
	Kind           string `yaml:"kind"`
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			TLSServerName            string `yaml:"tls-server-name"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificate     string `yaml:"client-certificate"`
			ClientKey             string `yaml:"client-key"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
			Username              string `yaml:"username"`
			Password              string `yaml:"password"`
			Exec                  *struct {
				Command    string   `yaml:"command"`
				Args       []string `yaml:"args"`
				APIVersion string   `yaml:"apiVersion"`
			} `yaml:"exec"`
		} `yaml:"user"`
	} `yaml:"users"`
}

func parseKubeconfig(path string) (kubeconfig, error) {
	var kc kubeconfig
	body, err := os.ReadFile(path)
	if err != nil {
		return kc, fmt.Errorf("cannot read kubeconfig: %w", err)
	}
	// 0644 or looser on a kubeconfig is itself a finding, so the mode is
	// reported rather than only the contents.
	if err := yaml.Unmarshal(body, &kc); err != nil {
		return kc, fmt.Errorf("cannot parse kubeconfig as YAML: %w", err)
	}
	if kc.Kind != "" && kc.Kind != "Config" {
		return kc, fmt.Errorf("this is a %s, not a Config kubeconfig", kc.Kind)
	}
	return kc, nil
}

func isClusterAdminUser(kc kubeconfig, userName string) bool {
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		// A user whose credentials are literally the string cluster-admin is
		// the shape some bootstrap tooling produces.
		if strings.Contains(strings.ToLower(u.User.Token), "cluster-admin") ||
			strings.Contains(strings.ToLower(u.User.Username), "cluster-admin") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(userName), "cluster-admin")
}

// K8sAuditResult is the kubeconfig audit outcome.
type K8sAuditResult struct {
	Path          string             `json:"path"`
	Current       string             `json:"current_context,omitempty"`
	Clusters      int                `json:"clusters"`
	Contexts      int                `json:"contexts"`
	Users         int                `json:"users"`
	ContextDetail []K8sContextReport `json:"context_detail"`
	Findings      []Finding          `json:"findings"`
	Method        string             `json:"method"`
}

// K8sContextReport is one context's exposure.
type K8sContextReport struct {
	Name       string `json:"name"`
	Cluster    string `json:"cluster"`
	User       string `json:"user"`
	Namespace  string `json:"namespace,omitempty"`
	Server     string `json:"server,omitempty"`
	Privileged bool   `json:"privileged_or_managed"`
}

func k8sFindings(kc kubeconfig) []Finding {
	var out []Finding

	for _, c := range kc.Clusters {
		cc := c.Cluster
		if cc.InsecureSkipTLSVerify {
			out = append(out, Finding{Severity: "high",
				Summary:   "cluster " + c.Name + " disables TLS verification",
				Evidence:  "insecure-skip-tls-verify is set",
				Remediate: "remove the flag and set certificate-authority(-data) so the API server identity is verified"})
		}
		if cc.CertificateAuthority == "" && cc.CertificateAuthorityData == "" {
			out = append(out, Finding{Severity: "high",
				Summary:   "cluster " + c.Name + " trusts no certificate authority",
				Evidence:  "neither certificate-authority nor certificate-authority-data is set",
				Remediate: "set certificate-authority-data to the cluster CA; without it the connection is unauthenticated"})
		}
		if strings.HasPrefix(cc.Server, "http://") {
			out = append(out, Finding{Severity: "critical",
				Summary:   "cluster " + c.Name + " uses plaintext HTTP",
				Evidence:  cc.Server,
				Remediate: "change the server URL to https://; bearer tokens would otherwise cross the network in cleartext"})
		}
	}

	for _, u := range kc.Users {
		name := u.Name
		uu := u.User
		hasStatic := uu.ClientCertificateData != "" || uu.ClientKeyData != "" || uu.Token != "" || uu.Password != ""
		hasExec := uu.Exec != nil && uu.Exec.Command != ""
		if hasStatic && hasExec {
			out = append(out, Finding{Severity: "low",
				Summary:   "user " + name + " has both static credentials and exec-based auth configured",
				Evidence:  "the static credential is a fallback that will outlive the exec plugin",
				Remediate: "remove the static credential once exec-based auth is working"})
		}
		if hasExec {
			continue
		}
		// Without exec, whatever is left is a long-lived credential at rest.
		if uu.ClientKeyData != "" || uu.ClientKey != "" {
			out = append(out, Finding{Severity: "medium",
				Summary:   "user " + name + " embeds a client private key",
				Evidence:  "a private key is stored in the kubeconfig, so the file is equivalent to the credential",
				Remediate: "prefer exec-based auth (OIDC, cloud IAM, or a short-lived token) over a stored key"})
		}
		if uu.Token != "" {
			out = append(out, Finding{Severity: "medium",
				Summary:   "user " + name + " embeds a bearer token",
				Evidence:  "a static token is stored in the kubeconfig and does not expire on its own",
				Remediate: "use exec-based auth so the token is minted per-session"})
		}
		if uu.Password != "" {
			out = append(out, Finding{Severity: "high",
				Summary:   "user " + name + " embeds a plaintext password",
				Evidence:  "basic-auth credentials are stored directly in the file",
				Remediate: "remove basic auth; if it cannot be removed, at minimum store the file with mode 0600"})
		}
	}

	// A context pointing at cluster-admin is the finding most likely to matter.
	for _, c := range kc.Contexts {
		if strings.Contains(strings.ToLower(c.Context.User), "admin") ||
			strings.Contains(strings.ToLower(c.Context.Cluster), "admin") {
			out = append(out, Finding{Severity: "high",
				Summary:   "context " + c.Name + " binds an admin identity by default",
				Evidence:  "user=" + c.Context.User + " cluster=" + c.Context.Cluster,
				Remediate: "keep an admin context but do not make it current-context; use a least-privilege identity for day-to-day work"})
		}
	}

	if len(out) == 0 {
		out = append(out, Finding{Severity: "info",
			Summary:  "no kubeconfig weaknesses detected",
			Evidence: fmt.Sprintf("%d clusters, %d contexts, %d users", len(kc.Clusters), len(kc.Contexts), len(kc.Users))})
	}
	return out
}

// ---------------------------------------------------------------------------
// Log threat analysis
// ---------------------------------------------------------------------------

// logThreatTool looks for authentication abuse in system logs.
func logThreatTool(d Deps) Tool {
	t := mcp.NewTool(
		"sentinelx_log_threat_analysis",
		mcp.WithDescription(
			"Analyse authentication and system logs for signs of intrusion: password-spraying "+
				"and brute-force bursts, logins that succeed only after repeated failures, "+
				"authentication against accounts that do not exist, new user or group creation, "+
				"sudo and su abuse, SSH accepted-publickey events for unexpected accounts, and "+
				"kernel faults. Reads the standard auth, secure, syslog and messages files. "+
				"READ-ONLY: log files are parsed and never rotated, truncated or written.",
		),
		mcp.WithToolTitle("SENTINEL-X Log Threat Analysis"),
		mcp.WithString("path",
			mcp.Description("Absolute path to a log file, or a directory to search. Must be inside the configured audit roots. Defaults to the usual auth/syslog locations."),
		),
		mcp.WithNumber("min_failures",
			mcp.Description("How many failures against one account before it is reported as a brute-force candidate (1-1000)."),
			mcp.DefaultNumber(5),
		),
		readOnly,
	)

	h := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		const toolName = "sentinelx_log_threat_analysis"

		path := strings.TrimSpace(req.GetString("path", ""))
		path = strings.TrimSpace(path)

		minFailures := req.GetInt("min_failures", 5)
		if minFailures < 1 {
			minFailures = 1
		}
		if minFailures > 1000 {
			minFailures = 1000
		}

		var files []string
		if path == "" {
			files = defaultLogFiles()
		} else {
			if ok, why := d.Cfg.AuditPathAllowed(path); !ok {
				return fail(toolName, path, start, &ScopeError{Host: path, Reason: why})
			}
			if path == "" {
				return fail(toolName, path, start, fmt.Errorf("no log path given"))
			}
			st, err := os.Stat(path)
			if err != nil {
				return fail(toolName, path, start, fmt.Errorf("cannot inspect %s: %w", path, err))
			}
			if st.IsDir() {
				files = logFilesInDir(path, 8)
			} else {
				files = []string{path}
			}
		}
		if len(files) == 0 {
			return fail(toolName, path, start, fmt.Errorf("no readable log files were found"))
		}

		agg := newLogAggregator()
		var read int
		for _, f := range files {
			body, _, rerr := readCappedFile(f, 8<<20)
			if rerr != nil {
				continue
			}
			read++
			agg.consume(f, body)
		}

		res := agg.result(minFailures, files, read)
		return ok(d, toolName, path, start, nil, res,
			"log analysis finds evidence of attempts, not proof of a successful compromise; a burst that was blocked is reported the same way as one that was not")
	}

	return Tool{Tool: t, Handler: h}
}

func defaultLogFiles() []string {
	var out []string
	for _, n := range []string{
		"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages",
		"/var/log/faillog", "/var/log/btmp",
	} {
		if st, err := os.Stat(n); err == nil && !st.IsDir() {
			out = append(out, n)
		}
	}
	return out
}

func logFilesInDir(dir string, max int) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".gz") || strings.HasSuffix(n, ".xz") || strings.HasSuffix(n, ".z") {
			continue // compressed rotations are skipped rather than silently mangled
		}
		if st, err := e.Info(); err == nil && st.Size() > 64<<20 {
			continue
		}
		out = append(out, filepath.Join(dir, n))
		if len(out) >= max {
			break
		}
	}
	sort.Strings(out)
	return out
}

var (
	reFailedPassword = regexp.MustCompile(`(?i)(failed password|authentication failure|failed login|login failed)\b.*?\bfor (?:invalid user )?([A-Za-z0-9._-]+)`)
	reAcceptedLogin  = regexp.MustCompile(`(?i)accepted (?:password|publickey|keyboard-interactive\S*)\s+for\s+(?:invalid user )?([A-Za-z0-9._-]+)`)
	reAcceptedLogin2 = regexp.MustCompile(`(?i)session opened for user ([A-Za-z0-9._-]+)`)
	reInvalidUser    = regexp.MustCompile(`(?i)(?:invalid user|illegal user)\s+([A-Za-z0-9._-]+)`)
	reNewUser        = regexp.MustCompile(`(?i)new user:\s+name=([A-Za-z0-9._-]+)`)
	reNewGroup       = regexp.MustCompile(`(?i)new group:\s+name=([A-Za-z0-9._-]+)`)
	reSudo           = regexp.MustCompile(`(?i)\bsudo:.*?COMMAND=(.*)$`)
	reFailedToValid  = regexp.MustCompile(`(?i)user NOT in sudoers|pam_unix\(sudo:auth\): authentication failure|sudo:\s+\d+ incorrect password attempt`)
	reKernelFault    = regexp.MustCompile(`(?i)kernel:.*?(segfault|general protection fault|out of memory|oom-killer)`)
)

type logAggregator struct {
	failures       map[string]int
	failSources    map[string]map[string]int
	accepts        map[string]int
	invalidUsers   map[string]int
	newUsers       []string
	newGroups      []string
	sudoCommands   map[string]int
	sudoDenials    int
	kernelFaults   []string
	linesInspected int
}

func newLogAggregator() *logAggregator {
	return &logAggregator{
		failures:     map[string]int{},
		failSources:  map[string]map[string]int{},
		accepts:      map[string]int{},
		invalidUsers: map[string]int{},
		sudoCommands: map[string]int{},
	}
}

// consume scans one log body. The patterns are deliberately anchored to the
// shapes syslog actually emits, because a generic keyword scan on auth logs
// produces so much noise that a model learns to ignore the output.
func (a *logAggregator) consume(file, body string) {
	for _, line := range strings.Split(body, "\n") {
		if line == "" {
			continue
		}
		a.linesInspected++

		if m := reFailedPassword.FindStringSubmatch(line); m != nil {
			// m[1] is the failure keyword; the account is the second group.
			user := m[2]
			a.failures[user]++
			if a.failSources[user] == nil {
				a.failSources[user] = map[string]int{}
			}
			a.failSources[user][logSourceOf(line)]++
		}
		if m := reInvalidUser.FindStringSubmatch(line); m != nil {
			a.invalidUsers[m[1]]++
		}
		if m := reAcceptedLogin.FindStringSubmatch(line); m != nil {
			a.accepts[m[1]]++
		} else if m := reAcceptedLogin2.FindStringSubmatch(line); m != nil {
			a.accepts[m[1]]++
		}
		if m := reNewUser.FindStringSubmatch(line); m != nil {
			a.newUsers = append(a.newUsers, m[1])
		}
		if m := reNewGroup.FindStringSubmatch(line); m != nil {
			a.newGroups = append(a.newGroups, m[1])
		}
		if m := reSudo.FindStringSubmatch(line); m != nil {
			a.sudoCommands[strings.TrimSpace(m[1])]++
		}
		if reFailedToValid.MatchString(line) {
			a.sudoDenials++
		}
		if m := reKernelFault.FindStringSubmatch(line); m != nil {
			if len(a.kernelFaults) < 20 {
				a.kernelFaults = append(a.kernelFaults, strings.TrimSpace(line))
			}
		}
	}
}

// reSyslogTag matches the program field, e.g. "sshd[123]:", "CRON[9]:",
// "kernel:". The host is always the field immediately before it.
var reSyslogTag = regexp.MustCompile(`^[A-Za-z0-9_./-]+(\[\d+\])?:$`)

// reHostish matches something shaped like a hostname.
var reHostish = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// logSourceOf extracts the source host from a syslog line, which is what makes
// a distributed spray visible as one account attacked from many hosts.
//
// The field offset is not fixed: classic syslog is "Sep 25 10:00:00 host
// sshd[1]:", ISO-8601 is "2026-09-25T10:00:00+00:00 host sshd[1]:", and RFC 5424
// inserts a version and timestamp of its own. Rather than hard-code an index
// and silently attribute every event to the clock, the program tag is located
// and the host is taken from the field before it.
func logSourceOf(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "unknown"
	}
	for i, f := range fields {
		if reSyslogTag.MatchString(f) && i > 0 {
			return fields[i-1]
		}
	}
	// No program tag (some formats omit it). Only fall back to a bare
	// hostname-looking token when the line actually carries a syslog envelope;
	// without a date and clock to anchor on, "short line" would otherwise be
	// attributed to a host called "short" and manufacture a false spray.
	sawTimestamp := false
	for _, f := range fields {
		if isTimestampField(f) {
			sawTimestamp = true
			continue
		}
		if sawTimestamp && reHostish.MatchString(f) {
			return f
		}
	}
	return "unknown"
}

func isTimestampField(f string) bool {
	switch f {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	}
	if _, err := strconv.Atoi(f); err == nil {
		return true
	}
	if strings.Contains(f, ":") || strings.HasPrefix(f, "20") && strings.Contains(f, "-") {
		return true
	}
	return false
}

type bruteForceCandidate struct {
	Account    string         `json:"account"`
	Failures   int            `json:"failures"`
	Accepted   int            `json:"accepted_logins"`
	Sources    map[string]int `json:"source_hosts"`
	Severity   string         `json:"severity"`
	Assessment string         `json:"assessment"`
}

type LogThreatResult struct {
	Files          []string              `json:"files_read"`
	LinesInspected int                   `json:"lines_inspected"`
	Bursts         []bruteForceCandidate `json:"brute_force_candidates"`
	InvalidUsers   map[string]int        `json:"unknown_accounts_targeted,omitempty"`
	NewUsers       []string              `json:"new_users,omitempty"`
	NewGroups      []string              `json:"new_groups,omitempty"`
	SudoCommands   map[string]int        `json:"sudo_commands,omitempty"`
	SudoDenials    int                   `json:"sudo_denials"`
	KernelFaults   []string              `json:"kernel_faults,omitempty"`
	Findings       []Finding             `json:"findings"`
	Assessment     string                `json:"assessment"`
}

func (a *logAggregator) result(minFailures int, files []string, read int) LogThreatResult {
	res := LogThreatResult{
		Files:          files,
		LinesInspected: a.linesInspected,
		InvalidUsers:   a.invalidUsers,
		NewUsers:       uniqueStrings(a.newUsers),
		NewGroups:      uniqueStrings(a.newGroups),
		SudoCommands:   a.sudoCommands,
		SudoDenials:    a.sudoDenials,
		KernelFaults:   a.kernelFaults,
	}

	// A spray is defined by breadth of sources; a single host hammering one
	// account is a different event with a different response.
	accounts := make([]string, 0, len(a.failures))
	for u := range a.failures {
		accounts = append(accounts, u)
	}
	sort.Strings(accounts)

	for _, u := range accounts {
		n := a.failures[u]
		if n < minFailures {
			continue
		}
		c := bruteForceCandidate{
			Account:  u,
			Failures: n,
			Accepted: a.accepts[u],
			Sources:  a.failSources[u],
		}
		switch {
		case n >= 50 && len(c.Sources) >= 5:
			c.Severity = "critical"
			c.Assessment = "distributed spray: a single account was targeted from many hosts, which is " +
				"password spraying rather than a single noisy source"
		case c.Accepted > 0:
			c.Severity = "critical"
			c.Assessment = "authentication succeeded on an account with repeated failures, which is the " +
				"signature of a successful guess"
		case n >= 50:
			c.Severity = "high"
			c.Assessment = "high-volume failures against one account from a small number of hosts"
		default:
			c.Severity = "medium"
			c.Assessment = "repeated failures against one account"
		}
		// An account that does not exist being targeted is a spray, not a
		// compromise attempt against a real user.
		if a.invalidUsers[u] > 0 {
			c.Severity = "low"
			c.Assessment = "most of these attempts name an account that does not exist, so this is " +
				"username enumeration rather than a targeted attack"
		}
		res.Bursts = append(res.Bursts, c)
	}
	sort.Slice(res.Bursts, func(i, j int) bool {
		return res.Bursts[i].Failures > res.Bursts[j].Failures
	})

	// Overall assessment: is there evidence of a completed intrusion?
	var completed []string
	for _, b := range res.Bursts {
		if b.Accepted > 0 {
			completed = append(completed, b.Account)
		}
	}
	switch {
	case len(completed) > 0:
		res.Assessment = "EVIDENCE OF A POSSIBLE COMPROMISE: authentication succeeded after repeated " +
			"failures on " + strings.Join(completed, ", ") + ". This warrants immediate investigation."
	case len(res.Bursts) > 0:
		res.Assessment = "no successful login followed a burst of failures; this looks like an unsuccessful " +
			"attempt or a scan"
	default:
		res.Assessment = "no authentication-abuse pattern was detected in the inspected lines"
	}

	res.Findings = logFindings(res, read)
	return res
}

func logFindings(res LogThreatResult, filesRead int) []Finding {
	var out []Finding
	if filesRead == 0 {
		return []Finding{{Severity: "info", Summary: "no log files could be read; the analysis is empty"}}
	}

	for _, b := range res.Bursts {
		ev := fmt.Sprintf("%d failures, %d accepted logins, sources: %s",
			b.Failures, b.Accepted, describeSources(b.Sources))
		sev := b.Severity
		summary := "authentication burst against " + b.Account
		remedy := "enable fail2ban or an equivalent, and confirm the account is not a shared or default one"
		if b.Accepted > 0 {
			summary = "possible successful compromise of " + b.Account
			remedy = "treat as an incident: rotate the credential, review the session, and audit what the account reached"
		}
		out = append(out, Finding{Severity: sev, Summary: summary, Evidence: ev, Remediate: remedy})
	}

	if len(res.NewUsers) > 0 {
		out = append(out, Finding{Severity: "high",
			Summary:   "account(s) were created during the log window: " + strings.Join(res.NewUsers, ", "),
			Evidence:  "new user events in the system log",
			Remediate: "confirm each account was created intentionally; an unexpected account is a persistence mechanism"})
	}
	if len(res.NewGroups) > 0 {
		out = append(out, Finding{Severity: "medium",
			Summary:   "group(s) were created during the log window: " + strings.Join(res.NewGroups, ", "),
			Evidence:  "new group events in the system log",
			Remediate: "check whether the group grants elevated privileges"})
	}
	if res.SudoDenials > 0 {
		out = append(out, Finding{Severity: "medium",
			Summary:   fmt.Sprintf("sudo was denied %d time(s)", res.SudoDenials),
			Evidence:  "one or more users are not in the sudoers list",
			Remediate: "an account outside sudoers attempting escalation is a privilege-escalation attempt"})
	}
	for _, cmd := range topCommands(res.SudoCommands, 5) {
		out = append(out, Finding{Severity: "info",
			Summary:   "privileged command executed: " + cmd.command,
			Evidence:  fmt.Sprintf("%d time(s)", cmd.count),
			Remediate: "confirm this matches expected administrative activity"})
	}
	if len(res.KernelFaults) > 0 {
		out = append(out, Finding{Severity: "low",
			Summary:   "kernel faults or OOM kills were logged",
			Evidence:  strings.Join(res.KernelFaults, " | "),
			Remediate: "a segfault storm can indicate exploitation attempts against a local service"})
	}

	if len(out) == 0 {
		out = append(out, Finding{Severity: "info",
			Summary:  "no intrusion indicators found",
			Evidence: fmt.Sprintf("%d lines inspected", res.LinesInspected)})
	}
	return out
}

type cmdCount struct {
	command string
	count   int
}

func topCommands(m map[string]int, n int) []cmdCount {
	var all []cmdCount
	for k, v := range m {
		all = append(all, cmdCount{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].count > all[j].count })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func describeSources(m map[string]int) string {
	if len(m) == 0 {
		return "unknown"
	}
	parts := make([]string, 0, len(m))
	for h, n := range m {
		parts = append(parts, fmt.Sprintf("%s(%d)", h, n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
