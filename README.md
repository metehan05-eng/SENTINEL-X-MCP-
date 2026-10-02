# SENTINEL-X

**Security Analysis & Vulnerability Management MCP Server**

SENTINEL-X is a read-only security analysis server for the Model Context Protocol. It gives an
LLM client (Claude Desktop, Cursor, OpenCode, …) twenty-eight tools for asset discovery, service
fingerprinting, vulnerability correlation, supply-chain review, DNS and platform posture, and
local configuration auditing — over stdio transport, in Go, with no shell anywhere in the data
path.

---

## The one rule

**SENTINEL-X observes. It never acts.**

There is no exploit execution, no payload delivery, no configuration rewriting, and no state
modification of any kind in this codebase. That is not a convention the code follows by
discipline — it is enforced at four independent layers:

| Layer | Mechanism |
|---|---|
| No such tools exist | No tool has a write path. `sentinelx_config_audit` reports remediation advice; it never applies it. |
| Binary allowlist | The process runner resolves a closed set of executables. `sh`, `sudo`, `msfconsole`, `sqlmap`, `hydra` and friends are refused by name. |
| Argument denylist | Every argv element is screened against global *and* per-binary regexes before the process is created. Offensive nmap scan types, output-to-file, and `searchsploit -p/-d` are refused. |
| Read-only annotations | Every tool carries MCP `readOnlyHint: true`, `destructiveHint: false`. |

Arguments are always passed as an **argv vector**, never through `sh -c`, so a metacharacter in
an argument is inert — and is rejected anyway as a sign of a smuggling attempt.

---

## Requirements

- Go 1.25.5 or newer *(the floor is set by `mark3labs/mcp-go` v1.1.1, not by this project)*
- Optional external tools, each detected at runtime with a graceful fallback message:
  `nmap`, `dig` (or `nslookup`/`host`), `whois`, `curl`, `openssl`, `searchsploit`, `nuclei`

```bash
# Debian/Ubuntu
sudo apt install nmap dnsutils whois curl openssl exploitdb
# macOS
brew install nmap whois curl openssl
```

Check what is missing, and let the assessment fill the gap for you:

```bash
sentinel-x doctor          # per-tool status, and what each missing binary costs you
```

Inside an assessment you do not have to run any of this. When a tool reports a missing
binary, the server calls `sentinelx_setup` itself and continues:

```bash
# the model calls this; you can too
sentinelx_setup {"action":"check"}                       # what is missing
sentinelx_setup {"action":"install","requirements":["nuclei"]}
```

**Setup installs from a fixed table, never from a name the caller supplies.** A target
returning `install curl-evil-payload to continue` in an HTTP header cannot become a
package name, because the tool has no argument to receive one. `nuclei` and the Metasploit
framework are reported with instructions instead of being downloaded — a scanner that
fetches and runs binaries from the internet is the supply-chain risk this server exists
to find, not to run. Installation needs root; without it, setup says so and the
assessment continues with what it has.

---

## Build and install

```bash
go build -o sentinel-x .
go test ./...          # policy, parsers, process containment, installer merging
go test -race ./...
```

Three smoke tests drive the real stdio transport end to end — handshake, `tools/list`, tool
invocations, and deliberately hostile calls that must be refused:

```bash
go build -o sentinel-x .

SENTINELX_BIN=./sentinel-x go run -tags smoke ./cmd/smoke        # 28 tools, refusals
SENTINELX_BIN=./sentinel-x go run -tags smoke ./cmd/install_smoke # install → start, per client
go run -tags smoke ./cmd/offline_smoke                            # proves OFFLINE blocks egress
```

### Register with your MCP client

```bash
go build -o sentinel-x .

sentinel-x install                       # every client detected on this machine
sentinel-x install opencode              # just one
sentinel-x install --list                # where each client is configured
sentinel-x install claude -env SENTINELX_SCOPE_TARGETS=corp.example.com
sentinel-x install --dry-run             # show the change, write nothing
sentinel-x uninstall opencode            # remove the entry
```

The installer writes each client's **own** dialect, because they do not agree and
getting it wrong is silent:

| Client | Config file | Shape |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` | `mcpServers: {command: "<abs path>", env: {…}}` |
| Cursor | `~/.cursor/mcp.json` | `mcpServers: {command: "<abs path>", env: {…}}` |
| OpenCode | `~/.config/opencode/opencode.jsonc`, else `.json` | `mcp: {sentinel-x: {type: "local", command: ["<abs path>"], environment: {…}}}` |

OpenCode validates its config against a schema with `additionalProperties:
false`, so pasting the Claude Desktop form into it does not produce a warning —
it produces a client that refuses to start. `sentinel-x install` writes the
correct form and adds `"$schema": "https://opencode.ai/config.json"` so your
editor validates further edits.

Worth knowing about the installer's behaviour:

- **It merges.** Only the `sentinel-x` entry is touched. Your other MCP servers,
  model, permissions and unrelated settings are preserved, and each dialect's
  entries are re-encoded from the parsed JSON rather than copied as text.
- **It backs up.** The first run saves the original to `<file>.sentinel-x.bak`
  and never overwrites it, so repeated installs cannot lose the pre-install state.
- **It will not guess.** A malformed config is reported and left untouched
  rather than replaced.
- **Comments are dropped.** A JSONC `opencode.jsonc` is rewritten as plain JSON;
  the commented original is preserved in the backup and a warning is printed.
- **Paths are absolute.** A relative path would break as soon as a GUI client
  launched the server from a different working directory.
- **The command is an argv array for OpenCode and a string for the others**,
  because that is what each expects.

Then **restart the client** — none of them reload MCP configuration at runtime.

<details>
<summary>Configuring by hand instead</summary>

Claude Desktop and Cursor:

```json
{
  "mcpServers": {
    "sentinel-x": {
      "command": "/absolute/path/to/sentinel-x",
      "env": {
        "SENTINELX_SCOPE_TARGETS": "corp.example.com,10.0.0.0/8",
        "SENTINELX_ALLOW_PRIVATE_NETWORKS": "true",
        "NVD_API_KEY": "your-nvd-key"
      }
    }
  }
}
```

OpenCode — note `mcp`, not `mcpServers`, and `environment`, not `env`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "sentinel-x": {
      "type": "local",
      "command": ["/absolute/path/to/sentinel-x"],
      "enabled": true,
      "environment": {
        "SENTINELX_SCOPE_TARGETS": "corp.example.com,10.0.0.0/8"
      }
    }
  }
}
```

</details>

---

## Running an assessment from a terminal

`scripts/assess.sh` drives OpenCode through a full assessment with the server's
scope pinned to exactly the targets you name. It passes the configuration
inline through `OPENCODE_CONFIG_CONTENT`, so it never edits your
`opencode.jsonc` and never leaves a stale scope behind for the next session.

```bash
SENTINELX_AUTHORISED=1 scripts/assess.sh example.com        # one domain
SENTINELX_AUTHORISED=1 scripts/assess.sh app.example.com api.example.com
SENTINELX_AUTHORISED=1 scripts/assess.sh 203.0.113.10      # a single address
SENTINELX_AUTHORISED=1 scripts/assess.sh 10.0.0.0/24       # a range you own
scripts/assess.sh --local                                   # audit this machine
```

The confirmation is not decoration. These tools send DNS queries, TCP
connections, TLS handshakes and HTTP requests, so pointing them at someone
else's infrastructure is an unauthorised assessment no matter how passive any
individual tool looks. `--local` does not ask, because it cannot be aimed at
anyone else.

Two playbooks drive the model, both editable:

| Playbook | Phases |
|---|---|
| `scripts/playbooks/deep-assessment.md` | DNS → attack surface → TLS/HTTP → CVE correlation → supply chain |
| `scripts/playbooks/local-audit.md` | host posture → config → secrets → binary hardening → logs |
| `scripts/playbooks/ip-assessment.md` | PTR → port scan → per-service TLS/HTTP → CVE correlation |

Both end with the same three report sections on purpose: **findings**, **what is
not wrong**, and **coverage gaps**. A report that lists only problems gives no
sense of how much was actually examined, and a model that does not say what it
could not determine will quietly leave gaps that look like passes.

### Using it from Cursor

`assess.sh` drives the model through `opencode run`, so it does not apply to
Cursor — Cursor is a chat client and will not run a playbook by itself. The MCP
server installs there normally; you paste the prompt instead:

```bash
SENTINELX_AUTHORISED=1 scripts/cursor.sh 203.0.113.10
```

That writes the `sentinel-x` entry into `~/.cursor/mcp.json` with
`SENTINELX_SCOPE_TARGETS` pinned to what you named, then prints the assessment
prompt for the chat. Re-run it to change the scope. The scope lives in the
config file because that is the only place Cursor reads it from, so unlike
`assess.sh` it is not a one-process setting.

#### Making the config portable

The entry is written with `--portable`, which records the command by name rather
than by absolute path:

```json
{"mcpServers": {"sentinel-x": {"command": "sentinel-x", "env": {...}}}}
```

An absolute path would pin the file to the account and checkout location of
whichever machine installed it — `/home/spectre05/SENTINEL-X/sentinel-x` resolves
nowhere else. The name is resolved through `PATH`, so the same file works
everywhere the binary is on `PATH`:

```bash
install -m 0755 sentinel-x ~/.local/bin/sentinel-x    # or /usr/local/bin
```

`--portable` is opt-out and verifies the name resolves at install time, so a
missing `PATH` entry surfaces now rather than as a silent failure inside the
client. `examples/cursor.mcp.json` is the same entry with the setup steps and
the scope rules written out, for copying to another machine.

Leave `SENTINELX_SCOPE_TARGETS` out and the server still answers, but stamps
every result with a notice that it ran unrestricted. Pinning it is the better
default; `scripts/cursor.sh` starts from `127.0.0.0/8` so nothing external is
reachable until you deliberately widen it.

Two differences from the OpenCode path are worth knowing. Cursor uses whichever
model your account provides, not `big-pickle`, and its tool-call discipline is
not something this project controls — the playbook carries the rules it needs
(the scope is given, do not shell out, an empty result is not a clean result) so
the report stays honest even when the model is less steerable.

`--local` runs with two settings the remote run does not use, both scoped to that
one process:

- `permission.external_directory` is allowed, because a self-audit is exactly the
  case where the interesting files live in `/etc`, `/usr` and `/var`, outside the
  project directory. Without it OpenCode refuses those reads and the audit
  silently omits `sshd_config`, sudoers and the rest.
- `permission.bash` stays refused, and that is deliberate rather than an
  oversight. SENTINEL-X confines every check to a fixed set of read-only system
  calls; letting the model run a shell would step around that entire guarantee.
  File modes, ownership and setuid bits come from `permission_audit` instead,
  which is a `stat(2)` wrapper that judges the combinations rather than dumping
  raw numbers.

If a target is refused as out of scope, the message names the entry that would
allow it:

```
policy refusal: target "www.example.com" is outside the authorised scope (example.com);
add "*.example.com" to SENTINELX_SCOPE_TARGETS to assess it
```

Naming a domain does not imply its subdomains on purpose — `example.com` can
front a very large estate — so the refusal tells you the exact scope to add
rather than widening itself.

Override the model with `SENTINELX_MODEL`:

```bash
SENTINELX_MODEL=opencode/big-pickle SENTINELX_AUTHORISED=1 scripts/assess.sh example.com
```

## Starting an assessment

Two tools answer the two questions an assessment actually opens with.

**"What is this host?"** — `sentinelx_network_profile` takes a single IP or hostname and
returns, in one call: who owns the address, the hop path to it, the operating system, every
open service with its version, and the exposures those versions imply.

```bash
# from Cursor, in plain language:
# "10.0.0.5'i derinlemesine incele, açıkları çıkar"
```

It runs as a sequence of stages, and reports each one in `coverage` — including the stages
that could not run. That matters: a deep profile that quietly skipped discovery would read
exactly like one that looked hard and found nothing.

| depth | what it adds |
|---|---|
| `quick` | ownership plus a top-100 service scan |
| `standard` | adds the hop path, OS detection and banner scripts |
| `deep` | adds TLS and cipher enumeration, certificate extraction, `--version-all` |

**"What is this machine doing on the network?"** — `sentinelx_traffic_audit` reads the
kernel's own connection tables under `/proc`: listening ports, established connections with
the owning process, ARP neighbours, the routing table and the resolver. It needs no root, and
reports which sockets it could not attribute to a process when it is not running as one.

It is worth being precise about what that is, because "traffic inspection" invites the wrong
model. **This is not packet capture.** There is no promiscuous mode, no payload decoding, and
it cannot see another machine's traffic or decrypt TLS. What it does give you is the thing
that usually answers the question — an unexpected listener, a process talking to a database
over cleartext, a management port bound to every interface, a host talking to a resolver you
did not configure.

---

## Output format

Every response — success or failure — is a JSON envelope with a stable shape, so a model can
parse it without guessing:

```json
{
  "tool": "sentinelx_port_scan",
  "target": "10.0.0.5",
  "timestamp": "2026-09-25T19:12:45Z",
  "duration_ms": 4210,
  "scope_notice": "SCOPE: no target scope is configured…",
  "secrets_redacted": true,
  "command": { "binary": "nmap", "args": ["-sV", "…"], "exit_code": 0 },
  "data": { "hosts": [ … ], "findings": [ … ] }
}
```

`command` records the exact invocation, so every finding is reproducible and auditable.

### A cached result says so

A repeat call inside `SENTINELX_CACHE_TTL` is served from memory and labelled in the
envelope itself, not in a footnote:

```json
{
  "tool": "sentinelx_port_scan",
  "target": "10.0.0.5",
  "timestamp": "2026-09-25T19:12:45Z",
  "cache_hit": true,
  "cache_age_ms": 240000,
  "cache_note": "RESULT SERVED FROM CACHE, 4m0s old (still probably current). Do not describe this as the current state of the target. Re-run this tool to refresh."
}
```

Two details matter. The `timestamp` is the **observation** time and is not rewritten on a
hit, because a ten-minute-old scan presented with a fresh timestamp is how stale data gets
reported as current. And the tools that change something — `sentinelx_setup`,
`sentinelx_baseline`, `sentinelx_sarif_report`, and the two active scanners — are never
cached at all. Replaying a successful "wrote /tmp/report.sarif" without touching the disk
would report success for an action that did not happen, which is worse than a slow call.

---

## Configuration

All environment-driven, all optional, all validated at start-up. **A malformed value is a
start-up error, not a silent default** — a typo in a timeout is exactly the thing an operator
needs to see.

| Variable | Default | Purpose |
|---|---|---|
| `SENTINELX_SCOPE_TARGETS` | *(unset)* | Comma-separated hosts, `*.suffix` wildcards, CIDRs, or bare suffixes. **Setting this enables scope enforcement automatically.** |
| `SENTINELX_ALLOW_PRIVATE_NETWORKS` | `true` | Permit RFC1918/loopback targets. Set `false` for internet-wide use. |
| `SENTINELX_OFFLINE` | `false` | Block **every** outbound call — NVD, `dig`, `whois`, HTTP probes, crt.sh. Checked before the request is issued, never after. Local audit tools keep working. |
| `SENTINELX_AUDIT_ROOTS` | `/etc`, `/usr/local/etc`, `/var/log`, `/opt`, `/srv`, `/home`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/lib` | **Replaces** the defaults; does not extend them. The executable directories are included so `sentinelx_binary_hardening` can inspect the system's own binaries. Paths that hold credentials (`/root`, `~/.ssh`) are outside every default root, and a symlink pointing out of a root is rejected. |
| `SENTINELX_RESOLVERS` | system resolver | Default resolver for `dig`. |
| `SENTINELX_NMAP_SCRIPTS` | 17 read-only NSE scripts | The closed script allowlist. |
| `SENTINELX_TIMEOUT_REON` / `_SCAN` / `_VULN` / `_AUDIT` / `_HTTP` / `_MAX` | 30s / 300s / 45s / 60s / 20s / 600s | Per-module budgets. A caller may shorten a budget but never raise it above `_MAX`. |
| `SENTINELX_MAX_OUTPUT_BYTES` | 2 MiB | Per-command output cap. |
| `SENTINELX_MAX_CONCURRENCY` | 4 | Simultaneously running external processes. |
| `SENTINELX_CACHE` | `on` | Memoise tool results. `off` / `0` / `false` / `no` / `disabled` (any case) turns it off. Every hit is labelled with its age. |
| `SENTINELX_CACHE_TTL` | `10m` | How long a memoised result stays servable. A nonsense value falls back to the default rather than disabling the cache. |
| `SENTINELX_CACHE_MAX` | `256` | Maximum cached envelopes. The oldest live entry is dropped to make room. |
| `SENTINELX_BUDGET_PER_TARGET` | `500` | External commands per target per hour. `0` means unlimited. |
| `SENTINELX_BUDGET_TOTAL` | `5000` | External commands per process per hour, across all targets. |
| `SENTINELX_BUDGET_PER_TOOL` | `1500` | External commands per binary per hour. |
| `SENTINELX_AUTO_INSTALL` | `on` | `off` makes `sentinelx_setup` report without installing. |
| `SENTINELX_VERBOSE` | `false` | Diagnostic logging to **stderr** (stdout is the protocol stream). |
| `NVD_API_KEY` | *(unset)* | Raises the NVD rate limit from 5 to 50 requests / 30s. The two tiers get separate limiters, so a client with a key is never throttled at the anonymous ceiling. |
| `SENTINELX_DKIM_SELECTORS` | a common default set | Extra DKIM selectors probed by `sentinelx_dns_security_audit`. |

---

## Process containment

`internal/utils` is the only place SENTINEL-X executes anything. Four guarantees:

- **Allowlist** — binary name resolved via `exec.LookPath` against a closed set; the check runs
  on the *base name*, so `/bin/bash` cannot pose as an allowed binary.
- **Argument vetting** — every argv element matched against global plus per-binary regexes
  before `Start()`. Per-binary scoping is what allows `searchsploit -p` to be refused while
  `nmap -p 1-1024` runs.
- **Timeout and process-group kill** — the child runs in its own process group. On expiry the
  whole group gets `SIGKILL`. `exec.CommandContext` alone is *not* enough: it signals only the
  direct child, and `cmd.Wait` blocks until the pipes close, so a backgrounded grandchild would
  keep the call blocked long past the deadline. `Runner.start` therefore signals the group the
  instant the context fires and refuses to wait on the reaper for more than 2 seconds.
  *(A regression test covers this; the bug cost 33 s before the fix, 0.31 s after.)*
- **Bounded output and a sanitised environment** — a size-capped buffer that reports truncation
  rather than growing without bound, and a minimal `PATH`/`HOME`/`LC_ALL` env so a hostile parent
  shell cannot inject `LD_PRELOAD` or `http_proxy` into a child.

---

## Honest limitations

These are real, and the server says so in its output rather than hiding them:

- **Version detection is a hypothesis.** Nmap fingerprints are probabilistic; every finding
  carries the reported confidence.
- **CPE matching is exact-string.** Distribution backports (Debian/Ubuntu/RHEL point releases)
  are frequently mislabelled by vendor records. `sentinelx_version_risk` returns an explicit
  per-match confidence and states this limitation in every response.
- **A clean audit is not a clean host.** The posture audit sees only what the current process
  can read. Run it as root for full `sshd` and firewall coverage, or the absence of a finding
  is meaningless.
- **NVD is not exhaustive.** Absent a match is not evidence of safety. The response says so.
- **"Not audited" is not "clean".** A manifest component with no version, or one whose CPE cannot
  be matched confidently, is reported as not audited. It is never rounded down to "no findings".
- **Passive subdomain discovery depends on a third party.** crt.sh is a volunteer-run service
  that is frequently slow or returning 5xx. When it is unavailable the tool says so instead of
  returning an empty result that would read as "no subdomains exist".
- **Binary hardening reads headers, not behaviour.** A set of mitigations does not mean the
  program is free of vulnerabilities, and the absence of NX or RELRO is not a finding about
  anything except the build flags.
- **The Kubernetes audit reads one file.** It says nothing about what the credentials in that
  file can reach. The server never contacts a cluster.
- **No automatic exploitation, by design.** If a request needs it, the model is told to say so
  plainly rather than attempting a workaround.
- **Metasploit coverage is index data, not a vulnerability finding.**
  `sentinelx_metasploit_reference` reads module metadata off disk and never runs a module. That a
  public exploit module exists for a CVE says a known attack path is published; it says nothing
  about whether any given target is affected. The tool states this in every response, and a
  missing module tree is reported as unavailable rather than as "no coverage".
- **SARIF counts findings, it does not score risk.** `sentinelx_sarif_report` maps each finding's
  reported severity onto a SARIF level and says so; it does not compute a risk score, and every result
  carries its own evidence and confidence so a consumer can tell a confirmed finding from a fingerprint
  hypothesis. Unknown severity becomes `note`, never `error`. An empty `results` array means no findings
  were supplied, which is not a statement that the target is clean.
- **Module coverage ages.** The index is whatever `metasploit-framework` ships on this machine at
  the moment it is read. It is not refreshed, and a CVE absent from a stale tree may still have
  a public exploit.
- **Baselines show change, not proof.** `sentinelx_baseline` stores fingerprints only, not evidence.
  A finding that stops appearing is reported as resolved, but it cannot distinguish a genuine fix
  from a service being down, a narrower scan, or a changed tool. The caveat is printed on every
  diff, and the baseline is written under the user config directory with owner-only permissions.

---

## Layout

```
sentinel-x/
├── go.mod
├── main.go                       # Stdio MCP server, registration, signal handling
├── cmd/smoke/                    # End-to-end stdio test (build tag: smoke)
├── cmd/offline_smoke/            # Proves OFFLINE blocks every egress path (build tag: smoke)
├── cmd/install_smoke/            # Install into each client, then start it (build tag: smoke)
├── install_cli.go                # install / uninstall / list subcommands
├── install_path_unix.go          # Path handling per platform
├── install_path_windows.go
└── internal/
    ├── config/config.go          # Env config + the security policy
    ├── install/install.go        # MCP client dialects, merge, atomic write
    ├── utils/
    │   ├── exec.go               # Allowlisted, vetted, timeboxed process runner
    │   ├── proc_unix.go          # Process-group kill
    │   ├── buffer.go             # Size-capped output capture
    │   └── redact.go             # Secret scrubbing
    └── tools/
        ├── common.go             # JSON envelope, argument helpers
        ├── tools.go              # Tool options, URL/port validation
        ├── recon.go              # DNS, WHOIS, reverse DNS, DNS posture, CT subdomains
        ├── dnssec_audit.go       # DNSSEC/SPF/DMARC/CAA analysis, crt.sh enumeration
        ├── scanner.go            # nmap -sV, TLS audit, HTTP headers
        ├── scan_parse.go         # nmap/TLS/HTTP parsers + triage rules
        ├── vulnerability.go      # NVD API, version correlation, advisory index
├── metasploit.go         # offline Metasploit module coverage lookup
├── sarif.go              # SARIF 2.1.0 output for CI
├── baseline.go           # save baselines and report what changed
        ├── supplychain.go        # Manifest discovery/parsing, SBOM, dependency audit
        ├── platform.go           # ELF/PE/Mach-O hardening, kubeconfig, log threats
        ├── stat_unix.go          # UID/GID helpers (!windows)
        ├── stat_windows.go       # UID/GID stubs (windows)
        └── audit.go              # Posture, config lint, secret scan, permissions
```

---

## Legal

SENTINEL-X is a defensive security tool. Use it only against systems you own or are explicitly
authorised to assess. Scanning third-party systems without authorisation is a criminal offence
in most jurisdictions, including under the CFAA (17 U.S.C. §1030) and the Computer Misuse Act
1990 (UK).

MIT licensed.
