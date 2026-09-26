#!/usr/bin/env bash
# SENTINEL-X assessment runner.
#
# Drives OpenCode through a full read-only assessment of the targets you name,
# with the MCP server's scope pinned to exactly those targets so the model
# cannot wander onto anything else.
#
# The scope is passed inline through OPENCODE_CONFIG_CONTENT, which means this
# script never edits your real opencode.json and never leaves a stale scope
# behind for the next session.
#
# Usage:
#   scripts/assess.sh <target> [target...]
#   scripts/assess.sh --local
#
# Examples:
#   scripts/assess.sh example.com
#   scripts/assess.sh app.example.com api.example.com
#   scripts/assess.sh 203.0.113.10
#   scripts/assess.sh 10.0.0.0/24
#   scripts/assess.sh --local            # audit this machine instead
#
# You must confirm you are authorised to test what you name:
#   SENTINELX_AUTHORISED=1 scripts/assess.sh example.com

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/sentinel-x"
MODEL="${SENTINELX_MODEL:-opencode/big-pickle}"
DEEP_PROMPT="$REPO_ROOT/scripts/playbooks/deep-assessment.md"
LOCAL_PROMPT="$REPO_ROOT/scripts/playbooks/local-audit.md"

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------- arguments

LOCAL=0
if [[ "${1:-}" == "--local" ]]; then
  LOCAL=1
  shift
fi

TARGETS=("$@")

if [[ $LOCAL -eq 0 && ${#TARGETS[@]} -eq 0 ]]; then
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
fi

# ------------------------------------------------- authorisation confirmation
#
# Only the remote modes need this. --local audits the machine you are already
# sitting at, which cannot be someone else's infrastructure.

if [[ $LOCAL -eq 0 && "${SENTINELX_AUTHORISED:-0}" != "1" ]]; then
  cat >&2 <<'EOF'

These tools actively probe the targets you name: DNS queries, TCP port scans,
TLS negotiation and HTTP requests. That is a security assessment, so it has to
be one you are allowed to perform.

Re-run with SENTINELX_AUTHORISED=1 to confirm you own the targets or have
written permission to test them.

    SENTINELX_AUTHORISED=1 scripts/assess.sh example.com

EOF
  exit 3
fi

# ------------------------------------------------------------------ validate

# Reject anything that is not a plain hostname, IP or CIDR before it reaches a
# config file or a network call.
validate_target() {
  local t="$1"
  if [[ "$t" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
     [[ "$t" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] ||
     [[ "$t" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
    return 0
  fi
  die "refusing target '$t': not a hostname, IP address or CIDR"
}

if [[ $LOCAL -eq 0 ]]; then
  for t in "${TARGETS[@]}"; do
    [[ "$t" == -* ]] && die "unexpected option '$t'"
    validate_target "$t"
  done
fi

# ----------------------------------------------------------------- preflight

[[ -x "$BIN" ]] || die "server binary not found at $BIN (run: go build -o sentinel-x .)"
command -v opencode >/dev/null || die "opencode is not on PATH"
[[ -f "$DEEP_PROMPT" ]] || die "playbook missing: $DEEP_PROMPT"
[[ -f "$LOCAL_PROMPT" ]] || die "playbook missing: $LOCAL_PROMPT"

for tool in dig nmap curl; do
  command -v "$tool" >/dev/null || info "warning: '$tool' is not installed; the tools that need it will refuse to run"
done

SCOPE="$(IFS=,; echo "${TARGETS[*]}")"

# ------------------------------------------------------------------- run it

if [[ $LOCAL -eq 1 ]]; then
  info "auditing this machine with $MODEL (no network scope needed)"
  # A self-audit is precisely the case where the interesting files live in
  # /etc, /usr and /var, which sit outside the project directory. OpenCode
  # refuses those reads as external_directory unless this one process is told
  # otherwise, and a half-run audit that silently omits sshd_config and
  # login.defs is worse than no audit. Scoped to this process only.
  LOCAL_CONFIG=$(cat <<JSON
{
  "\$schema": "https://opencode.ai/config.json",
  "permission": {
    "external_directory": "allow",
    "bash": "ask"
  }
}
JSON
)
  export OPENCODE_CONFIG_CONTENT="$LOCAL_CONFIG"

  # Give the model the host facts it would otherwise reach for with `pwd`, `id`
  # and `uname`. Those are refused in this run, and a model that opens with a
  # refused call tends to stop there instead of continuing the audit. Nothing
  # here is secret: it is the same information host_posture_audit reports.
  CONTEXT=$(cat <<CONTEXT_BLOCK
## This machine

The audit target is the host you are running on. Shell access is refused in this
run, so these are the facts you would otherwise have to look up yourself:

- working directory: $PWD
- user: $(id -un)
- kernel: $(uname -sr)
- hostname: $(hostname)
- audit roots the server will accept paths under: /etc, /usr/local/etc,
  /var/log, /opt, /srv, /home, /usr/bin, /usr/sbin, /bin, /sbin, /usr/lib

Begin with \`sentinelx_host_posture_audit\`. Do not run shell commands.
CONTEXT_BLOCK
)
  exec opencode run --model "$MODEL" "$CONTEXT

$(cat "$LOCAL_PROMPT")"
fi

info "scope: $SCOPE"
info "model: $MODEL"
info "targets: ${#TARGETS[@]}"

# OPENCODE_CONFIG_CONTENT is merged over the user's own config for this one
# process only. Declaring the server here pins its scope to the targets above,
# so a misjudged model call is refused by the server rather than reaching the
# network.
CONFIG=$(cat <<JSON
{
  "\$schema": "https://opencode.ai/config.json",
  "mcp": {
    "sentinel-x": {
      "type": "local",
      "command": ["$BIN"],
      "enabled": true,
      "environment": {
        "SENTINELX_SCOPE_TARGETS": "$SCOPE",
        "SENTINELX_VERBOSE": "true"
      }
    }
  }
}
JSON
)

# The model is told the scope directly. Left to discover it, it spends turns
# dumping the environment and reading client configuration, and the
# configuration reads are refused by the client's own sandbox anyway.
PROMPT=$(sed "s|<!-- SCOPE -->|- The authorised targets are: $SCOPE|" "$DEEP_PROMPT")

printf '\n'
OPENCODE_CONFIG_CONTENT="$CONFIG" \
  exec opencode run --model "$MODEL" "$PROMPT"
