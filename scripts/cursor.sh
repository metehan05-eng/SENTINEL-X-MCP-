#!/usr/bin/env bash
# Set up SENTINEL-X for Cursor and print the prompt to paste into its chat.
#
#   scripts/cursor.sh 203.0.113.10
#   scripts/cursor.sh 203.0.113.0/24
#   SENTINELX_ALLOW_PRIVATE_NETWORKS=1 scripts/cursor.sh 192.168.1.1
#
# Cursor is a chat client, not an agent runner, so the assessment prompt cannot
# be executed for you the way `assess.sh` does it through `opencode run`. What
# this script does is pin the scope into the MCP entry and then print the prompt
# so the audit is the same question in both clients.
#
# The scope is written into the config file rather than passed per run, because
# that is the only place Cursor reads it. Re-run this script to change it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/sentinel-x"
PLAYBOOK="$REPO_ROOT/scripts/playbooks/ip-assessment.md"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $# -ge 1 ]] || {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 1
}

TARGETS=("$@")
for t in "${TARGETS[@]}"; do
  if [[ "$t" == -* ]]; then die "unexpected option '$t'"; fi
done

[[ -x "$BIN" ]] || die "server binary not found (run: export PATH=/tmp/opencode/go/bin:\$PATH && go build -o sentinel-x .)"

# The config registers the command by name, so the binary has to be on PATH on
# every machine that reads the config. Offer the one-line fix rather than an
# error the user has to interpret.
if ! command -v sentinel-x >/dev/null; then
  info "sentinel-x is not on PATH, so a config that registers the name would point at nothing"
  info "fix it with:  sudo install -m 0755 '$BIN' /usr/local/bin/sentinel-x"
  die "add the binary to PATH, then run this again"
fi
[[ -f "$PLAYBOOK" ]] || die "playbook missing: $PLAYBOOK"

SCOPE="$(IFS=,; echo "${TARGETS[*]}")"

# The authorisation gate lives in this script, not in the server. Naming an
# address means asserting you are allowed to test it.
if [[ "${SENTINELX_AUTHORISED:-0}" != "1" ]]; then
  cat <<'MSG'
error: you have not confirmed authorisation.

  These tools send TCP connections, TLS handshakes and HTTP requests to whatever
  you name, so pointing them at someone else's address is an unauthorised
  assessment however passive any single tool looks.

  If the address is yours, or you have written permission to test it:

      SENTINELX_AUTHORISED=1 scripts/cursor.sh <address>

MSG
  exit 3
fi

# --portable registers the command by name rather than by absolute path, so the
# config keeps working if it is copied to another machine or the repository is
# moved. examples/cursor.mcp.json is the same entry, documented for sharing.
ENV_ARGS=(--portable --env "SENTINELX_SCOPE_TARGETS=$SCOPE")
# Private addresses are refused by default policy. Forward the operator's own
# decision rather than making them re-derive the variable name.
if [[ "${SENTINELX_ALLOW_PRIVATE_NETWORKS:-0}" == "1" ]]; then
  ENV_ARGS+=(--env "SENTINELX_ALLOW_PRIVATE_NETWORKS=true")
fi

info "installing the MCP entry for Cursor, scope pinned to: $SCOPE"
"$BIN" install --client cursor "${ENV_ARGS[@]}"

cat <<MSG

$(info "scope: $SCOPE")

==============================================================================
PASTE THIS INTO THE CURSOR CHAT
==============================================================================

$(sed "s|<!-- SCOPE -->|- The authorised target is: $SCOPE|" "$PLAYBOOK" | sed -n '1,/^## What does not apply here/p' | head -n -1)

==============================================================================

If Cursor asks whether to allow the MCP tools, allow them: every check this
assessment makes is read-only, and refusing the tools produces a report that
claims nothing was found because nothing was looked at.
MSG
