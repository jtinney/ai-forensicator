#!/usr/bin/env bash
# audit-pretool-deny.sh — PreToolUse hook for the `Bash` tool.
#
# Reads the proposed Bash command from stdin (Claude Code hook JSON envelope)
# and exits 2 (deny) when the command writes to ./analysis/forensic_audit.log
# via shell redirection (>, >>), `tee`, or in-place sed. The only allowed write
# path is through `audit.sh`, which stamps the wall-clock UTC timestamp itself.
# This is enforcement for DISCIPLINE.md rule A (audit-log integrity).
#
# Read-only access to the audit log (cat / head / tail / grep / wc) is unaffected.
#
# Wired in .claude/settings.json under hooks.PreToolUse, matcher "Bash".

set -u

# ---- read hook envelope from stdin ----
input="$(cat 2>/dev/null || true)"
if [[ -z "$input" ]]; then
    # Empty stdin — no command to inspect, allow by default
    exit 0
fi

# Extract tool_input.command. Prefer python3 (always present on SIFT) for
# robust JSON parsing; fall back to a permissive grep if python3 is missing.
cmd=""
if command -v python3 >/dev/null 2>&1; then
    cmd="$(printf '%s' "$input" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get("tool_input", {}).get("command", ""))
except Exception:
    pass
' 2>/dev/null || true)"
fi
if [[ -z "$cmd" ]]; then
    # Last-resort extraction — tolerate missing python or malformed envelope
    cmd="$(printf '%s' "$input" | grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"command"[[:space:]]*:[[:space:]]*"(.*)"/\1/' || true)"
fi

# Nothing to inspect — allow
[[ -z "$cmd" ]] && exit 0

# ---- allow path: any invocation of the audit framework scripts themselves ----
# (audit.sh is the canonical writer; the others are read-only or write
# integrity-violation rows via audit.sh, so they cannot forge timestamps.)
if printf '%s' "$cmd" | grep -qE '(audit\.sh|audit-verify\.sh|audit-retrofit\.sh|audit-pretool-deny\.sh)'; then
    exit 0
fi

# ---- deny path: write op TARGETING forensic_audit.log specifically ----
# The patterns are deliberately destination-pinned to avoid false positives
# on benign commands that happen to mention forensic_audit.log (e.g.
# `printf 'note about forensic_audit.log' > /tmp/foo` is allowed).
#
# Matches:
#   (a) shell redirection (>, >>) where the target ends with forensic_audit.log
#   (b) tee [-a] forensic_audit.log
#   (c) sed -i ... forensic_audit.log
#   (d) dd of=...forensic_audit.log
#   (e) cp / mv / install / rsync with forensic_audit.log in arg list
#       (these are blunter — we deny any cp/mv whose args mention the log)
#   (f) python -c "...open('...forensic_audit...', ...).write(..."
DENY_RE='((>>?|tee[[:space:]]+(-a[[:space:]]+)?|sed[[:space:]]+-i[[:space:]]+|dd[[:space:]]+[^|;]*of=)[^|;>&]*forensic_audit\.log)|(\b(cp|mv|install|rsync)\b[^|;&]*forensic_audit\.log)|(\bpython3?\b[^|;&]*open\([^)]*forensic_audit)'

if printf '%s' "$cmd" | grep -qE "$DENY_RE"; then
    cat >&2 <<EOF
PreToolUse DENY: forensic_audit.log writes must go through audit.sh.

Why: audit.sh stamps the wall-clock UTC timestamp itself (date -u +%Y-%m-%d %H:%M:%S UTC).
Direct \`>>\` / \`>\` / \`tee\` / \`sed -i\` / \`cp\` / \`mv\` / \`python open()\` writes let the
agent assert a timestamp that does not match wall-clock — a chain-of-custody violation.

Use:  bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next step>"

If you genuinely need to read the audit log, use cat / head / tail / grep / Read —
those are not denied. If you need to inspect a forensic_audit.log from a closed
case, copy it under a different filename first (e.g. \`cp source.log /tmp/inspect.txt\`)
or use \`audit-retrofit.sh\` for offline integrity checking.

See: .claude/skills/dfir-discipline/DISCIPLINE.md rule A
EOF
    exit 2
fi

# ---- manifest gate (issue #12) ----
# When the proposed Bash command's argv references ./evidence/ or
# ./analysis/_extracted/, run manifest-check.sh --quiet. If the manifest
# is broken (missing rows, bespoke hash files, partial expansion, etc.)
# refuse the command — agents must not read evidence on top of an
# untrustworthy ledger.
#
# Scoped tightly so unrelated Bash calls are not slowed by the check.
# A pass on a well-formed case is < 200 ms; the python json-parse + os.walk
# fast-path is intentional. The /case slash command also runs manifest-check
# directly (belt-and-suspenders); this hook catches agents that bypass /case.
#
# Allow the manifest-check itself, the audit framework, and case-init.sh
# (which builds the manifest) through unconditionally — otherwise the check
# becomes a chicken-and-egg: case-init.sh creates rows but cannot read
# evidence to do so.
if printf '%s' "$cmd" | grep -qE '(manifest-check\.sh|case-init\.sh|extraction-plan\.sh|extraction-cleanup\.sh|preflight\.sh|intake-check\.sh|intake-interview\.sh|leads-check\.sh|baseline-check\.sh|mitre-validate\.sh|lint-survey\.sh|spreadsheet-of-doom)'; then
    exit 0
fi

# Match argv tokens that reference the two protected directories. Pin to
# ./evidence/ or evidence/ and ./analysis/_extracted/ or analysis/_extracted/
# (with optional leading dot-slash). The pattern is deliberately narrow so
# benign mentions in stdin / quoted strings don't trigger the check.
TARGET_RE='(^|[[:space:]=])(\.?\/)?(evidence|analysis\/_extracted)\/'
if printf '%s' "$cmd" | grep -qE "$TARGET_RE"; then
    SCRIPT_DIR_HOOK="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
    MANIFEST_CHECK="${SCRIPT_DIR_HOOK}/manifest-check.sh"
    if [[ -x "$MANIFEST_CHECK" && -d ./analysis ]]; then
        # Run from the case workspace (CWD when the hook fires). Suppress
        # stdout, capture stderr only on failure so the deny message is
        # actionable. Use --quiet for fast-path.
        rc=0
        check_stderr="$(bash "$MANIFEST_CHECK" --quiet 2>&1 >/dev/null)" || rc=$?
        if [[ "$rc" -eq 1 ]]; then
            cat >&2 <<EOF
PreToolUse DENY: manifest integrity check failed.

The proposed command references ./evidence/ or ./analysis/_extracted/, but
analysis/manifest.md is incomplete (missing rows, partial bundle expansion,
or a bespoke hash file lives outside the canonical ledger).

Run for full details:
  bash .claude/skills/dfir-bootstrap/manifest-check.sh

Quick summary from --quiet:
$(printf '%s\n' "$check_stderr" | sed 's/^/  /')

Resolution paths:
  - case-init.sh-side issues (missing manifest rows, partial expansion):
      operator clears analysis/_extracted/<basename>/ then re-runs
      bash .claude/skills/dfir-bootstrap/case-init.sh <CASE_ID>
  - bespoke hash file: reconcile its rows into manifest.md, then remove
    the bespoke file (do NOT blindly delete — it may carry real work).

See: GitHub issue #12 (case-init determinism + manifest-check gate)
EOF
            exit 2
        fi
        # rc 0 (PASS) or rc 2 (preconditions wrong, e.g. fresh case
        # without analysis/) — allow.
    fi
fi

exit 0
