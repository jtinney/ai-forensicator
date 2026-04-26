#!/usr/bin/env bash
# audit-stop.sh — Stop-event hook. Records a session-boundary marker in
# the forensic audit log, but ONLY when the prior session actually
# produced work. A run of stop_hook entries with no interleaved analysis
# rows is noise; this script suppresses the repeat.
#
# Wired in .claude/settings.json under hooks.Stop.

set -u

AUDIT="./analysis/forensic_audit.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="$SCRIPT_DIR/audit.sh"

# Quiet exit if not in a case dir
[[ -d ./analysis ]] || exit 0
[[ -f "$AUDIT" ]] || exit 0
[[ -x "$AUDIT_SH" ]] || exit 0

# Inspect the last non-comment row. If it's already a stop_hook, this
# session produced no work — skip logging another marker.
last_row="$(grep -v '^#' "$AUDIT" 2>/dev/null | tail -1)"
if [[ -z "$last_row" ]]; then
    exit 0
fi

# Extract the action field (column 2 of the pipe-delimited row)
last_action="$(echo "$last_row" | awk -F' \\| ' '{print $2}')"
if [[ "$last_action" == "stop_hook" ]]; then
    # Previous boundary was already a stop_hook with no work in between.
    # Don't add another — it's noise.
    exit 0
fi

# Real session boundary; log it.
bash "$AUDIT_SH" "stop_hook" \
    "session boundary — last work entry was: $(echo "$last_action" | cut -c1-80)" \
    "review prior audit entries and ./analysis/<domain>/findings.md for context" \
    >/dev/null 2>&1 || true

exit 0
