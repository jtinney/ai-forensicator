#!/usr/bin/env bash
# audit.sh — append a properly-formatted entry to ./analysis/forensic_audit.log
# Format enforced by the Analysis Discipline contract across all DFIR skills:
#   <UTC timestamp> | <action> | <finding/result> | <next step>

set -eu

if [[ $# -lt 3 ]]; then
    cat >&2 <<EOF
usage: audit.sh "<action>" "<finding/result>" "<next step>"

Example:
  audit.sh "fls -r -o 65664 evidence.E01" \\
           "11553 entries, NTFS partition at offset 65664" \\
           "feed to mactime -> theft-window slice"
EOF
    exit 2
fi

ACTION="$1"
RESULT="$2"
NEXT="$3"

AUDIT="./analysis/forensic_audit.log"
if [[ ! -f "$AUDIT" ]]; then
    mkdir -p ./analysis
    echo "# Forensic audit log (created by audit.sh)" > "$AUDIT"
fi

# ---- reject malformed entries up front ----
# 1. Vague / placeholder action text — these always indicate an agent
#    skipped the discipline of naming the triggering step.
case "$ACTION" in
    ""|"analysis update"|"progress"|"update"|"note"|"todo"|"work"|"continue")
        echo "audit.sh: refused — action must name the exact triggering step" >&2
        exit 3
        ;;
esac
# 2. Empty result or next-step fields are also discipline failures.
#    A row with no result is just noise; a row with no next step has
#    nothing to chain off. Stop-hook entries are an exception (caller
#    sets a fixed pseudo-result; we allow them).
if [[ -z "$RESULT" || -z "$NEXT" ]]; then
    if [[ "$ACTION" != "stop_hook" ]]; then
        echo "audit.sh: refused — result and next-step fields are required" >&2
        exit 3
    fi
fi

# ---- de-dupe: if the previous row has the SAME action and result and
#      was logged within the last 5 seconds, skip. This catches
#      double-firing PostToolUse hooks (e.g. audit-exports.sh)
#      without losing legitimate repeated entries. ----
if [[ -s "$AUDIT" ]]; then
    last_line="$(tail -1 "$AUDIT" 2>/dev/null || true)"
    # Only check pipe-delimited rows
    if [[ "$last_line" == *" | "* ]]; then
        last_ts="${last_line%% |*}"
        last_action="$(echo "$last_line" | awk -F' \\| ' '{print $2}')"
        last_result="$(echo "$last_line" | awk -F' \\| ' '{print $3}')"
        # Compare epoch seconds; the timestamp is "YYYY-MM-DD HH:MM:SS UTC"
        last_epoch="$(date -u -d "${last_ts}" +%s 2>/dev/null || echo 0)"
        now_epoch="$(date -u +%s)"
        if [[ "$last_action" == "$ACTION" && "$last_result" == "$RESULT" \
              && "$last_epoch" -gt 0 && $((now_epoch - last_epoch)) -lt 5 ]]; then
            # Silently skip — this is a hook double-fire, not a real second event.
            exit 0
        fi
    fi
fi

UTC_NOW="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
# Collapse literal pipes in args so they don't break the delimiter
ACTION_SAFE="${ACTION//|/\\|}"
RESULT_SAFE="${RESULT//|/\\|}"
NEXT_SAFE="${NEXT//|/\\|}"

printf "%s | %s | %s | %s\n" "$UTC_NOW" "$ACTION_SAFE" "$RESULT_SAFE" "$NEXT_SAFE" >> "$AUDIT"
echo "[audit] appended -> $AUDIT"
