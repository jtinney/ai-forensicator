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

# Reject vague action text
case "$ACTION" in
    ""|"analysis update"|"progress"|"update"|"note"|"todo")
        echo "audit.sh: refused — action must name the exact triggering step" >&2
        exit 3
        ;;
esac

UTC_NOW="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
# Collapse literal pipes in args so they don't break the delimiter
ACTION_SAFE="${ACTION//|/\\|}"
RESULT_SAFE="${RESULT//|/\\|}"
NEXT_SAFE="${NEXT//|/\\|}"

printf "%s | %s | %s | %s\n" "$UTC_NOW" "$ACTION_SAFE" "$RESULT_SAFE" "$NEXT_SAFE" >> "$AUDIT"
echo "[audit] appended -> $AUDIT"
