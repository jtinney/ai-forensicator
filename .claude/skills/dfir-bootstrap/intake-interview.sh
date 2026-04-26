#!/usr/bin/env bash
# intake-interview.sh — interactively populate blank chain-of-custody
# fields in ./reports/00_intake.md. Refuses to accept blank or
# placeholder responses (use "n/a — <reason>" if a field genuinely does
# not apply).
#
# Modes:
#   - default: read from /dev/tty interactively. If /dev/tty is not
#     available (non-interactive harness), exit nonzero with a marker
#     file at ./analysis/.intake-pending and a clear message so the
#     orchestrator can surface to the user.
#   - --from-env: each missing field is supplied via environment
#     variables INTAKE_SOURCE / INTAKE_ACQUIRED / INTAKE_RECEIVED /
#     INTAKE_EVIDENCE_HASH / INTAKE_INTEGRITY / INTAKE_INCIDENT /
#     INTAKE_PRIORITIES. Useful for harness-driven non-TTY flows.
#
# Idempotent. Only fills fields that intake-check.sh reports blank.

set -u

INTAKE="./reports/00_intake.md"
PENDING_FILE="./analysis/.intake-pending"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
INTAKE_CHECK="$SCRIPT_DIR/intake-check.sh"
AUDIT_SH="$SCRIPT_DIR/audit.sh"
MODE="${1:-tty}"

if [[ ! -f "$INTAKE" ]]; then
    echo "intake-interview: $INTAKE not found — run case-init.sh first" >&2
    exit 2
fi

# ---- discover blank fields via intake-check ----
blank_fields=()
while IFS= read -r line; do
    [[ -n "$line" ]] && blank_fields+=("$line")
done < <(bash "$INTAKE_CHECK" 2>&1 | sed -n 's/^  - //p')

if [[ ${#blank_fields[@]} -eq 0 ]]; then
    echo "intake-interview: all required fields already populated; nothing to do."
    rm -f "$PENDING_FILE" 2>/dev/null
    exit 0
fi

# Hints for each known field
declare -A HINTS=(
    ["Source"]="who handed it over (name, org, ticket, badge #)"
    ["Acquired"]="when + where + how it was collected (UTC date, host, tool)"
    ["Received"]="when it landed in this case directory (UTC date, examiner)"
    ["Evidence hash (SHA-256)"]="paste the sha256 of the primary evidence file (or 'see manifest.md' if multi-item)"
    ["Integrity verification"]="how was the hash confirmed at intake (e.g. 'sha256sum vs sender-provided hash matched')"
    ["Reported incident"]="the original incident ticket / report / case reference"
    ["Analyst priorities"]="what the requester wants answered first (1-2 sentences)"
)

declare -A INPUT=()

# ---- gather inputs ----
if [[ "$MODE" == "--from-env" ]]; then
    INPUT["Source"]="${INTAKE_SOURCE:-}"
    INPUT["Acquired"]="${INTAKE_ACQUIRED:-}"
    INPUT["Received"]="${INTAKE_RECEIVED:-}"
    INPUT["Evidence hash (SHA-256)"]="${INTAKE_EVIDENCE_HASH:-}"
    INPUT["Integrity verification"]="${INTAKE_INTEGRITY:-}"
    INPUT["Reported incident"]="${INTAKE_INCIDENT:-}"
    INPUT["Analyst priorities"]="${INTAKE_PRIORITIES:-}"
    for f in "${blank_fields[@]}"; do
        if [[ -z "${INPUT[$f]:-}" ]]; then
            echo "intake-interview: --from-env mode but no value supplied for '$f'" >&2
            echo "intake-interview: set the matching INTAKE_* env var and re-run" >&2
            exit 1
        fi
    done
else
    # TTY mode
    if ! { [[ -r /dev/tty ]] && [[ -w /dev/tty ]]; }; then
        # Non-interactive harness — leave a pending marker for the orchestrator
        mkdir -p "$(dirname "$PENDING_FILE")" 2>/dev/null
        {
            printf "INTAKE-PENDING — %s\n" "$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
            printf "Blank fields requiring operator input:\n"
            for f in "${blank_fields[@]}"; do
                printf "  - %s — %s\n" "$f" "${HINTS[$f]:-}"
            done
            printf "\nResolve via:\n"
            printf "  bash .claude/skills/dfir-bootstrap/intake-interview.sh             # interactive\n"
            printf "  bash .claude/skills/dfir-bootstrap/intake-interview.sh --from-env    # set INTAKE_* env vars first\n"
        } > "$PENDING_FILE"
        echo "intake-interview: no TTY available; created $PENDING_FILE" >&2
        echo "  ${#blank_fields[@]} blank field(s); operator must complete intake before phases 4/5/6 will run." >&2
        exit 3
    fi

    printf "\n=== Case Intake Interview ===\n"
    printf "Filling %d blank chain-of-custody field(s) in %s\n" "${#blank_fields[@]}" "$INTAKE"
    printf "Use 'n/a — <reason>' if a field genuinely does not apply.\n"
    for f in "${blank_fields[@]}"; do
        val=""
        while true; do
            printf "\n[intake] %s\n" "$f"
            [[ -n "${HINTS[$f]:-}" ]] && printf "        (%s)\n" "${HINTS[$f]}"
            printf "      > "
            IFS= read -r val < /dev/tty || {
                echo "intake-interview: aborted by operator before completion" >&2
                exit 4
            }
            # Strip leading/trailing whitespace
            val="${val#"${val%%[![:space:]]*}"}"
            val="${val%"${val##*[![:space:]]}"}"
            if [[ -z "$val" ]] || echo "$val" | grep -qiE '^(TBD|TODO|FIXME|N/A|\?|-)$'; then
                printf "      ! blank/placeholder rejected. Use 'n/a — <reason>' if this field genuinely does not apply.\n"
                continue
            fi
            if [[ "$val" == *$'\n'* ]]; then
                printf "      ! newlines not allowed in a single field; collapse to one line.\n"
                continue
            fi
            break
        done
        INPUT["$f"]="$val"
    done
fi

# ---- write back into 00_intake.md (Python for safe in-place edit) ----
export __IF_Source="${INPUT["Source"]:-}"
export __IF_Acquired="${INPUT["Acquired"]:-}"
export __IF_Received="${INPUT["Received"]:-}"
export __IF_EvidenceHash="${INPUT["Evidence hash (SHA-256)"]:-}"
export __IF_Integrity="${INPUT["Integrity verification"]:-}"
export __IF_Incident="${INPUT["Reported incident"]:-}"
export __IF_Priorities="${INPUT["Analyst priorities"]:-}"

python3 - "$INTAKE" <<'PY'
import os, re, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    lines = fh.readlines()

mapping = [
    ("- Source:",                  os.environ.get("__IF_Source", "")),
    ("- Acquired:",                os.environ.get("__IF_Acquired", "")),
    ("- Received:",                os.environ.get("__IF_Received", "")),
    ("- Evidence hash (SHA-256):", os.environ.get("__IF_EvidenceHash", "")),
    ("- Integrity verification:",  os.environ.get("__IF_Integrity", "")),
    ("- Reported incident:",       os.environ.get("__IF_Incident", "")),
    ("- Analyst priorities:",      os.environ.get("__IF_Priorities", "")),
]
placeholder_re = re.compile(r"^\s*(?:TBD|TODO|FIXME|N/A|\?|-)?\s*$", re.IGNORECASE)

out = []
for ln in lines:
    handled = False
    for prefix, value in mapping:
        if not value:
            continue
        if ln.startswith(prefix):
            current = ln[len(prefix):].rstrip("\n")
            if placeholder_re.match(current):
                out.append(f"{prefix} {value}\n")
                handled = True
            break
    if not handled:
        out.append(ln)

with open(path, "w", encoding="utf-8") as fh:
    fh.writelines(out)
PY

# ---- verify, audit, cleanup ----
if bash "$INTAKE_CHECK" >/dev/null 2>&1; then
    rm -f "$PENDING_FILE" 2>/dev/null
    if [[ -x "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" "intake-interview" \
            "filled ${#blank_fields[@]} chain-of-custody field(s) in 00_intake.md" \
            "phases 2-6 may now proceed" >/dev/null 2>&1 || true
    fi
    echo ""
    echo "intake-interview: intake complete."
    exit 0
else
    echo "intake-interview: post-write check still failing — inspect $INTAKE manually" >&2
    exit 5
fi
