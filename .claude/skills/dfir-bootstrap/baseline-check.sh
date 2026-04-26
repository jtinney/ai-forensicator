#!/usr/bin/env bash
# baseline-check.sh — per-domain baseline-artifact gap detector.
#
# Reads the matching domain SKILL.md, extracts the <!-- baseline-artifacts -->
# fenced block, and tests each declared artifact path under ./analysis/<DOMAIN>/.
#
# Output: a single JSON line on stdout describing the gap state. The
# orchestrator's resume protocol and the correlator's Phase 4 step both
# call this and emit `L-BASELINE-<DOMAIN>` leads when missing != [].
#
# Block format inside SKILL.md:
#   <!-- baseline-artifacts:start -->
#   required: analysis/network/capinfos.txt
#   required-tier1: analysis/network/zeek/conn.log
#   optional:  analysis/network/proto-hier.txt
#   <!-- baseline-artifacts:end -->
#
# `required` rows are always checked. `required-tier1` rows are checked only
# when the corresponding skill is GREEN in ./analysis/preflight.md (the
# tool was actually available on this SIFT instance).
#
# Exit codes:
#   0 — no gap (all required+tier1 artifacts present, or tier 2/3 with required present)
#   1 — gap (one or more required artifacts missing)
#   2 — preconditions wrong (no SKILL.md, no analysis dir, bad domain)
#
# Usage:
#   bash baseline-check.sh <DOMAIN>
#   DOMAIN: filesystem | timeline | windows-artifacts | memory | network | yara

set -u

DOMAIN="${1:-}"
if [[ -z "$DOMAIN" ]]; then
    echo "usage: baseline-check.sh <DOMAIN>" >&2
    echo "  DOMAIN: filesystem | timeline | windows-artifacts | memory | network | yara" >&2
    exit 2
fi

# Map DOMAIN to the skill-file path
case "$DOMAIN" in
    filesystem)        SKILL_FILE=".claude/skills/sleuthkit/SKILL.md"           ;;
    timeline)          SKILL_FILE=".claude/skills/plaso-timeline/SKILL.md"      ;;
    windows-artifacts) SKILL_FILE=".claude/skills/windows-artifacts/SKILL.md"   ;;
    memory)            SKILL_FILE=".claude/skills/memory-analysis/SKILL.md"     ;;
    network)           SKILL_FILE=".claude/skills/network-forensics/SKILL.md"   ;;
    yara)              SKILL_FILE=".claude/skills/yara-hunting/SKILL.md"        ;;
    *)
        printf '{"domain":"%s","error":"unknown domain"}\n' "$DOMAIN"
        exit 2
        ;;
esac

if [[ ! -f "$SKILL_FILE" ]]; then
    printf '{"domain":"%s","error":"skill file not found: %s"}\n' "$DOMAIN" "$SKILL_FILE"
    exit 2
fi

# ---- determine the skill's preflight tier ----
# Read ./analysis/preflight.md if present; map skill name to GREEN/YELLOW/RED.
TIER="UNKNOWN"
PREFLIGHT="./analysis/preflight.md"

# Map domain to the per-skill row label used in preflight.md
case "$DOMAIN" in
    filesystem)        SKILL_LABEL="sleuthkit"          ;;
    timeline)          SKILL_LABEL="plaso-timeline"     ;;
    windows-artifacts) SKILL_LABEL="windows-artifacts"  ;;
    memory)            SKILL_LABEL="memory-analysis"    ;;
    network)           SKILL_LABEL="network-forensics"  ;;
    yara)              SKILL_LABEL="yara-hunting"       ;;
esac

if [[ -f "$PREFLIGHT" ]]; then
    # Look for a row like: | network-forensics | GREEN | ... |
    row="$(grep -E "^\|[[:space:]]*${SKILL_LABEL}[[:space:]]*\|" "$PREFLIGHT" | head -1)"
    if [[ -n "$row" ]]; then
        if   echo "$row" | grep -q 'GREEN';  then TIER="GREEN"
        elif echo "$row" | grep -q 'YELLOW'; then TIER="YELLOW"
        elif echo "$row" | grep -q 'RED';    then TIER="RED"
        fi
    fi
fi

# ---- extract the baseline-artifacts block from the skill file ----
# awk extracts lines strictly between the start/end markers.
required_paths=()
tier1_paths=()
optional_paths=()

while IFS= read -r raw; do
    # Trim leading/trailing whitespace
    line="$(echo "$raw" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    case "$line" in
        required-tier1:*) tier1_paths+=("$(echo "${line#required-tier1:}" | sed -E 's/^[[:space:]]+//')") ;;
        required:*)        required_paths+=("$(echo "${line#required:}" | sed -E 's/^[[:space:]]+//')") ;;
        optional:*)        optional_paths+=("$(echo "${line#optional:}" | sed -E 's/^[[:space:]]+//')") ;;
        *)                 ;;  # ignore unrecognized lines (forward-compatible)
    esac
done < <(awk '/<!-- baseline-artifacts:start -->/{flag=1; next} /<!-- baseline-artifacts:end -->/{flag=0} flag' "$SKILL_FILE")

# If the block is absent, that itself is a contract gap — flag it
if [[ "${#required_paths[@]}" -eq 0 && "${#tier1_paths[@]}" -eq 0 && "${#optional_paths[@]}" -eq 0 ]]; then
    printf '{"domain":"%s","tier":"%s","missing":[],"warning":"no <!-- baseline-artifacts --> block in %s"}\n' \
        "$DOMAIN" "$TIER" "$SKILL_FILE"
    exit 0
fi

# ---- test required + (conditionally) tier1 paths ----
missing=()
for p in "${required_paths[@]}"; do
    [[ -z "$p" ]] && continue
    # Honor both `analysis/...` and `./analysis/...` forms
    test_path="$p"
    [[ "${test_path:0:2}" != "./" ]] && test_path="./${test_path}"
    if [[ ! -e "$test_path" ]]; then
        missing+=("$p")
    fi
done

# Only enforce tier1 when preflight reports GREEN
if [[ "$TIER" == "GREEN" ]]; then
    for p in "${tier1_paths[@]}"; do
        [[ -z "$p" ]] && continue
        test_path="$p"
        [[ "${test_path:0:2}" != "./" ]] && test_path="./${test_path}"
        if [[ ! -e "$test_path" ]]; then
            missing+=("$p")
        fi
    done
fi

# ---- emit JSON-line ----
# Build the missing[] JSON array
missing_json="["
first=1
for m in "${missing[@]}"; do
    if [[ "$first" -eq 1 ]]; then first=0; else missing_json+=","; fi
    # Escape any embedded quotes (paths shouldn't have them, but defensive)
    esc="${m//\"/\\\"}"
    missing_json+="\"${esc}\""
done
missing_json+="]"

printf '{"domain":"%s","tier":"%s","skill_file":"%s","required_count":%d,"tier1_count":%d,"missing":%s}\n' \
    "$DOMAIN" "$TIER" "$SKILL_FILE" "${#required_paths[@]}" "${#tier1_paths[@]}" "$missing_json"

if [[ "${#missing[@]}" -gt 0 ]]; then
    exit 1
fi
exit 0
