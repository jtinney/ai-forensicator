#!/usr/bin/env bash
# audit-exports.sh — sha256 every file under ./exports/ and track it in
# ./analysis/exports-manifest.md.
#
# Why: ./exports/ holds *extracted* artifacts (files carved from disk,
# files reassembled from network captures, per-flow data, per-stream pcaps,
# bulk_extractor output, malware samples carved from memory). These are
# new analytic units — investigators chain conclusions on top (YARA,
# disassembly, attribution). Each one needs its own integrity record so a
# future examiner can verify they're looking at the same bytes.
#
# Behavior:
#   - Walks ./exports/ recursively (depth-unbounded).
#   - For each file, computes sha256.
#   - Looks up the path in ./analysis/exports-manifest.md.
#       - Not present → append a row with first_seen UTC + size + sha.
#       - Present, sha matches → skip (idempotent fast path).
#       - Present, sha DIFFERS → append a MUTATED row (extracted artifacts
#         should be immutable; mutation is a chain-of-custody concern).
#   - All audit-trail entries go through audit.sh (DISCIPLINE rule A).
#
# Wired in .claude/settings.json under hooks.PostToolUse, matcher
# "Bash|Write|Edit", alongside audit-verify.sh.
#
# Idempotent fast path: skips entirely if ./exports/ has no files newer
# than the sidecar mtime, so the hook stays cheap on cases that don't
# touch ./exports/.

set -u

EXPORTS="./exports"
ANALYSIS="./analysis"
MANIFEST="${ANALYSIS}/exports-manifest.md"
SIDECAR="${ANALYSIS}/.exports.lastscan"
# audit.sh lives next to this script — locate via BASH_SOURCE so the hook
# works regardless of the agent's cwd.
AUDIT_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/audit.sh"

# Quiet exit if not in a case dir
[[ -d "$EXPORTS" && -d "$ANALYSIS" ]] || exit 0

# ---- fast path: nothing new in ./exports/ since last scan ----
if [[ -f "$SIDECAR" ]]; then
    # Any file in ./exports/ newer than the sidecar?
    new_hit="$(find "$EXPORTS" -type f -newer "$SIDECAR" -print -quit 2>/dev/null || true)"
    if [[ -z "$new_hit" ]]; then
        # Touch the sidecar so its mtime advances even when nothing changed
        # (keeps the next scan's anchor close to the present).
        touch "$SIDECAR" 2>/dev/null || true
        exit 0
    fi
fi

# ---- ensure manifest exists ----
if [[ ! -f "$MANIFEST" ]]; then
    cat > "$MANIFEST" <<'EOF'
# Exports Manifest — sha256 of every extracted artifact under ./exports/

> Original-evidence intake hashes live in `./analysis/manifest.md`.
> This file tracks **derivative artifacts** that became analytic units —
> things carved/reassembled/dumped from the original evidence. Every row
> is appended by `audit-exports.sh` (PostToolUse hook). MUTATED rows are
> chain-of-custody concerns — extracted artifacts should be immutable.

| path | size | sha256 | first_seen_utc | event | notes |
|---|---|---|---|---|---|
EOF
fi

UTC_NOW="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"

# Collect existing manifest rows (path -> sha256) — gawk is on every SIFT
declare -A KNOWN_SHA=()
while IFS= read -r row; do
    # row format: "| <path> | <size> | <sha> | <utc> | <event> | <notes> |"
    # Strip leading "| " and split by " | ". We only need fields 1 (path) and 3 (sha).
    p="$(echo "$row" | awk -F' \\| ' '{print $1}' | sed -E 's/^\| //')"
    s="$(echo "$row" | awk -F' \\| ' '{print $3}')"
    e="$(echo "$row" | awk -F' \\| ' '{print $5}')"
    [[ -z "$p" || -z "$s" ]] && continue
    # If we have multiple rows for the same path (e.g. a MUTATED row), the LAST
    # row wins — that represents the current claimed sha256.
    KNOWN_SHA["$p"]="$s|$e"
done < <(grep -E '^\| (\./|/)' "$MANIFEST" 2>/dev/null || true)

new_count=0
mutated_count=0
unchanged_count=0

# Walk every file under ./exports/
while IFS= read -r -d '' f; do
    rel="$f"   # already starts with ./exports/
    size=$(stat -c%s "$f" 2>/dev/null || echo 0)
    sha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    [[ -z "$sha" ]] && continue

    if [[ -n "${KNOWN_SHA[$rel]:-}" ]]; then
        prev="${KNOWN_SHA[$rel]%%|*}"
        prev_event="${KNOWN_SHA[$rel]##*|}"
        if [[ "$prev" == "$sha" ]]; then
            unchanged_count=$((unchanged_count + 1))
            continue
        fi
        # Mutation detected — append MUTATED row
        printf "| %s | %s | %s | %s | MUTATED | previous sha %s (event=%s) — extracted artifact mutated; investigate |\n" \
            "$rel" "$size" "$sha" "$UTC_NOW" "$prev" "$prev_event" \
            >> "$MANIFEST"
        mutated_count=$((mutated_count + 1))
    else
        # First sighting
        printf "| %s | %s | %s | %s | first-seen |  |\n" \
            "$rel" "$size" "$sha" "$UTC_NOW" \
            >> "$MANIFEST"
        new_count=$((new_count + 1))
    fi
done < <(find "$EXPORTS" -type f -print0 2>/dev/null)

# ---- emit one audit entry summarizing the sweep (only if anything changed) ----
if [[ "$new_count" -gt 0 || "$mutated_count" -gt 0 ]]; then
    if [[ -f "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" \
            "audit-exports.sh" \
            "exports-manifest update: ${new_count} new, ${mutated_count} MUTATED, ${unchanged_count} unchanged" \
            "manifest at ${MANIFEST}; mutated rows are chain-of-custody concerns" \
            >/dev/null 2>&1 || true
    fi
fi

# Advance sidecar mtime to NOW
touch "$SIDECAR" 2>/dev/null || true

exit 0
