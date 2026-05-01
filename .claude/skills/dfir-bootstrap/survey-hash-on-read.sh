#!/usr/bin/env bash
# survey-hash-on-read.sh — record + verify sha256 of a file the surveyor is
# about to examine. Refuses (exit 2) if the live hash differs from the first
# recorded hash for the same path. Idempotent on (path, sha256) match.
#
# Usage: survey-hash-on-read.sh <DOMAIN> <FILE_PATH>
# Side effect: appends a row to ./analysis/<DOMAIN>/files-examined.tsv:
#   path<TAB>sha256<TAB>size_bytes<TAB>mtime_utc<TAB>examined_at_utc
#
# Behavior:
#   - First touch on a (path, sha) pair: record a row, cross-check the live
#     sha against analysis/manifest.md and analysis/exports-manifest.md, log
#     a soft "orphan" warning via audit.sh if the sha is in neither (layer-3
#     tool output the surveyor itself produced is the legitimate orphan
#     case — refusing would break normal survey flow).
#   - Subsequent touch with same sha: silent idempotent skip (no new row).
#   - Subsequent touch with different sha: log MISMATCH via audit.sh and
#     exit 2. The caller (the surveyor agent) MUST stop and surface the
#     mismatch to the orchestrator — do NOT silently re-hash.
#
# Path conventions:
#   - The path is recorded in the TSV verbatim as supplied by the caller.
#     Subsequent invocations must use the same path string to match the
#     existing row. Callers SHOULD canonicalize before invoking (e.g. drop
#     leading "./", collapse double slashes); this script does NOT
#     canonicalize implicitly so the audit trail stays operator-controlled.
#
# Portability note:
#   - mtime computation uses GNU `date -u -d "@<epoch>"` and GNU `stat -c%Y`.
#     SIFT (Ubuntu) is GNU coreutils — fine. BSD-based systems (macOS) need
#     `date -u -r <epoch>` and `stat -f%m`. This script targets SIFT.
#
# Exit codes:
#   0   ok (recorded a new row OR idempotent skip on matching sha)
#   2   refusal (file unreadable, hash mismatch with prior record, or
#       missing required arguments)

set -u

# ---- arguments ----
if [[ $# -lt 2 ]]; then
    echo "usage: survey-hash-on-read.sh <DOMAIN> <FILE_PATH>" >&2
    exit 2
fi
DOMAIN="${1:?domain required}"
FILE="${2:?file required}"

# ---- locate audit.sh next to us via BASH_SOURCE (matches the bootstrap
# convention used by audit-stop.sh, mitre-validate.sh, extraction-plan.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"

TSV="./analysis/${DOMAIN}/files-examined.tsv"
mkdir -p "./analysis/${DOMAIN}"
if [[ ! -f "$TSV" ]]; then
    printf "path\tsha256\tsize_bytes\tmtime_utc\texamined_at_utc\n" > "$TSV"
fi

if [[ ! -r "$FILE" ]]; then
    echo "[hash-on-read] not readable: $FILE" >&2
    exit 2
fi

live_sha=$(sha256sum "$FILE" | awk '{print $1}')
size=$(stat -c%s "$FILE")
mtime=$(date -u -d "@$(stat -c%Y "$FILE")" '+%Y-%m-%d %H:%M:%S UTC')
now=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

# Look up the prior recorded sha for this exact path string.
prev=$(awk -F'\t' -v p="$FILE" '$1==p {print $2; exit}' "$TSV" 2>/dev/null || true)
if [[ -n "$prev" ]]; then
    if [[ "$prev" != "$live_sha" ]]; then
        if [[ -x "$AUDIT_SH" ]]; then
            bash "$AUDIT_SH" "survey-hash-on-read MISMATCH" \
                "examined-file sha changed: $FILE was=$prev now=$live_sha" \
                "STOP — investigate tamper before continuing survey" \
                >/dev/null 2>&1 || true
        fi
        echo "[hash-on-read] HASH MISMATCH on $FILE (was=$prev now=$live_sha)" >&2
        exit 2
    fi
    # Same path, same sha — idempotent skip. No new TSV row.
    exit 0
fi

# First touch on this path — cross-check the live sha against the canonical
# ledgers. Layer-3 tool output (CSVs the surveyor itself produced) won't be
# in either manifest; that's a soft warning, not a refusal.
if ! grep -qF "$live_sha" ./analysis/manifest.md ./analysis/exports-manifest.md 2>/dev/null; then
    if [[ -x "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" "survey-hash-on-read orphan" \
            "$FILE sha=$live_sha not in manifest.md or exports-manifest.md" \
            "verify file is layer-3 (recomputable tool output)" \
            >/dev/null 2>&1 || true
    fi
fi

printf "%s\t%s\t%s\t%s\t%s\n" "$FILE" "$live_sha" "$size" "$mtime" "$now" >> "$TSV"
