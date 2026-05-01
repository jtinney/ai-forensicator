#!/usr/bin/env bash
# extraction-cleanup.sh -- per-stage extracted-bytes remover for sequential
# extraction mode (issue #4). Invoked by the orchestrator between stage N's
# Phase 3 (investigators) and stage N+1's Phase 1 (extract).
#
# Removes ./analysis/_extracted/<basename>/ and only that directory. Keeps:
#   - ./analysis/<domain>/findings.md, survey-EV*.md, files-examined.tsv, etc.
#   - ./exports/**       (extracted artifacts per layer-4 of the folder model)
#   - ./reports/**
#   - ./analysis/manifest.md, ./analysis/leads.md, ./analysis/correlation.md
#   - ./analysis/forensic_audit.log
#
# Layer-2 framing: ./analysis/_extracted/<basename>/ is layer-2 evidence-grade
# staging. Cleanup removes the staging tree but leaves the manifest rows
# (chain of custody) and every layer-3 / layer-4 derivation intact. A future
# re-extraction (e.g. an L-EXTRACT-RE-NN lead) will re-stage the same bytes
# from the original archive in ./evidence/.
#
# Usage
#   bash .claude/skills/dfir-bootstrap/extraction-cleanup.sh <BASENAME>
#
# <BASENAME> matches case-init.sh's expansion-dir name -- the archive's
# filename minus its extension (e.g. ACQ-IR-host01-20250702 for
# ACQ-IR-host01-20250702.zip; foo for foo.tar.gz).
#
# Exit
#   0   cleanup ran (or directory was already absent -- idempotent skip)
#   1   refused (basename traversal, missing dir mid-run, or path escape)
#   2   misuse (no basename argument)
#
# Audit row format
#   "[disk] stage <N>: cleanup <archive> deleted=<N> files"
# is documented in ORCHESTRATE.md under "Sequential extraction protocol".
# This script writes a simpler audit row -- the stage number is opaque to
# the cleanup script, so the orchestrator wraps with its own audit row that
# names the stage. (Stage-aware audit row is left to the orchestrator.)

set -u

BASENAME="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"
EXTRACT_DIR="./analysis/_extracted"

if [[ -z "$BASENAME" ]]; then
    echo "usage: extraction-cleanup.sh <BASENAME>" >&2
    echo "  <BASENAME>: case-init.sh expansion subdir (archive minus its extension)" >&2
    exit 2
fi

# Refuse path traversal: BASENAME must be a single path component.
case "$BASENAME" in
    */* | *..* | "" | .)
        echo "extraction-cleanup: refused -- basename must be a single path component (got: $BASENAME)" >&2
        exit 1
        ;;
esac

TARGET="${EXTRACT_DIR}/${BASENAME}"

# Idempotency: if the dir is already gone, audit a no-op and exit 0.
if [[ ! -d "$TARGET" ]]; then
    if [[ -x "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" "extraction-cleanup" \
            "no-op: ${TARGET} already absent" \
            "advance to next sequential stage" >/dev/null 2>&1 || true
    fi
    echo "extraction-cleanup: ${TARGET} already absent -- nothing to do"
    exit 0
fi

# Path escape check: realpath the target and confirm it is still inside
# the extract dir. Defends against symlinks pointing out of the case.
real_extract="$(readlink -f "$EXTRACT_DIR" 2>/dev/null || echo "")"
real_target="$(readlink -f "$TARGET" 2>/dev/null || echo "")"
if [[ -z "$real_extract" || -z "$real_target" ]]; then
    echo "extraction-cleanup: refused -- could not resolve realpath for ${TARGET}" >&2
    exit 1
fi
if [[ "$real_target" != "$real_extract"/* ]]; then
    echo "extraction-cleanup: refused -- ${TARGET} resolves outside ${EXTRACT_DIR}" >&2
    exit 1
fi

# Count files (depth-unbounded, regular files only) before deletion. This
# is the "deleted=<N>" figure the audit line carries.
DELETED_COUNT="$(find "$TARGET" -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
[[ -z "$DELETED_COUNT" ]] && DELETED_COUNT=0

# Delete. -rf only inside the verified target.
rm -rf -- "$TARGET"

# Verify the deletion actually happened.
if [[ -d "$TARGET" ]]; then
    if [[ -x "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" "extraction-cleanup FAILED" \
            "could not remove ${TARGET}; rm -rf returned but dir still present" \
            "investigate filesystem permissions / open file handles" >/dev/null 2>&1 || true
    fi
    echo "extraction-cleanup: FAILED -- ${TARGET} still present after rm -rf" >&2
    exit 1
fi

# Audit the cleanup. The orchestrator may layer its own
# "[disk] stage <N>: cleanup <archive>" row on top of this one with the
# stage number it is tracking; this script's row is the unconditional
# disk-side record.
if [[ -x "$AUDIT_SH" ]]; then
    bash "$AUDIT_SH" "extraction-cleanup" \
        "removed ${TARGET}; deleted=${DELETED_COUNT} files" \
        "advance to next sequential stage (or close case if last)" >/dev/null 2>&1 || true
fi

echo "extraction-cleanup: removed ${TARGET}; deleted=${DELETED_COUNT} files"
exit 0
