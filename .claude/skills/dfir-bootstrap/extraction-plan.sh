#!/usr/bin/env bash
# extraction-plan.sh -- disk-space-aware extraction planner.
#
# Walks ./evidence/ depth-unbounded for archive bundles (zip / tar / tar.gz /
# tar.bz2 / 7z), estimates the decompressed total, and compares against free
# disk at ./working/. Writes ./analysis/extraction-plan.md with one
# of three plan modes -- bulk, sequential, or blocked -- and (when blocked)
# appends a BLOCKED row to ./analysis/leads.md.
#
# Layer-2 framing: archive bundles unpack into ./working/<base>/.
# That tree IS layer-2 evidence-grade staging tracked by manifest.md, NOT
# layer-4 derived artifacts. Per the project's five-layer model, bundle
# members are original evidence, just unpacked -- not exports. This planner
# therefore plans against working/, not exports/.
#
# Modes
#   bulk        sum + headroom <= free.                      Phase 1 extracts everything.
#   sequential  every individual archive fits, but sum does not. Phase 1 extracts the
#               smallest archive first; the orchestrator drives extract->survey->
#               investigate->cleanup->next-stage between subsequent archives.
#   blocked     >=1 archive's estimated size + headroom exceeds free space.
#               L-EXTRACT-DISK-01 BLOCKED row appended to leads.md.
#
# Inputs (env)
#   HEADROOM_PCT  default 20. Reserve N% of the estimated total as headroom on
#                 top of the total before declaring a fit.
#
# Output
#   ./analysis/extraction-plan.md  -- the plan (rewritten on every run)
#   ./analysis/leads.md            -- appended L-EXTRACT-DISK-NN row on blocked
#   audit row                      -- "extraction-plan computed: ..."
#
# Exit
#   0   plan mode = bulk OR sequential
#   1   plan mode = blocked (>=1 archive doesn't fit alone)
#   2   misuse / preconditions wrong (no evidence dir, malformed env)
#
# Idempotency: re-running on the same evidence regenerates the same plan
# file. Archive ordering is deterministic (lexicographic by relative path
# from ./evidence/). The sequential schedule is a stable smallest-first sort
# by estimated decompressed size with the relative path as tiebreak.

set -u

EVIDENCE_DIR="./evidence"
EXTRACT_DIR="./working"
PLAN_FILE="./analysis/extraction-plan.md"
LEADS="./analysis/leads.md"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"
HEADROOM_PCT="${HEADROOM_PCT:-20}"

# ---- preconditions ----
if [[ ! -d "$EVIDENCE_DIR" ]]; then
    echo "extraction-plan: $EVIDENCE_DIR not found (run from case workspace)" >&2
    exit 2
fi
if ! [[ "$HEADROOM_PCT" =~ ^[0-9]+$ ]]; then
    echo "extraction-plan: HEADROOM_PCT must be a non-negative integer (got: $HEADROOM_PCT)" >&2
    exit 2
fi
mkdir -p "./analysis" "$EXTRACT_DIR"

# ---- helpers ----
hsize() { local b="$1"; numfmt --to=iec --suffix=B "$b" 2>/dev/null || echo "${b}B"; }

# Classify an archive by `file -b` output (same patterns as case-init.sh).
# Some `file` versions on Linux do NOT include "tar archive" inline for
# `.tar.gz` / `.tar.bz2`; we fall back to a `tar -tzf` / `tar -tjf` listing
# probe to confirm the gzip/bzip2 stream really wraps a tar. Cheap (one
# header read) and avoids miscategorising data-only gzip blobs as bundles.
classify_kind() {
    local f="$1" ftype_raw kind=""
    ftype_raw="$(file -b "$f" 2>/dev/null || echo unknown)"
    case "$ftype_raw" in
        *"Zip archive"*)      kind="zip" ;;
        *"7-zip archive"*)    kind="7z" ;;
        *"gzip compressed"*)
            if file -b "$f" 2>/dev/null | grep -q 'tar archive' \
               || tar -tzf "$f" >/dev/null 2>&1; then
                kind="gzip-tar"
            fi ;;
        *"bzip2 compressed"*)
            if file -b "$f" 2>/dev/null | grep -q 'tar archive' \
               || tar -tjf "$f" >/dev/null 2>&1; then
                kind="bzip-tar"
            fi ;;
        *"POSIX tar"*|*"tar archive"*) kind="tar" ;;
    esac
    echo "$kind"
}

# Estimate decompressed size of an archive in bytes. Best-effort; on failure
# returns 0, which the caller treats as "unknown" (does not block, but also
# does not contribute to the total -- conservative fallback).
#
# Reuses the same patterns case-init.sh uses (unzip -l, tar -tvf, 7z l) so
# the planner's view and the actual extraction agree on which archive is
# which size. Duplicated here rather than sourced because case-init.sh is
# under active churn (issue #12) and we don't want to couple the two scripts'
# control flow. If a clean shared lib emerges later, both can refactor onto
# it; for now, the duplication is cheap and isolated.
estimate_expanded_size() {
    local arch="$1" kind="$2"
    case "$kind" in
        zip)
            unzip -l "$arch" 2>/dev/null | awk 'END{print $1+0}'
            ;;
        gzip-tar)
            tar -tzvf "$arch" 2>/dev/null | awk '{s+=$3} END{print s+0}'
            ;;
        bzip-tar)
            tar -tjvf "$arch" 2>/dev/null | awk '{s+=$3} END{print s+0}'
            ;;
        tar)
            tar -tvf "$arch" 2>/dev/null | awk '{s+=$3} END{print s+0}'
            ;;
        7z)
            7z l "$arch" 2>/dev/null | awk '/^[0-9]/ {s+=$4} END{print s+0}'
            ;;
        *)
            echo 0
            ;;
    esac
}

# ---- 1. enumerate archives, deterministic order ----
# Walk depth-unbounded (matching the case-init.sh fix in issue #12) and
# capture only regular files. Sort by relative path so re-runs are stable.
declare -a ARCHIVES_RELPATH=()
declare -a ARCHIVES_KIND=()
declare -a ARCHIVES_EST=()

# Build a sorted, NUL-safe list of regular files under evidence/ then walk it.
mapfile -d '' all_files < <(find "$EVIDENCE_DIR" -mindepth 1 -type f -print0 2>/dev/null \
                             | LC_ALL=C sort -z)

for f in "${all_files[@]}"; do
    [[ -f "$f" ]] || continue
    kind="$(classify_kind "$f")"
    [[ -z "$kind" ]] && continue
    rel="${f#./}"
    est="$(estimate_expanded_size "$f" "$kind")"
    [[ -z "$est" ]] && est=0
    ARCHIVES_RELPATH+=("$rel")
    ARCHIVES_KIND+=("$kind")
    ARCHIVES_EST+=("$est")
done

ARCH_COUNT="${#ARCHIVES_RELPATH[@]}"

# ---- 2. compute totals + free disk ----
EST_TOTAL=0
if [[ "$ARCH_COUNT" -gt 0 ]]; then
    for e in "${ARCHIVES_EST[@]}"; do
        [[ -z "$e" ]] && continue
        EST_TOTAL=$(( EST_TOTAL + e ))
    done
fi

AVAIL_KB="$(df --output=avail "$EXTRACT_DIR" 2>/dev/null | tail -1 | tr -d '[:space:]')"
if [[ -z "$AVAIL_KB" || ! "$AVAIL_KB" =~ ^[0-9]+$ ]]; then
    AVAIL_KB=0
fi
FREE_BYTES=$(( AVAIL_KB * 1024 ))

HEADROOM_BYTES=$(( EST_TOTAL * HEADROOM_PCT / 100 ))
NEED_BYTES=$(( EST_TOTAL + HEADROOM_BYTES ))

# Per-archive fit check.
ARCH_OVERSIZED=0
LARGEST_REL=""
LARGEST_EST=0
if [[ "$ARCH_COUNT" -gt 0 ]]; then
    for ((i=0; i<ARCH_COUNT; i++)); do
        e="${ARCHIVES_EST[$i]}"
        if [[ "$e" -gt "$LARGEST_EST" ]]; then
            LARGEST_EST="$e"
            LARGEST_REL="${ARCHIVES_RELPATH[$i]}"
        fi
        arch_need=$(( e + (e * HEADROOM_PCT / 100) ))
        if [[ "$e" -gt 0 && "$arch_need" -gt "$FREE_BYTES" ]]; then
            ARCH_OVERSIZED=1
        fi
    done
fi

# ---- 3. choose mode ----
MODE=""
if [[ "$ARCH_COUNT" -eq 0 ]]; then
    MODE="bulk"
elif [[ "$ARCH_OVERSIZED" -eq 1 ]]; then
    MODE="blocked"
elif [[ "$NEED_BYTES" -le "$FREE_BYTES" ]]; then
    MODE="bulk"
else
    MODE="sequential"
fi

# ---- 4. write the plan file ----
declare -a SEQ_ORDER=()
if [[ "$MODE" == "sequential" ]]; then
    seq_packed=""
    for ((i=0; i<ARCH_COUNT; i++)); do
        seq_packed+="$(printf '%020d\t%s\t%s' "${ARCHIVES_EST[$i]}" "${ARCHIVES_RELPATH[$i]}" "${ARCHIVES_KIND[$i]}")"$'\n'
    done
    while IFS=$'\t' read -r est rel kind; do
        [[ -z "$rel" ]] && continue
        # Strip the zero-padding from the est key for display
        clean_est="${est##+(0)}"
        [[ -z "$clean_est" ]] && clean_est=0
        SEQ_ORDER+=("${rel}|${kind}|${clean_est}")
    done < <(printf '%s' "$seq_packed" | LC_ALL=C sort -k1,1n -k2,2)
fi

UTC_NOW="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"

{
    cat <<EOF
# Extraction Plan

| Field | Value |
|---|---|
| Generated | ${UTC_NOW} |
| Mode | ${MODE} |
| Archive count | ${ARCH_COUNT} |
| Estimated total decompressed | $(hsize "$EST_TOTAL") (${EST_TOTAL} bytes) |
| Headroom (${HEADROOM_PCT}%) | $(hsize "$HEADROOM_BYTES") (${HEADROOM_BYTES} bytes) |
| Required (total + headroom) | $(hsize "$NEED_BYTES") (${NEED_BYTES} bytes) |
| Free at \`${EXTRACT_DIR}\` | $(hsize "$FREE_BYTES") (${FREE_BYTES} bytes) |

> **Layer-2 staging.** Bundle expansion lands at \`./working/<basename>/\`.
> Per the project's five-layer model, bundle members are layer-2 evidence-grade
> staging (tracked by \`manifest.md\`), NOT layer-4 derived artifacts. The planner
> sizes against the analysis partition for that reason.

EOF

    case "$MODE" in
        bulk)
            cat <<EOF

## Plan: bulk

Free space accommodates the full decompressed corpus plus a ${HEADROOM_PCT}% headroom.
Triage (Phase 1) may instruct \`case-init.sh\` to bulk-extract every archive in one pass
(\`BULK_EXTRACT=1\`).

EOF
            if [[ "$ARCH_COUNT" -gt 0 ]]; then
                cat <<'EOF'

| stage | archive | kind | estimated_decompressed |
|---|---|---|---|
EOF
                for ((i=0; i<ARCH_COUNT; i++)); do
                    printf '| 1 | %s | %s | %s |\n' \
                        "${ARCHIVES_RELPATH[$i]}" \
                        "${ARCHIVES_KIND[$i]}" \
                        "$(hsize "${ARCHIVES_EST[$i]}")"
                done
            else
                # shellcheck disable=SC2016  # backticks here are markdown, not command substitution
                printf '\n_No archive bundles found in \`%s\`._\n' "$EVIDENCE_DIR"
            fi
            ;;

        sequential)
            cat <<EOF

## Plan: sequential

The combined decompressed estimate (with ${HEADROOM_PCT}% headroom) exceeds free space, but
every individual archive fits alone. Triage (Phase 1) extracts only the first stage. The
orchestrator runs Phase 2 (surveyor) and Phase 3 (investigators) on each stage, then
\`extraction-cleanup.sh\` removes that stage's extracted bytes -- analysis/, exports/, and
manifest rows are preserved -- before advancing to the next stage. Schedule is sorted
**smallest first** so the largest archive runs last (peak disk usage is reached only
once, at the largest archive's stage).

\`case-init.sh\` MUST NOT bulk-extract in this mode. Triage invokes it with
\`BULK_EXTRACT=0\` (or unset) and stages archive 1 only; subsequent stages are driven by
the orchestrator's sequential-extraction protocol (see ORCHESTRATE.md).

EOF
            cat <<'EOF'

| stage | archive | kind | estimated_decompressed |
|---|---|---|---|
EOF
            stage=1
            for entry in "${SEQ_ORDER[@]}"; do
                rel="${entry%%|*}"
                rest="${entry#*|}"
                kind="${rest%%|*}"
                est="${rest#*|}"
                printf '| %d | %s | %s | %s |\n' "$stage" "$rel" "$kind" "$(hsize "$est")"
                stage=$((stage + 1))
            done
            ;;

        blocked)
            DEFICIT=0
            ARCH_NEED_LARGEST=$(( LARGEST_EST + (LARGEST_EST * HEADROOM_PCT / 100) ))
            if [[ "$ARCH_NEED_LARGEST" -gt "$FREE_BYTES" ]]; then
                DEFICIT=$(( ARCH_NEED_LARGEST - FREE_BYTES ))
            fi
            cat <<EOF

## Plan: blocked

At least one archive's estimated decompressed size + ${HEADROOM_PCT}% headroom exceeds
free space at \`${EXTRACT_DIR}\`. Triage MUST NOT extract any archive. The orchestrator
should surface lead \`L-EXTRACT-DISK-01\` to the operator.

| Field | Value |
|---|---|
| Largest archive | \`${LARGEST_REL}\` |
| Largest estimated decompressed | $(hsize "$LARGEST_EST") (${LARGEST_EST} bytes) |
| Required (largest + ${HEADROOM_PCT}% headroom) | $(hsize "$ARCH_NEED_LARGEST") (${ARCH_NEED_LARGEST} bytes) |
| Free at \`${EXTRACT_DIR}\` | $(hsize "$FREE_BYTES") (${FREE_BYTES} bytes) |
| Required-free-space delta | $(hsize "$DEFICIT") (${DEFICIT} bytes) |

Resolution paths:
1. Free enough disk to satisfy the delta; re-run \`extraction-plan.sh\`.
2. Mount a larger volume at \`./working/\` and re-run.
3. Decline the case if neither (1) nor (2) is feasible.

EOF
            cat <<'EOF'

| stage | archive | kind | estimated_decompressed |
|---|---|---|---|
EOF
            for ((i=0; i<ARCH_COUNT; i++)); do
                printf '| - | %s | %s | %s |\n' \
                    "${ARCHIVES_RELPATH[$i]}" \
                    "${ARCHIVES_KIND[$i]}" \
                    "$(hsize "${ARCHIVES_EST[$i]}")"
            done
            ;;
    esac
} > "$PLAN_FILE"

# ---- 5. on blocked, append the BLOCKED lead row to leads.md ----
if [[ "$MODE" == "blocked" ]]; then
    DEFICIT=0
    ARCH_NEED_LARGEST=$(( LARGEST_EST + (LARGEST_EST * HEADROOM_PCT / 100) ))
    if [[ "$ARCH_NEED_LARGEST" -gt "$FREE_BYTES" ]]; then
        DEFICIT=$(( ARCH_NEED_LARGEST - FREE_BYTES ))
    fi

    if [[ ! -f "$LEADS" ]]; then
        cat > "$LEADS" <<'EOF'
| lead_id | evidence_id | domain | hypothesis | pointer | priority | status | notes |
|---------|-------------|--------|------------|---------|----------|--------|-------|
EOF
    fi

    last_n="$(grep -oE '\| L-EXTRACT-DISK-[0-9]+' "$LEADS" 2>/dev/null \
              | grep -oE '[0-9]+$' | sort -n | tail -1)"
    if [[ -z "$last_n" ]]; then
        next_n=1
    else
        next_n=$((10#$last_n + 1))
    fi
    LEAD_ID="$(printf 'L-EXTRACT-DISK-%02d' "$next_n")"

    HYPOTHESIS="Disk-pressure block: ${LARGEST_REL} requires $(hsize "$ARCH_NEED_LARGEST") (largest + ${HEADROOM_PCT}% headroom); free $(hsize "$FREE_BYTES")"
    NOTES="required-free-space-delta=$(hsize "$DEFICIT") (${DEFICIT} bytes); free disk or remount before retrying"
    if ! grep -qF "$HYPOTHESIS" "$LEADS" 2>/dev/null; then
        printf '| %s | - | bootstrap | %s | analysis/extraction-plan.md | high | blocked | %s |\n' \
            "$LEAD_ID" "$HYPOTHESIS" "$NOTES" >> "$LEADS"
    fi
fi

# ---- 6. audit + return ----
if [[ -x "$AUDIT_SH" ]]; then
    bash "$AUDIT_SH" "extraction-plan computed" \
        "mode=${MODE} archives=${ARCH_COUNT} est_total=${EST_TOTAL} free=${FREE_BYTES}" \
        "case-init.sh BULK_EXTRACT gating per plan" >/dev/null 2>&1 || true
fi

echo "extraction-plan: mode=${MODE} archives=${ARCH_COUNT} est_total=${EST_TOTAL} free=${FREE_BYTES} plan=${PLAN_FILE}"

case "$MODE" in
    bulk|sequential) exit 0 ;;
    blocked)         exit 1 ;;
    *)               exit 2 ;;
esac
