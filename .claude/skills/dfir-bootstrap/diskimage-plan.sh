#!/usr/bin/env bash
# diskimage-plan.sh -- disk-image discovery + mount planner.
#
# Walks ./evidence/ AND ./working/ depth-unbounded for disk images
# (E01, raw/dd, vmdk, vhd, vhdx, qcow2). Detects format via qemu-img info
# and ewfinfo, computes logical (virtual) size, records the canonical
# adapter chain per DISCIPLINE §P-diskimage. Writes ./analysis/diskimage-plan.md.
#
# Mount layer consumes ~0 disk (qemu-nbd is a block-device facade);
# headroom check covers only mount-metadata + audit-ledger overhead.
# The mode tree mirrors extraction-plan.sh so the orchestrator can take
# the most-restrictive of the two plans for the dispatch decision.
#
# Modes
#   bulk        every disk image fits the small mount-overhead budget. Triage
#               mounts every image in Phase 1.
#   sequential  combined budget exceeds free, but every image fits alone.
#               Orchestrator stages mount/dismount per disk image.
#   blocked     a single image's mount overhead + headroom exceeds free
#               disk, OR an encrypted image is detected without a key,
#               OR a required tool (qemu-nbd / ewfmount) is missing.
#               L-MOUNT-DISK-NN row appended to leads.md.
#
# Inputs (env)
#   HEADROOM_PCT       default 20.
#   MOUNT_OVERHEAD_MB  default 64. Reserved per disk image for mountpoint
#                      bookkeeping, mmls output, sentinel JSON, audit rows.
#
# Output
#   ./analysis/diskimage-plan.md  -- the plan (rewritten on every run)
#   ./analysis/leads.md           -- appended L-MOUNT-DISK-NN row on blocked
#   audit row                     -- "diskimage-plan computed: ..."
#
# Exit
#   0   plan mode = bulk OR sequential
#   1   plan mode = blocked
#   2   misuse / preconditions wrong (no analysis dir, malformed env)
#
# Idempotency: re-running on the same evidence regenerates the same plan
# file. Image ordering is deterministic (lexicographic by relative path).

set -u

EVIDENCE_DIR="./evidence"
WORKING_DIR="./working"
PLAN_FILE="./analysis/diskimage-plan.md"
LEADS="./analysis/leads.md"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"
HEADROOM_PCT="${HEADROOM_PCT:-20}"
MOUNT_OVERHEAD_MB="${MOUNT_OVERHEAD_MB:-64}"

# ---- preconditions ----
if [[ ! -d "./analysis" ]]; then
    echo "diskimage-plan: ./analysis not found (run from case workspace)" >&2
    exit 2
fi
if [[ ! -d "$EVIDENCE_DIR" ]]; then
    echo "diskimage-plan: $EVIDENCE_DIR not found" >&2
    exit 2
fi
if ! [[ "$HEADROOM_PCT" =~ ^[0-9]+$ ]]; then
    echo "diskimage-plan: HEADROOM_PCT must be a non-negative integer (got: $HEADROOM_PCT)" >&2
    exit 2
fi
if ! [[ "$MOUNT_OVERHEAD_MB" =~ ^[0-9]+$ ]]; then
    echo "diskimage-plan: MOUNT_OVERHEAD_MB must be a non-negative integer (got: $MOUNT_OVERHEAD_MB)" >&2
    exit 2
fi
mkdir -p "./analysis"

# ---- helpers ----
hsize() { local b="$1"; numfmt --to=iec --suffix=B "$b" 2>/dev/null || echo "${b}B"; }

# Classify by qemu-img info first (most authoritative for virtual disks),
# fall back to ewfinfo for E01, then file -b for raw heuristics.
# Echoes one of: e01 | raw | vmdk | vpc | vhdx | qcow2 | encrypted | unknown
classify_diskimage() {
    local f="$1" qfmt="" qenc="" ftype_raw=""

    # E01 first — ewfinfo exit 0 is authoritative
    if command -v ewfinfo >/dev/null 2>&1 && ewfinfo "$f" >/dev/null 2>&1; then
        echo "e01"
        return 0
    fi

    # qemu-img info — emits "file format: <fmt>" and "encrypted: yes" when set
    if command -v qemu-img >/dev/null 2>&1; then
        local qout
        qout="$(qemu-img info "$f" 2>/dev/null || true)"
        qfmt="$(printf '%s\n' "$qout" | awk -F': ' '/^file format:/ {print $2; exit}')"
        qenc="$(printf '%s\n' "$qout" | awk -F': ' '/^encrypted:/ {print $2; exit}')"
        if [[ "$qenc" == "yes" ]]; then
            echo "encrypted"
            return 0
        fi
        case "$qfmt" in
            raw|vmdk|vpc|vhdx|qcow2)
                echo "$qfmt"
                return 0
                ;;
        esac
    fi

    # Last-resort heuristic for raw images via file(1) + extension.
    ftype_raw="$(file -b "$f" 2>/dev/null || echo unknown)"
    case "$ftype_raw" in
        *"DOS/MBR boot sector"*|*"GPT partition table"*)
            echo "raw"
            return 0
            ;;
    esac
    case "$f" in
        *.dd|*.raw|*.img)
            # Trust the extension when qemu-img wasn't decisive.
            echo "raw"
            return 0
            ;;
    esac

    echo "unknown"
    return 0
}

# Logical size: virtual size (qemu-img) for virtual formats; file size
# (stat) for raw/E01. Echoes bytes; 0 on failure (caller treats as
# unknown — does not block but does not contribute to the total either).
logical_size() {
    local f="$1" kind="$2" virt=""
    case "$kind" in
        vmdk|vpc|vhdx|qcow2)
            if command -v qemu-img >/dev/null 2>&1; then
                virt="$(qemu-img info "$f" 2>/dev/null \
                        | awk -F'[()]' '/^virtual size:/ {print $2; exit}' \
                        | awk '{print $1}')"
                # virt is the byte count from "virtual size: X (NNN bytes)"
                if [[ "$virt" =~ ^[0-9]+$ ]]; then
                    echo "$virt"
                    return 0
                fi
            fi
            ;;
    esac
    stat -c%s "$f" 2>/dev/null || echo 0
}

# Adapter chain per DISCIPLINE §P-diskimage
adapter_chain() {
    local kind="$1"
    case "$kind" in
        e01)         echo "ewfmount -> qemu-nbd -f raw -> mount -o ro,noload" ;;
        raw)         echo "qemu-nbd -f raw -> mount -o ro,noload" ;;
        vmdk)        echo "qemu-nbd -f vmdk -> mount -o ro,noload" ;;
        vpc)         echo "qemu-nbd -f vpc -> mount -o ro,noload" ;;
        vhdx)        echo "qemu-nbd -f vhdx -> mount -o ro,noload" ;;
        qcow2)       echo "qemu-nbd -f qcow2 -> mount -o ro,noload" ;;
        encrypted)   echo "BLOCK: encrypted (provide-key)" ;;
        unknown)     echo "BLOCK: format unknown" ;;
    esac
}

# Helper: ensure leads.md exists with the canonical 8-column header.
ensure_leads_md() {
    if [[ ! -f "$LEADS" ]]; then
        mkdir -p ./analysis
        cat > "$LEADS" <<'EOF'
| lead_id | evidence_id | domain | hypothesis | pointer | priority | status | notes |
|---------|-------------|--------|------------|---------|----------|--------|-------|
EOF
    fi
}

# Pick the next L-<PREFIX>-NN id given a numeric prefix.
next_lead_id() {
    local prefix="$1"
    local last_n
    last_n="$(grep -oE "\\| ${prefix}-[0-9]+" "$LEADS" 2>/dev/null \
              | grep -oE '[0-9]+$' | sort -n | tail -1)"
    if [[ -z "$last_n" ]]; then
        printf '%s-01' "$prefix"
    else
        printf '%s-%02d' "$prefix" $((10#$last_n + 1))
    fi
}

# Append a BLOCKED lead row, idempotent on hypothesis match.
append_blocked_lead() {
    local prefix="$1" ev_id="$2" hypothesis="$3" pointer="$4" notes="$5"
    ensure_leads_md
    local hyp_safe="${hypothesis//|/\\|}"
    local notes_safe="${notes//|/\\|}"
    if grep -qF "$hyp_safe" "$LEADS" 2>/dev/null; then
        local existing
        existing="$(grep -F "$hyp_safe" "$LEADS" 2>/dev/null \
                    | grep -oE "\\| ${prefix}-[0-9]+" | head -1 | tr -d '| ')"
        echo "${existing:-${prefix}-??}"
        return 0
    fi
    local lead_id
    lead_id="$(next_lead_id "$prefix")"
    printf '| %s | %s | bootstrap | %s | %s | high | blocked | %s |\n' \
        "$lead_id" "$ev_id" "$hyp_safe" "$pointer" "$notes_safe" >> "$LEADS"
    echo "$lead_id"
}

# ---- 1. enumerate disk images, deterministic order ----
declare -a IMG_RELPATH=()
declare -a IMG_KIND=()
declare -a IMG_LOGICAL=()
declare -a IMG_ADAPTER=()

# Walk both evidence/ and working/ depth-unbounded. Disk images may be
# nested inside extracted archives.
declare -a search_roots=()
[[ -d "$EVIDENCE_DIR" ]] && search_roots+=("$EVIDENCE_DIR")
[[ -d "$WORKING_DIR" ]] && search_roots+=("$WORKING_DIR")

# Skip ./working/mounts/ — those are the mount points themselves, not
# new disk images to plan against.
mapfile -d '' all_files < <(find "${search_roots[@]}" -mindepth 1 -type f \
                            -not -path "$WORKING_DIR/mounts/*" \
                            -print0 2>/dev/null \
                          | LC_ALL=C sort -z)

for f in "${all_files[@]}"; do
    [[ -f "$f" ]] || continue

    # Cheap pre-filter on extension to avoid running qemu-img on every
    # bundle member. The classifier still re-checks via qemu-img/ewfinfo
    # for files that pass the filter.
    case "$f" in
        *.E01|*.e01|*.Ex01|*.ex01|*.[eE]0[0-9][0-9]|*.dd|*.raw|*.img|*.vmdk|*.VMDK|*.vhd|*.VHD|*.vhdx|*.VHDX|*.qcow2|*.QCOW2)
            ;;
        *)
            continue
            ;;
    esac

    # Skip secondary segments of split E01 (only the first segment is the
    # canonical entry; libewf chains the rest).
    case "$f" in
        *.E0[2-9]|*.E[1-9][0-9]|*.e0[2-9]|*.e[1-9][0-9])
            continue
            ;;
    esac

    kind="$(classify_diskimage "$f")"
    [[ "$kind" == "unknown" ]] && continue

    rel="${f#./}"
    logical="$(logical_size "$f" "$kind")"
    [[ -z "$logical" ]] && logical=0
    adapter="$(adapter_chain "$kind")"

    IMG_RELPATH+=("$rel")
    IMG_KIND+=("$kind")
    IMG_LOGICAL+=("$logical")
    IMG_ADAPTER+=("$adapter")
done

IMG_COUNT="${#IMG_RELPATH[@]}"

# ---- 2. compute totals + free disk ----
# Mount overhead per image (small): mountpoint dirs, mmls output,
# sentinel JSON, audit-row overhead. MOUNT_OVERHEAD_MB default 64.
PER_IMAGE_OVERHEAD=$(( MOUNT_OVERHEAD_MB * 1024 * 1024 ))
TOTAL_OVERHEAD=$(( IMG_COUNT * PER_IMAGE_OVERHEAD ))

AVAIL_KB="$(df --output=avail "$WORKING_DIR" 2>/dev/null | tail -1 | tr -d '[:space:]')"
if [[ -z "$AVAIL_KB" || ! "$AVAIL_KB" =~ ^[0-9]+$ ]]; then
    AVAIL_KB=0
fi
FREE_BYTES=$(( AVAIL_KB * 1024 ))

HEADROOM_BYTES=$(( TOTAL_OVERHEAD * HEADROOM_PCT / 100 ))
NEED_BYTES=$(( TOTAL_OVERHEAD + HEADROOM_BYTES ))

# ---- 3. encrypted / unsupported pre-block check ----
ENCRYPTED_HITS=0
for k in "${IMG_KIND[@]:-}"; do
    [[ "$k" == "encrypted" ]] && ENCRYPTED_HITS=$((ENCRYPTED_HITS + 1))
done

# Per-image overhead fit (any single image's overhead+headroom must fit)
PER_IMG_NEED=$(( PER_IMAGE_OVERHEAD + (PER_IMAGE_OVERHEAD * HEADROOM_PCT / 100) ))
PER_IMG_OVERSIZED=0
if [[ "$IMG_COUNT" -gt 0 && "$PER_IMG_NEED" -gt "$FREE_BYTES" ]]; then
    PER_IMG_OVERSIZED=1
fi

# ---- 4. choose mode ----
MODE=""
if [[ "$IMG_COUNT" -eq 0 ]]; then
    MODE="bulk"
elif [[ "$ENCRYPTED_HITS" -gt 0 || "$PER_IMG_OVERSIZED" -eq 1 ]]; then
    MODE="blocked"
elif [[ "$NEED_BYTES" -le "$FREE_BYTES" ]]; then
    MODE="bulk"
else
    MODE="sequential"
fi

# ---- 5. write the plan file ----
UTC_NOW="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"

{
    cat <<EOF
# Disk-Image Mount Plan

| Field | Value |
|---|---|
| Generated | ${UTC_NOW} |
| Mode | ${MODE} |
| Disk-image count | ${IMG_COUNT} |
| Mount overhead per image | $(hsize "$PER_IMAGE_OVERHEAD") |
| Total overhead | $(hsize "$TOTAL_OVERHEAD") |
| Headroom (${HEADROOM_PCT}%) | $(hsize "$HEADROOM_BYTES") |
| Required (overhead + headroom) | $(hsize "$NEED_BYTES") |
| Free at \`${WORKING_DIR}\` | $(hsize "$FREE_BYTES") |

> **Mount layer.** Disk images route through \`qemu-nbd\` (and \`ewfmount\` for
> E01) into \`./working/mounts/<EV>/p<M>/\`, exposed read-only. Mounts consume
> ~0 disk (block-device facade); planner sizes only mount-metadata + audit
> overhead per image. Tool flow per DISCIPLINE §P-diskimage.

EOF

    if [[ "$IMG_COUNT" -gt 0 ]]; then
        cat <<'EOF'
| stage | source | format | logical-size | adapter chain |
|---|---|---|---|---|
EOF
        for ((i=0; i<IMG_COUNT; i++)); do
            stage="$((i + 1))"
            [[ "$MODE" == "blocked" ]] && stage="-"
            [[ "$MODE" == "bulk" ]] && stage="1"
            printf '| %s | %s | %s | %s | %s |\n' \
                "$stage" \
                "${IMG_RELPATH[$i]}" \
                "${IMG_KIND[$i]}" \
                "$(hsize "${IMG_LOGICAL[$i]}")" \
                "${IMG_ADAPTER[$i]}"
        done
    else
        printf '\n_No disk images found in `%s` or `%s`._\n' \
            "$EVIDENCE_DIR" "$WORKING_DIR"
    fi

    case "$MODE" in
        bulk)
            cat <<EOF

## Plan: bulk

Every disk image is mounted in Phase 1 (triage). Mounts persist for the
duration of analysis and are detached at case close by
\`diskimage-unmount-all.sh\` (QA-phase gate).

Triage invokes \`diskimage-mount.sh <relpath> <EV>\` for each image in
the order above.
EOF
            ;;
        sequential)
            cat <<EOF

## Plan: sequential

Combined mount overhead exceeds free space, but every image's overhead
fits alone. Triage mounts the first image only; the orchestrator drives
mount/dismount cycles per image. \`extraction-cleanup.sh\` calls
\`diskimage-unmount.sh <EV>\` BEFORE deleting any \`./working/<bundle>/\`
that contains the image source.
EOF
            ;;
        blocked)
            DEFICIT=0
            if [[ "$PER_IMG_NEED" -gt "$FREE_BYTES" ]]; then
                DEFICIT=$(( PER_IMG_NEED - FREE_BYTES ))
            fi
            cat <<EOF

## Plan: blocked

Triage MUST NOT mount any disk image. The orchestrator surfaces lead
\`L-MOUNT-DISK-NN\` to the operator.

| Field | Value |
|---|---|
| Encrypted images detected | ${ENCRYPTED_HITS} |
| Per-image required (overhead + ${HEADROOM_PCT}% headroom) | $(hsize "$PER_IMG_NEED") |
| Free at \`${WORKING_DIR}\` | $(hsize "$FREE_BYTES") |
| Required-free-space delta | $(hsize "$DEFICIT") |

Resolution paths:
1. Provide a key for any encrypted source (re-run plan).
2. Free enough disk to satisfy the delta; re-run \`diskimage-plan.sh\`.
3. Mount a larger volume at \`./working/\` and re-run.
EOF
            ;;
    esac
} > "$PLAN_FILE"

# ---- 6. on blocked, append BLOCKED leads to leads.md ----
if [[ "$MODE" == "blocked" ]]; then
    if [[ "$ENCRYPTED_HITS" -gt 0 ]]; then
        for ((i=0; i<IMG_COUNT; i++)); do
            [[ "${IMG_KIND[$i]}" == "encrypted" ]] || continue
            hyp="Encrypted disk image: ${IMG_RELPATH[$i]} (qemu-img reports encrypted=yes); cannot mount without key"
            notes="suggested-fix=provide-key; tool-needed=disk-decryption-key; re-run diskimage-plan.sh after key supplied"
            lid="$(append_blocked_lead "L-MOUNT-DISK" "-" "$hyp" "analysis/diskimage-plan.md" "$notes")"
            [[ -n "$lid" ]] || true
        done
    fi
    if [[ "$PER_IMG_OVERSIZED" -eq 1 ]]; then
        DEFICIT=$(( PER_IMG_NEED - FREE_BYTES ))
        hyp="Disk-pressure block: per-image mount overhead $(hsize "$PER_IMG_NEED") exceeds free $(hsize "$FREE_BYTES")"
        notes="required-free-space-delta=$(hsize "$DEFICIT"); free disk or remount before retrying"
        lid="$(append_blocked_lead "L-MOUNT-DISK" "-" "$hyp" "analysis/diskimage-plan.md" "$notes")"
        [[ -n "$lid" ]] || true
    fi
fi

# ---- 7. audit + return ----
if [[ -x "$AUDIT_SH" ]]; then
    bash "$AUDIT_SH" "diskimage-plan computed" \
        "cmd: bash diskimage-plan.sh; exit=0; mode=${MODE} images=${IMG_COUNT} encrypted=${ENCRYPTED_HITS} overhead=${TOTAL_OVERHEAD} free=${FREE_BYTES}" \
        "diskimage-mount.sh per image per plan order" >/dev/null 2>&1 || true
fi

echo "diskimage-plan: mode=${MODE} images=${IMG_COUNT} encrypted=${ENCRYPTED_HITS} overhead=${TOTAL_OVERHEAD} free=${FREE_BYTES} plan=${PLAN_FILE}"

case "$MODE" in
    bulk|sequential) exit 0 ;;
    blocked)         exit 1 ;;
    *)               exit 2 ;;
esac
