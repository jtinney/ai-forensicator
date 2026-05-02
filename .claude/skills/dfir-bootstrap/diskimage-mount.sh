#!/usr/bin/env bash
# diskimage-mount.sh -- canonical disk-image mount helper per
# DISCIPLINE §P-diskimage.
#
# Usage: bash diskimage-mount.sh <source-relpath> <ev-id>
#
#   <source-relpath>  path under ./evidence/ or ./working/ (relative or
#                     project-relative — the helper resolves to abs)
#   <ev-id>           evidence_id slot (EV01, EV02, ...). Caller is
#                     responsible for selecting an unused slot.
#
# Pipeline (uniform across formats; format detection only chooses qemu-nbd
# -f flag and whether ewfmount is needed first):
#
#   1. qemu-img info <source>                        # detection
#   2. lsmod | grep -q '^nbd' || modprobe nbd ...    # bootstrap (idempotent)
#   3. ewfmount <source> <ewfmount-dir>/             # E01 only
#   4. qemu-nbd --read-only --cache=none --format=<fmt> --connect=/dev/nbdN <source>
#   5. mmls /dev/nbdN > ./analysis/filesystem/mmls-<EV>.txt
#   6. mount -o ro,noload /dev/nbdNpM ./working/mounts/<EV>/pM   # per partition
#   7. sha256sum <source>                            # original-artifact hash
#   8. sha256sum /dev/nbdN                           # mount-source byte stream
#   9. write sentinel ./working/mounts/.<ev>.mount.json
#  10. (on every exit, via trap)
#       umount each partition mount; qemu-nbd --disconnect; fusermount -u <ewfmount-dir>
#
# Every command in the pipeline emits ONE exact-command audit row via
# audit.sh per DISCIPLINE §A.1 + the command-documentation contract in
# §P-diskimage. Investigators can replay the case from the audit log
# alone.
#
# Idempotent: if the sentinel exists and the recorded /dev/nbdN is still
# attached to the same source, the helper short-circuits and exits 0
# without re-mounting. Callers re-running this script after a clean
# unmount get a fresh mount cycle.
#
# Failure handling: on any nonzero pipeline step, the EXIT trap detaches
# every layer the helper attached so far (umount, qemu-nbd --disconnect,
# fusermount -u), appends an L-MOUNT-FAIL-NN BLOCKED lead, and exits 1.
# Encrypted sources BLOCK before attach with L-MOUNT-DISK-NN.
#
# Hashing contract:
#   - source sha256       -- ALWAYS (skipped if already in manifest.md)
#   - /dev/nbdN sha256    -- ALWAYS (the final-working-artifact equivalent)
#   - mount-tree files    -- NEVER (survey-hash-on-read.sh handles those at touch time)
#   - ewfmount intermediate /<ewf-dir>/ewf1 -- NEVER (chain-of-custody event audited only)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"

SOURCE_REL="${1:-}"
EV_ID="${2:-}"

if [[ -z "$SOURCE_REL" || -z "$EV_ID" ]]; then
    echo "usage: diskimage-mount.sh <source-relpath> <ev-id>" >&2
    exit 2
fi

if [[ ! "$EV_ID" =~ ^EV[0-9]{2,}$ ]]; then
    echo "diskimage-mount: ev-id must match EV[0-9]{2,} (got: $EV_ID)" >&2
    exit 2
fi

# Resolve source to an absolute path (qemu-nbd needs it).
if [[ "$SOURCE_REL" = /* ]]; then
    SOURCE_ABS="$SOURCE_REL"
else
    SOURCE_ABS="$(readlink -f "$SOURCE_REL" 2>/dev/null || echo "")"
fi
if [[ -z "$SOURCE_ABS" || ! -f "$SOURCE_ABS" ]]; then
    echo "diskimage-mount: source not found: $SOURCE_REL" >&2
    exit 2
fi

MOUNT_BASE="./working/mounts/${EV_ID}"
EWFMOUNT_DIR="${MOUNT_BASE}/.ewf"
SENTINEL="./working/mounts/.${EV_ID}.mount.json"
LEADS="./analysis/leads.md"

mkdir -p "$MOUNT_BASE"
mkdir -p ./analysis/filesystem

# ---- audit helper ----
emit_audit() {
    # emit_audit "<phase>: <verb>" "<exact cmd line>" "<exit>" "<extras>" "<next step>"
    local phase="$1" cmd="$2" rc="$3" extras="$4" nxt="$5"
    local result="cmd: ${cmd}; exit=${rc}"
    [[ -n "$extras" ]] && result+="; ${extras}"
    if [[ -x "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" "$phase" "$result" "$nxt" >/dev/null 2>&1 || true
    fi
}

# ---- leads helpers (mirror extraction-plan / case-init patterns) ----
ensure_leads_md() {
    if [[ ! -f "$LEADS" ]]; then
        mkdir -p ./analysis
        cat > "$LEADS" <<'EOF'
| lead_id | evidence_id | domain | hypothesis | pointer | priority | status | notes |
|---------|-------------|--------|------------|---------|----------|--------|-------|
EOF
    fi
}
next_lead_id() {
    local prefix="$1" last_n
    last_n="$(grep -oE "\\| ${prefix}-[0-9]+" "$LEADS" 2>/dev/null \
              | grep -oE '[0-9]+$' | sort -n | tail -1)"
    if [[ -z "$last_n" ]]; then printf '%s-01' "$prefix"
    else printf '%s-%02d' "$prefix" $((10#$last_n + 1)); fi
}
append_blocked_lead() {
    local prefix="$1" ev="$2" hyp="$3" pointer="$4" notes="$5"
    ensure_leads_md
    local hyp_safe="${hyp//|/\\|}" notes_safe="${notes//|/\\|}"
    if grep -qF "$hyp_safe" "$LEADS" 2>/dev/null; then
        grep -F "$hyp_safe" "$LEADS" 2>/dev/null \
            | grep -oE "\\| ${prefix}-[0-9]+" | head -1 | tr -d '| '
        return 0
    fi
    local lid; lid="$(next_lead_id "$prefix")"
    printf '| %s | %s | bootstrap | %s | %s | high | blocked | %s |\n' \
        "$lid" "$ev" "$hyp_safe" "$pointer" "$notes_safe" >> "$LEADS"
    echo "$lid"
}

# ---- detach state (populated as we attach) ----
PARTITIONS_MOUNTED=()
NBD_ATTACHED=""
EWFMOUNT_ATTACHED=""

# Trap detaches every layer in reverse order on EVERY exit path,
# including failures and signals. This is the chain-of-custody invariant:
# we never leave a /dev/nbdN attached or a mount lingering.
detach_all() {
    local exit_code=$?
    set +e

    # 1. unmount filesystem partitions
    for mp in "${PARTITIONS_MOUNTED[@]}"; do
        if mountpoint -q "$mp" 2>/dev/null; then
            local cmd="umount ${mp}"
            sudo umount "$mp" 2>/dev/null
            emit_audit "diskimage-mount: umount" "$cmd" "$?" "mountpoint=$mp" "qemu-nbd --disconnect"
        fi
    done

    # 2. detach qemu-nbd
    if [[ -n "$NBD_ATTACHED" ]]; then
        local cmd="qemu-nbd --disconnect ${NBD_ATTACHED}"
        sudo qemu-nbd --disconnect "$NBD_ATTACHED" 2>/dev/null
        emit_audit "diskimage-mount: nbd-detach" "$cmd" "$?" "nbd=${NBD_ATTACHED}" "fusermount -u (E01) or done"
    fi

    # 3. unmount ewfmount FUSE layer (E01 only)
    if [[ -n "$EWFMOUNT_ATTACHED" ]]; then
        local cmd="fusermount -u ${EWFMOUNT_ATTACHED}"
        fusermount -u "$EWFMOUNT_ATTACHED" 2>/dev/null
        emit_audit "diskimage-mount: ewfmount-detach" "$cmd" "$?" "ewfdir=${EWFMOUNT_ATTACHED}" "done"
    fi

    exit "$exit_code"
}
trap detach_all EXIT

# ---- step 1: detect format ----
QEMU_INFO_OUT=""
QEMU_INFO_RC=0
if command -v qemu-img >/dev/null 2>&1; then
    QEMU_INFO_OUT="$(qemu-img info "$SOURCE_ABS" 2>&1)"
    QEMU_INFO_RC=$?
    emit_audit "diskimage-mount: detect-format" \
        "qemu-img info ${SOURCE_ABS}" "$QEMU_INFO_RC" \
        "" "classify and pick adapter"
fi

KIND="unknown"
ENC_FLAG=""
if [[ "$QEMU_INFO_RC" -eq 0 ]]; then
    QFMT="$(printf '%s\n' "$QEMU_INFO_OUT" | awk -F': ' '/^file format:/ {print $2; exit}')"
    QENC="$(printf '%s\n' "$QEMU_INFO_OUT" | awk -F': ' '/^encrypted:/ {print $2; exit}')"
    [[ "$QENC" == "yes" ]] && ENC_FLAG="encrypted"
    case "$QFMT" in
        raw|vmdk|vpc|vhdx|qcow2) KIND="$QFMT" ;;
    esac
fi
# E01 detection via ewfinfo (more authoritative than qemu-img for E01)
if [[ "$KIND" == "unknown" || "$KIND" == "raw" ]]; then
    if command -v ewfinfo >/dev/null 2>&1 && ewfinfo "$SOURCE_ABS" >/dev/null 2>&1; then
        emit_audit "diskimage-mount: ewfinfo-probe" \
            "ewfinfo ${SOURCE_ABS}" "0" "" "classify as e01"
        KIND="e01"
    fi
fi

if [[ -n "$ENC_FLAG" ]]; then
    hyp="Encrypted disk image: ${SOURCE_REL} requires decryption key"
    notes="suggested-fix=provide-key; format=${KIND}; re-run after key supplied"
    lid="$(append_blocked_lead "L-MOUNT-DISK" "$EV_ID" "$hyp" "analysis/manifest.md" "$notes")"
    emit_audit "diskimage-mount: BLOCKED encrypted" \
        "qemu-img info reported encrypted=yes" "0" "lead=${lid}" "operator: provide key, re-run"
    echo "diskimage-mount: BLOCKED — encrypted source ($SOURCE_REL); lead=${lid}" >&2
    exit 1
fi

if [[ "$KIND" == "unknown" ]]; then
    hyp="Disk image format unknown for ${SOURCE_REL}: qemu-img info + ewfinfo both failed to classify"
    notes="suggested-fix=add-format-support; tool-needed=qemu-img-or-ewfinfo; investigate manually"
    lid="$(append_blocked_lead "L-MOUNT-FAIL" "$EV_ID" "$hyp" "analysis/manifest.md" "$notes")"
    emit_audit "diskimage-mount: BLOCKED unknown-format" \
        "classify_diskimage returned unknown" "1" "lead=${lid}" "operator: classify manually"
    echo "diskimage-mount: BLOCKED — format unknown for $SOURCE_REL; lead=${lid}" >&2
    exit 1
fi

# ---- short-circuit: existing sentinel + still-attached nbd ----
if [[ -f "$SENTINEL" ]]; then
    PRIOR_NBD="$(grep -oE '"nbd-device": *"[^"]+"' "$SENTINEL" 2>/dev/null \
                | head -1 | sed 's/.*"\(\/dev\/nbd[0-9]\+\)".*/\1/')"
    if [[ -n "$PRIOR_NBD" && -b "$PRIOR_NBD" ]]; then
        # Probe whether nbd is currently bound to our source
        if sudo nbd-client -c "$PRIOR_NBD" >/dev/null 2>&1 \
           || [[ -s "/sys/block/$(basename "$PRIOR_NBD")/size" ]]; then
            emit_audit "diskimage-mount: idempotent-skip" \
                "sentinel ${SENTINEL} present; nbd ${PRIOR_NBD} still attached" \
                "0" "ev=${EV_ID} format=${KIND}" "no-op"
            echo "diskimage-mount: $EV_ID already mounted at $PRIOR_NBD (sentinel hit)"
            # Suppress the trap from detaching — we did not attach this round.
            trap - EXIT
            exit 0
        fi
    fi
fi

# ---- step 2: bootstrap nbd kernel module ----
NBD_OK=0
if lsmod 2>/dev/null | grep -q '^nbd'; then
    NBD_OK=1
    emit_audit "diskimage-mount: nbd-probe" \
        "lsmod | grep -q '^nbd'" "0" "module=loaded" "qemu-nbd attach"
else
    emit_audit "diskimage-mount: nbd-probe" \
        "lsmod | grep -q '^nbd'" "1" "module=absent" "modprobe nbd max_part=16"
    if sudo modprobe nbd max_part=16 2>/dev/null; then
        NBD_OK=1
        emit_audit "diskimage-mount: modprobe-nbd" \
            "modprobe nbd max_part=16" "0" "module=loaded" "qemu-nbd attach"
    else
        emit_audit "diskimage-mount: modprobe-nbd" \
            "modprobe nbd max_part=16" "$?" "module=load-failed" "operator: kernel nbd missing"
    fi
fi
if [[ "$NBD_OK" -ne 1 ]]; then
    hyp="nbd kernel module unavailable on host; cannot attach $SOURCE_REL"
    notes="suggested-fix=install-package; tool-needed=kernel-nbd-module"
    lid="$(append_blocked_lead "L-MOUNT-FAIL" "$EV_ID" "$hyp" "analysis/manifest.md" "$notes")"
    echo "diskimage-mount: BLOCKED — nbd kernel module not loadable; lead=${lid}" >&2
    exit 1
fi

# ---- pick a free /dev/nbd<N> ----
pick_nbd() {
    local n=0
    while [[ $n -lt 16 ]]; do
        local dev="/dev/nbd${n}"
        if [[ ! -b "$dev" ]]; then
            n=$((n + 1)); continue
        fi
        # /sys/block/nbdN/size == 0 means unused
        local size=0
        size="$(cat "/sys/block/nbd${n}/size" 2>/dev/null || echo 0)"
        if [[ "$size" == "0" ]]; then
            echo "$dev"
            return 0
        fi
        n=$((n + 1))
    done
    echo ""
}
NBD_DEV="$(pick_nbd)"
if [[ -z "$NBD_DEV" ]]; then
    hyp="No free /dev/nbd[0-15] available; all 16 nbd slots in use"
    notes="suggested-fix=detach-stale-nbd-or-modprobe-with-larger-nbds-max"
    lid="$(append_blocked_lead "L-MOUNT-FAIL" "$EV_ID" "$hyp" "analysis/manifest.md" "$notes")"
    echo "diskimage-mount: BLOCKED — no free nbd device; lead=${lid}" >&2
    exit 1
fi

# ---- step 3: ewfmount (E01 only) ----
QEMU_SOURCE="$SOURCE_ABS"
QEMU_FMT=""
case "$KIND" in
    e01)
        mkdir -p "$EWFMOUNT_DIR"
        local_cmd="ewfmount ${SOURCE_ABS} ${EWFMOUNT_DIR}"
        ewfmount "$SOURCE_ABS" "$EWFMOUNT_DIR" 2>/dev/null
        rc=$?
        emit_audit "diskimage-mount: ewfmount" "$local_cmd" "$rc" "ewfdir=${EWFMOUNT_DIR}" "qemu-nbd attach"
        if [[ "$rc" -ne 0 || ! -e "${EWFMOUNT_DIR}/ewf1" ]]; then
            hyp="ewfmount failed for ${SOURCE_REL} (E01 source); cannot expose raw byte stream"
            notes="suggested-fix=verify-libewf-tools; cmd=${local_cmd}; rc=${rc}"
            lid="$(append_blocked_lead "L-MOUNT-FAIL" "$EV_ID" "$hyp" "analysis/manifest.md" "$notes")"
            echo "diskimage-mount: BLOCKED — ewfmount failed for $SOURCE_REL; lead=${lid}" >&2
            exit 1
        fi
        EWFMOUNT_ATTACHED="$EWFMOUNT_DIR"
        QEMU_SOURCE="${EWFMOUNT_DIR}/ewf1"
        QEMU_FMT="raw"
        ;;
    raw)        QEMU_FMT="raw"   ;;
    vmdk)       QEMU_FMT="vmdk"  ;;
    vpc)        QEMU_FMT="vpc"   ;;
    vhdx)       QEMU_FMT="vhdx"  ;;
    qcow2)      QEMU_FMT="qcow2" ;;
esac

# ---- step 4: qemu-nbd attach ----
ATTACH_CMD="qemu-nbd --read-only --cache=none --format=${QEMU_FMT} --connect=${NBD_DEV} ${QEMU_SOURCE}"
sudo qemu-nbd --read-only --cache=none --format="$QEMU_FMT" --connect="$NBD_DEV" "$QEMU_SOURCE" 2>/dev/null
rc=$?
emit_audit "diskimage-mount: nbd-attach" "$ATTACH_CMD" "$rc" "nbd=${NBD_DEV} format=${QEMU_FMT}" "mmls partition table"
if [[ "$rc" -ne 0 ]]; then
    hyp="qemu-nbd attach failed for ${SOURCE_REL} (format=${KIND}); see audit log for stderr"
    notes="suggested-fix=verify-source-integrity; cmd=${ATTACH_CMD}; rc=${rc}"
    lid="$(append_blocked_lead "L-MOUNT-FAIL" "$EV_ID" "$hyp" "analysis/manifest.md" "$notes")"
    echo "diskimage-mount: BLOCKED — qemu-nbd attach failed for $SOURCE_REL; lead=${lid}" >&2
    exit 1
fi
NBD_ATTACHED="$NBD_DEV"

# Wait for the kernel to populate /sys/block/<nbdN>/size
sleep_count=0
while [[ "$sleep_count" -lt 20 ]]; do
    sz="$(cat "/sys/block/$(basename "$NBD_DEV")/size" 2>/dev/null || echo 0)"
    [[ "$sz" != "0" ]] && break
    sleep 0.1
    sleep_count=$((sleep_count + 1))
done

# ---- step 5: mmls (partition layout) ----
MMLS_OUT="./analysis/filesystem/mmls-${EV_ID}.txt"
MMLS_CMD="mmls ${NBD_DEV}"
mmls "$NBD_DEV" > "$MMLS_OUT" 2>/dev/null
rc=$?
emit_audit "diskimage-mount: mmls" "$MMLS_CMD > $MMLS_OUT" "$rc" "out=${MMLS_OUT}" "mount partitions"
# mmls non-zero is non-fatal (some images have no partition table; we still
# attempt to mount /dev/nbdN as a single filesystem).

# ---- step 6: mount partitions ----
# Parse mmls output: rows starting with a digit are partition slots.
# Format: "<slot>:  <start>  <end>  <length>  <description>"
declare -a PARTS_TO_MOUNT=()
if [[ "$rc" -eq 0 && -s "$MMLS_OUT" ]]; then
    while read -r slot _; do
        [[ "$slot" =~ ^[0-9]{3}: ]] || continue
        # mmls slot 000 typically maps to /dev/nbdNp1, but partitions
        # without a filesystem (e.g. extended container, unallocated) need
        # filtering. Use file -s on each /dev/nbdNp* the kernel created.
        :
    done < "$MMLS_OUT"
fi
# Walk every /dev/nbdNpM the kernel created; let mount succeed where it can.
for partdev in "${NBD_DEV}"p*; do
    [[ -b "$partdev" ]] || continue
    pnum="${partdev##*p}"
    mp="${MOUNT_BASE}/p${pnum}"
    mkdir -p "$mp"
    # Attempt mount; ro,noload prevents journal replay on ext.
    MOUNT_CMD="mount -o ro,noload ${partdev} ${mp}"
    sudo mount -o ro,noload "$partdev" "$mp" 2>/dev/null
    mrc=$?
    if [[ "$mrc" -ne 0 ]]; then
        # Retry without noload (NTFS / FAT don't accept noload)
        MOUNT_CMD="mount -o ro ${partdev} ${mp}"
        sudo mount -o ro "$partdev" "$mp" 2>/dev/null
        mrc=$?
    fi
    if [[ "$mrc" -eq 0 ]]; then
        PARTITIONS_MOUNTED+=("$mp")
        FS_TYPE="$(findmnt -n -o FSTYPE "$mp" 2>/dev/null || echo unknown)"
        emit_audit "diskimage-mount: partition-mount" \
            "$MOUNT_CMD" "0" "fs=${FS_TYPE} part=${partdev}" "next partition or hash"
    else
        rmdir "$mp" 2>/dev/null || true
        emit_audit "diskimage-mount: partition-mount" \
            "$MOUNT_CMD" "$mrc" "part=${partdev} skip=true" "filesystem unsupported or unallocated; continue"
    fi
done

# ---- step 7: source sha256 ----
SRC_HASH_CMD="sha256sum ${SOURCE_ABS}"
SRC_SHA="$(sha256sum "$SOURCE_ABS" 2>/dev/null | awk '{print $1}')"
emit_audit "diskimage-mount: source-hash" "$SRC_HASH_CMD" "$?" "sha256=${SRC_SHA}" "nbd-stream hash"

# ---- step 8: /dev/nbdN sha256 (the final-working-artifact equivalent) ----
NBD_HASH_CMD="sha256sum ${NBD_DEV}"
NBD_SHA="$(sudo sha256sum "$NBD_DEV" 2>/dev/null | awk '{print $1}')"
emit_audit "diskimage-mount: nbd-stream-hash" "$NBD_HASH_CMD" "$?" "sha256=${NBD_SHA} nbd=${NBD_DEV}" "write sentinel"

if [[ -z "$NBD_SHA" ]]; then
    hyp="sha256sum of ${NBD_DEV} returned empty for ${SOURCE_REL}; chain-of-custody invariant violated"
    notes="suggested-fix=re-run-mount; verify nbd kernel module"
    lid="$(append_blocked_lead "L-MOUNT-FAIL" "$EV_ID" "$hyp" "analysis/manifest.md" "$notes")"
    echo "diskimage-mount: BLOCKED — empty nbd sha256; lead=${lid}" >&2
    exit 1
fi

# ---- step 9: write sentinel ----
UTC_NOW="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
QEMU_NBD_VER="$(qemu-nbd --version 2>/dev/null | head -1 | sed 's/"/\\"/g' || echo unknown)"
EWFMOUNT_VER=""
if [[ "$KIND" == "e01" ]]; then
    EWFMOUNT_VER="$(ewfmount -V 2>&1 | head -1 | sed 's/"/\\"/g' || echo unknown)"
fi
MOUNT_LIST_JSON="["
first=1
for mp in "${PARTITIONS_MOUNTED[@]:-}"; do
    [[ -z "$mp" ]] && continue
    if [[ "$first" -eq 1 ]]; then first=0; else MOUNT_LIST_JSON+=", "; fi
    MOUNT_LIST_JSON+="\"${mp}\""
done
MOUNT_LIST_JSON+="]"

cat > "$SENTINEL" <<EOF
{
  "schema": "diskimage-mount/v1",
  "ev_id": "${EV_ID}",
  "source_relpath": "${SOURCE_REL}",
  "source_abspath": "${SOURCE_ABS}",
  "format": "${KIND}",
  "qemu_format": "${QEMU_FMT}",
  "adapter_chain": "$(/bin/echo -n "$KIND" | grep -q '^e01$' && echo 'ewfmount -> qemu-nbd -f raw -> mount -o ro,noload' || echo "qemu-nbd -f ${QEMU_FMT} -> mount -o ro,noload")",
  "ewfmount_dir": "${EWFMOUNT_ATTACHED}",
  "nbd_device": "${NBD_DEV}",
  "mount_points": ${MOUNT_LIST_JSON},
  "source_sha256": "${SRC_SHA}",
  "nbd_byte_sha256": "${NBD_SHA}",
  "tool_versions": {
    "qemu-nbd": "${QEMU_NBD_VER}",
    "ewfmount": "${EWFMOUNT_VER}"
  },
  "ts_attach": "${UTC_NOW}",
  "ts_detach": null,
  "mounted": true
}
EOF
emit_audit "diskimage-mount: sentinel-write" \
    "Write ${SENTINEL}" "0" \
    "ev=${EV_ID} format=${KIND} nbd=${NBD_DEV} mounts=${#PARTITIONS_MOUNTED[@]} src-sha=${SRC_SHA:0:16} nbd-sha=${NBD_SHA:0:16}" \
    "case-init.sh appends manifest rows (blob + disk-mount)"

# Successful exit — suppress the trap so we DO NOT detach. Mount persists
# for downstream phases. diskimage-unmount.sh detaches when needed.
trap - EXIT

echo "diskimage-mount: $EV_ID mounted (format=${KIND}, nbd=${NBD_DEV}, partitions=${#PARTITIONS_MOUNTED[@]})"
exit 0
