#!/usr/bin/env bash
# diskimage-unmount.sh -- canonical disk-image dismount per
# DISCIPLINE §P-diskimage.
#
# Usage: bash diskimage-unmount.sh <ev-id>
#
# Reads ./working/mounts/.<ev>.mount.json (the sentinel written by
# diskimage-mount.sh) and reverses the adapter chain:
#
#   1. umount each ./working/mounts/<EV>/p<M>/ partition
#   2. qemu-nbd --disconnect /dev/nbd<N>
#   3. fusermount -u <ewfmount-dir>     # E01 only
#
# Marks the sentinel as `unmounted` (does NOT delete -- chain-of-custody
# record is preserved). Idempotent: re-running on an already-unmounted
# sentinel is a no-op (logged once).
#
# Used by:
#   - extraction-cleanup.sh (sequential mode, before rm -rf bundle dir)
#   - diskimage-unmount-all.sh (case close, QA-phase gate)
#   - operator manual invocation
#
# Every command emits an exact-command audit row per DISCIPLINE §A.1.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"

EV_ID="${1:-}"
if [[ -z "$EV_ID" ]]; then
    echo "usage: diskimage-unmount.sh <ev-id>" >&2
    exit 2
fi
if [[ ! "$EV_ID" =~ ^EV[0-9]{2,}$ ]]; then
    echo "diskimage-unmount: ev-id must match EV[0-9]{2,} (got: $EV_ID)" >&2
    exit 2
fi

SENTINEL="./working/mounts/.${EV_ID}.mount.json"
if [[ ! -f "$SENTINEL" ]]; then
    echo "diskimage-unmount: no sentinel for $EV_ID at $SENTINEL — nothing to do" >&2
    exit 0
fi

emit_audit() {
    local phase="$1" cmd="$2" rc="$3" extras="$4" nxt="$5"
    local result="cmd: ${cmd}; exit=${rc}"
    [[ -n "$extras" ]] && result+="; ${extras}"
    if [[ -x "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" "$phase" "$result" "$nxt" >/dev/null 2>&1 || true
    fi
}

# Read sentinel fields with cheap awk/grep (avoid jq dependency).
read_sentinel_field() {
    local key="$1"
    grep -oE "\"${key}\":[[:space:]]*\"[^\"]*\"" "$SENTINEL" 2>/dev/null \
        | head -1 \
        | sed -E "s/.*\"${key}\":[[:space:]]*\"([^\"]*)\".*/\1/"
}

read_sentinel_mounts() {
    # Extract the mount_points array. Format: "mount_points": ["a", "b"]
    grep -oE '"mount_points":[[:space:]]*\[[^]]*\]' "$SENTINEL" 2>/dev/null \
        | head -1 \
        | grep -oE '"[^"]+"' \
        | tr -d '"'
}

read_sentinel_bool() {
    local key="$1"
    grep -oE "\"${key}\":[[:space:]]*(true|false)" "$SENTINEL" 2>/dev/null \
        | head -1 \
        | awk -F': *' '{print $2}'
}

NBD_DEV="$(read_sentinel_field nbd_device)"
EWF_DIR="$(read_sentinel_field ewfmount_dir)"
ALREADY_UNMOUNTED="$(read_sentinel_bool mounted)"

# Idempotent: if sentinel says mounted=false, just confirm and exit.
if [[ "$ALREADY_UNMOUNTED" == "false" ]]; then
    emit_audit "diskimage-unmount: idempotent-skip" \
        "sentinel ${SENTINEL} mounted=false" "0" "ev=${EV_ID}" "no-op"
    echo "diskimage-unmount: $EV_ID already unmounted"
    exit 0
fi

# 1. Unmount partitions (read from sentinel).
for mp in $(read_sentinel_mounts); do
    if mountpoint -q "$mp" 2>/dev/null; then
        cmd="umount ${mp}"
        sudo umount "$mp" 2>/dev/null
        rc=$?
        emit_audit "diskimage-unmount: umount" "$cmd" "$rc" "mountpoint=${mp}" \
            "next partition or qemu-nbd --disconnect"
    fi
done

# 2. qemu-nbd --disconnect
if [[ -n "$NBD_DEV" && -b "$NBD_DEV" ]]; then
    cmd="qemu-nbd --disconnect ${NBD_DEV}"
    sudo qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null
    rc=$?
    emit_audit "diskimage-unmount: nbd-detach" "$cmd" "$rc" "nbd=${NBD_DEV}" \
        "fusermount -u (E01 only) or done"
fi

# 3. fusermount -u (ewfmount layer, E01 only)
if [[ -n "$EWF_DIR" && -d "$EWF_DIR" ]]; then
    if mountpoint -q "$EWF_DIR" 2>/dev/null; then
        cmd="fusermount -u ${EWF_DIR}"
        fusermount -u "$EWF_DIR" 2>/dev/null
        rc=$?
        emit_audit "diskimage-unmount: ewfmount-detach" "$cmd" "$rc" \
            "ewfdir=${EWF_DIR}" "mark sentinel unmounted"
    fi
fi

# 4. Mark sentinel unmounted (preserve chain-of-custody record).
UTC_NOW="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
# In-place edit: flip "mounted": true -> false; set ts_detach.
# sed -i is denied on audit log paths but allowed on sentinels in working/mounts/.
sed -i.bak \
    -e "s/\"mounted\":[[:space:]]*true/\"mounted\": false/" \
    -e "s/\"ts_detach\":[[:space:]]*null/\"ts_detach\": \"${UTC_NOW}\"/" \
    "$SENTINEL" 2>/dev/null
rm -f "${SENTINEL}.bak" 2>/dev/null

emit_audit "diskimage-unmount: sentinel-mark" \
    "sed -i mounted=false ts_detach=${UTC_NOW} ${SENTINEL}" "0" \
    "ev=${EV_ID}" "done"

echo "diskimage-unmount: $EV_ID detached"
exit 0
