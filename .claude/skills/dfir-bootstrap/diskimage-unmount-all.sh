#!/usr/bin/env bash
# diskimage-unmount-all.sh -- detach every disk-image mount in this case.
#
# Usage: bash diskimage-unmount-all.sh
#
# Walks ./working/mounts/.*.mount.json sentinels and invokes
# diskimage-unmount.sh on each EV with "mounted": true. Used by:
#
#   - QA phase, immediately before case-close sign-off.
#   - operator manual invocation when wrapping up a case.
#
# Exits 0 on full success, 1 if any per-EV unmount returned nonzero.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"
UNMOUNT_SH="${SCRIPT_DIR}/diskimage-unmount.sh"

if [[ ! -x "$UNMOUNT_SH" ]]; then
    echo "diskimage-unmount-all: $UNMOUNT_SH not executable" >&2
    exit 2
fi

MOUNTS_DIR="./working/mounts"
if [[ ! -d "$MOUNTS_DIR" ]]; then
    echo "diskimage-unmount-all: no $MOUNTS_DIR — nothing to do"
    exit 0
fi

failures=0
checked=0
unmounted=0

# Walk sentinel files. Pattern: ./working/mounts/.<EV>.mount.json
shopt -s nullglob
for sentinel in "${MOUNTS_DIR}"/.*.mount.json; do
    [[ -f "$sentinel" ]] || continue
    checked=$((checked + 1))

    base="$(basename "$sentinel")"
    # .EV01.mount.json -> EV01
    ev="${base#.}"
    ev="${ev%.mount.json}"

    if [[ ! "$ev" =~ ^EV[0-9]{2,}$ ]]; then
        echo "diskimage-unmount-all: skipping malformed sentinel $sentinel (ev=$ev)" >&2
        continue
    fi

    if bash "$UNMOUNT_SH" "$ev"; then
        unmounted=$((unmounted + 1))
    else
        failures=$((failures + 1))
    fi
done

if [[ -x "$AUDIT_SH" ]]; then
    bash "$AUDIT_SH" "diskimage-unmount-all: sweep" \
        "cmd: bash diskimage-unmount-all.sh; exit=${failures}; checked=${checked} unmounted=${unmounted} failures=${failures}" \
        "case-close OK" >/dev/null 2>&1 || true
fi

echo "diskimage-unmount-all: checked=${checked} unmounted=${unmounted} failures=${failures}"
[[ "$failures" -eq 0 ]]
