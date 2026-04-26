#!/usr/bin/env bash
# audit-verify.sh — PostToolUse drift detector for forensic_audit.log.
#
# After every Bash / Write / Edit, scans new appends to ./analysis/forensic_audit.log
# since the last hook firing. Flags timestamps that drift from wall-clock by more
# than $AUDIT_VERIFY_TOLERANCE seconds (default 60), and timestamps that use the
# ISO-8601 'YYYY-MM-DDTHH:MM:SSZ' form (audit.sh emits 'YYYY-MM-DD HH:MM:SS UTC' —
# anything else was direct-written and is suspect).
#
# Append-only: never modifies existing rows. Violations are emitted as new rows
# via audit.sh itself, so the violation entries are themselves well-formed.
#
# Wired in .claude/settings.json under hooks.PostToolUse, matcher "Bash|Write|Edit".

set -u

# Quietly exit if not in a case dir
AUDIT="./analysis/forensic_audit.log"
[[ -f "$AUDIT" ]] || exit 0

SIDECAR="./analysis/.audit.lastsize"
TOLERANCE_SECS="${AUDIT_VERIFY_TOLERANCE:-60}"
# audit.sh lives next to this script — locate via BASH_SOURCE so the hook
# works regardless of the agent's cwd.
AUDIT_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/audit.sh"

# ---- byte-offset bookkeeping ----
cur_size=$(stat -c%s "$AUDIT" 2>/dev/null || echo 0)
last_size=$(cat "$SIDECAR" 2>/dev/null || echo 0)
[[ "$last_size" =~ ^[0-9]+$ ]] || last_size=0

# Sidecar mtime = when the previous PostToolUse fire ran. We use it as the
# drift floor: any new row dated before this is suspicious (it was written
# in the past, not at write-time wall-clock). This avoids flagging long-
# running Bash calls (e.g., a 5-minute tshark) that write audit entries
# throughout their execution: the entries are correct, just older than
# wall_epoch by minutes.
sidecar_mtime=$(stat -c%Y "$SIDECAR" 2>/dev/null || echo 0)
[[ "$sidecar_mtime" =~ ^[0-9]+$ ]] || sidecar_mtime=0

if [[ "$cur_size" -le "$last_size" ]]; then
    echo "$cur_size" > "$SIDECAR" 2>/dev/null || true
    exit 0
fi

new_bytes=$(( cur_size - last_size ))
new_text=$(tail -c "$new_bytes" "$AUDIT" 2>/dev/null || true)
if [[ -z "$new_text" ]]; then
    echo "$cur_size" > "$SIDECAR" 2>/dev/null || true
    exit 0
fi

wall_epoch=$(date -u +%s)
# Allowed window: [drift_floor, drift_ceiling]
# - drift_floor = previous PostToolUse fire time minus tolerance
#   (or wall_now - 1h if no sidecar yet — first run)
# - drift_ceiling = wall_now + tolerance (catch future-dated forgeries)
if [[ "$sidecar_mtime" -gt 0 ]]; then
    drift_floor=$(( sidecar_mtime - TOLERANCE_SECS ))
else
    drift_floor=$(( wall_epoch - 3600 ))
fi
drift_ceiling=$(( wall_epoch + TOLERANCE_SECS ))

emit_violation() {
    local desc="$1"
    if [[ -f "$AUDIT_SH" ]]; then
        bash "$AUDIT_SH" \
            "audit-verify.sh" \
            "INTEGRITY-VIOLATION ${desc}" \
            "agent must re-emit forensic_audit.log entries via audit.sh; do not direct-write" \
            >/dev/null 2>&1 || true
    fi
}

# ---- scan new tail, flag suspect rows ----
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue

    # Skip violation entries we ourselves emit (avoid feedback loop)
    if [[ "$line" == *"audit-verify.sh"* && "$line" == *"INTEGRITY-VIOLATION"* ]]; then
        continue
    fi

    epoch=0
    if [[ "$line" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})\ ([0-9]{2}):([0-9]{2}):([0-9]{2})\ UTC\ \| ]]; then
        # Canonical audit.sh format
        Y="${BASH_REMATCH[1]}" M="${BASH_REMATCH[2]}" D="${BASH_REMATCH[3]}"
        h="${BASH_REMATCH[4]}" m="${BASH_REMATCH[5]}" s="${BASH_REMATCH[6]}"
        epoch=$(date -u -d "$Y-$M-$D $h:$m:$s UTC" +%s 2>/dev/null || echo 0)
    elif [[ "$line" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z ]]; then
        # ISO-8601 T...Z — case7 forgery shape; audit.sh never emits this
        Y="${BASH_REMATCH[1]}" M="${BASH_REMATCH[2]}" D="${BASH_REMATCH[3]}"
        h="${BASH_REMATCH[4]}" m="${BASH_REMATCH[5]}" s="${BASH_REMATCH[6]}"
        epoch=$(date -u -d "$Y-$M-$D $h:$m:$s UTC" +%s 2>/dev/null || echo 0)
        excerpt="$(printf '%s' "$line" | head -c 100 | tr '|' '!')"
        emit_violation "MALFORMED-FORMAT line uses ISO-8601 T...Z (audit.sh emits 'YYYY-MM-DD HH:MM:SS UTC') :: ${excerpt}"
    else
        # Could not parse leading timestamp at all
        excerpt="$(printf '%s' "$line" | head -c 100 | tr '|' '!')"
        emit_violation "UNPARSEABLE-TIMESTAMP :: ${excerpt}"
        continue
    fi

    # Drift check — must fall in [drift_floor, drift_ceiling].
    # Below floor = row written in the past (suspicious unless this is the
    # first PostToolUse fire). Above ceiling = future-dated (always flag).
    if [[ "$epoch" -gt 0 ]]; then
        if [[ "$epoch" -lt "$drift_floor" ]]; then
            drift=$(( drift_floor - epoch ))
            excerpt="$(printf '%s' "$line" | head -c 100 | tr '|' '!')"
            emit_violation "DRIFT-PAST line stamp ${drift}s before previous hook fire (anchor=${sidecar_mtime}) :: ${excerpt}"
        elif [[ "$epoch" -gt "$drift_ceiling" ]]; then
            drift=$(( epoch - wall_epoch ))
            excerpt="$(printf '%s' "$line" | head -c 100 | tr '|' '!')"
            emit_violation "DRIFT-FUTURE line stamp ${drift}s after wall (tolerance ${TOLERANCE_SECS}s) :: ${excerpt}"
        fi
    fi
done <<< "$new_text"

# Advance sidecar past anything we may have just written
final_size=$(stat -c%s "$AUDIT" 2>/dev/null || echo "$cur_size")
echo "$final_size" > "$SIDECAR" 2>/dev/null || true

exit 0
