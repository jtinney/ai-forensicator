#!/usr/bin/env bash
# audit-retrofit.sh — one-shot offline integrity checker for an existing
# forensic_audit.log.
#
# Walks the log line-by-line, parses every leading timestamp, and flags rows
# that diverge from the canonical 'YYYY-MM-DD HH:MM:SS UTC' form audit.sh emits.
# Writes a markdown report to <audit-dir>/audit-integrity.md. Read-only — never
# modifies the audit log.
#
# Use:
#   bash audit-retrofit.sh /path/to/forensic_audit.log

set -u

if [[ $# -lt 1 ]]; then
    cat >&2 <<EOF
usage: audit-retrofit.sh <path-to-forensic_audit.log>

Walks the log and writes <audit-dir>/audit-integrity.md flagging rows that:
  - use 'YYYY-MM-DDTHH:MM:SSZ' form (audit.sh emits 'YYYY-MM-DD HH:MM:SS UTC')
  - are non-monotonic (>60s backwards) vs. the previous well-formed row
  - cluster >=4 rows at an identical second (humans + tools rarely coincide)
  - cannot be parsed at all

Drift vs. file mtime is reported in an informational appendix only — file
mtime is the moment of last append, not a per-line wall-clock anchor, so
multi-day drifts are normal for cases that span sessions and are not
violations on their own.

Read-only retro-audit. Does not modify the audit log.
EOF
    exit 2
fi

AUDIT="$1"
if [[ ! -f "$AUDIT" ]]; then
    echo "audit-retrofit.sh: not a file: $AUDIT" >&2
    exit 2
fi

REPORT="$(dirname "$AUDIT")/audit-integrity.md"
LOG_MTIME=$(stat -c%Y "$AUDIT" 2>/dev/null || echo 0)
LOG_MTIME_HUMAN=$(date -u -d "@${LOG_MTIME}" +'%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo unknown)

SAME_SEC_THRESHOLD=4
BACKWARDS_TOL=60
DRIFT_INFO_TOL=86400     # report rows >24h from mtime informationally only

declare -A SEC_LINES=()
declare -A SEC_COUNT=()
suspect_rows=()
drift_info_rows=()
iso_t_count=0
drift_info_count=0
nonmono_count=0
unparseable_count=0
last_epoch=0
ln=0

while IFS= read -r line || [[ -n "$line" ]]; do
    ln=$(( ln + 1 ))
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue

    reasons=""
    ts_text="(no timestamp)"
    epoch=0

    if [[ "$line" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})\ ([0-9]{2}):([0-9]{2}):([0-9]{2})\ UTC\ \| ]]; then
        Y="${BASH_REMATCH[1]}"; M="${BASH_REMATCH[2]}"; D="${BASH_REMATCH[3]}"
        h="${BASH_REMATCH[4]}"; m="${BASH_REMATCH[5]}"; s="${BASH_REMATCH[6]}"
        ts_text="${Y}-${M}-${D} ${h}:${m}:${s} UTC"
        epoch=$(date -u -d "${Y}-${M}-${D} ${h}:${m}:${s} UTC" +%s 2>/dev/null || echo 0)
    elif [[ "$line" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z ]]; then
        Y="${BASH_REMATCH[1]}"; M="${BASH_REMATCH[2]}"; D="${BASH_REMATCH[3]}"
        h="${BASH_REMATCH[4]}"; m="${BASH_REMATCH[5]}"; s="${BASH_REMATCH[6]}"
        ts_text="${Y}-${M}-${D}T${h}:${m}:${s}Z"
        reasons="ISO-8601 T...Z form (audit.sh emits 'YYYY-MM-DD HH:MM:SS UTC')"
        iso_t_count=$(( iso_t_count + 1 ))
        epoch=$(date -u -d "${Y}-${M}-${D} ${h}:${m}:${s} UTC" +%s 2>/dev/null || echo 0)
    else
        reasons="could not parse leading timestamp"
        unparseable_count=$(( unparseable_count + 1 ))
        excerpt="$(printf '%s' "$line" | head -c 120 | tr '|' '!')"
        suspect_rows+=("${ln}|${ts_text}|${reasons}|${excerpt}")
        continue
    fi

    if [[ "$epoch" -gt 0 && "$LOG_MTIME" -gt 0 ]]; then
        if [[ "$epoch" -gt "$LOG_MTIME" ]]; then
            drift=$(( epoch - LOG_MTIME ))
        else
            drift=$(( LOG_MTIME - epoch ))
        fi
        # Drift is informational only — file mtime is the last-append moment,
        # not a per-line wall-clock. Multi-day drifts are normal across sessions.
        if [[ "$drift" -gt "$DRIFT_INFO_TOL" ]]; then
            excerpt_d="$(printf '%s' "$line" | head -c 100 | tr '|' '!')"
            drift_info_rows+=("${ln}|${ts_text}|${drift}|${excerpt_d}")
            drift_info_count=$(( drift_info_count + 1 ))
        fi
    fi

    if [[ "$last_epoch" -gt 0 && "$epoch" -gt 0 ]]; then
        if [[ $(( epoch + BACKWARDS_TOL )) -lt "$last_epoch" ]]; then
            r="non-monotonic: drops $(( last_epoch - epoch ))s vs prev row"
            reasons="${reasons:+${reasons}; }${r}"
            nonmono_count=$(( nonmono_count + 1 ))
        fi
    fi
    if [[ "$epoch" -gt "$last_epoch" ]]; then
        last_epoch="$epoch"
    fi

    SEC_COUNT["$ts_text"]=$(( ${SEC_COUNT["$ts_text"]:-0} + 1 ))
    if [[ -z "${SEC_LINES[$ts_text]:-}" ]]; then
        SEC_LINES["$ts_text"]="$ln"
    else
        SEC_LINES["$ts_text"]="${SEC_LINES[$ts_text]},$ln"
    fi

    if [[ -n "$reasons" ]]; then
        excerpt="$(printf '%s' "$line" | head -c 120 | tr '|' '!')"
        suspect_rows+=("${ln}|${ts_text}|${reasons}|${excerpt}")
    fi
done < "$AUDIT"

cluster_count=0
cluster_rows=0
for ts in "${!SEC_COUNT[@]}"; do
    n="${SEC_COUNT[$ts]}"
    if [[ "$n" -ge "$SAME_SEC_THRESHOLD" ]]; then
        cluster_count=$(( cluster_count + 1 ))
        cluster_rows=$(( cluster_rows + n ))
    fi
done

# ---- write report ----
{
    echo "# Audit-Log Integrity Report"
    echo
    echo "**Audit log:** \`${AUDIT}\`"
    echo "**Log file mtime:** ${LOG_MTIME_HUMAN} (epoch ${LOG_MTIME})"
    echo
    echo "Scan policy:"
    echo
    echo "1. The canonical \`audit.sh\` format is \`YYYY-MM-DD HH:MM:SS UTC | action | result | next\`."
    echo "   Lines matching \`YYYY-MM-DDTHH:MM:SSZ\` (ISO-8601 T...Z) were NOT written by audit.sh."
    echo "2. Same-second clusters (>= ${SAME_SEC_THRESHOLD} rows at identical second) are flagged."
    echo "3. Timestamps that go backwards more than ${BACKWARDS_TOL}s vs. the previous row are flagged."
    echo "4. Drift vs. file mtime is informational only (see appendix); not counted as a violation."
    echo
    echo "## Suspect rows"
    echo
    echo "| line | timestamp | reasons | excerpt |"
    echo "|---|---|---|---|"
    if [[ "${#suspect_rows[@]}" -eq 0 ]]; then
        echo "| (none) | | | |"
    else
        for row in "${suspect_rows[@]}"; do
            IFS='|' read -r r_ln r_ts r_reasons r_excerpt <<< "$row"
            r_excerpt="${r_excerpt//|/\\|}"
            echo "| ${r_ln} | \`${r_ts}\` | ${r_reasons} | \`${r_excerpt}\` |"
        done
    fi
    echo
    echo "## Same-second clusters (>= ${SAME_SEC_THRESHOLD} rows at identical second)"
    echo
    echo "| timestamp | rows | line numbers |"
    echo "|---|---|---|"
    if [[ "$cluster_count" -eq 0 ]]; then
        echo "| (none) | | |"
    else
        # Print sorted by descending count
        for ts in "${!SEC_COUNT[@]}"; do
            n="${SEC_COUNT[$ts]}"
            if [[ "$n" -ge "$SAME_SEC_THRESHOLD" ]]; then
                echo "| \`${ts}\` | ${n} | ${SEC_LINES[$ts]} |"
            fi
        done | sort -t'|' -k3 -rn
    fi
    echo
    echo "## Informational: drift vs. file mtime (> 24h)"
    echo
    echo "These are NOT counted as violations — listed for context only."
    echo
    echo "| line | timestamp | drift_seconds | excerpt |"
    echo "|---|---|---|---|"
    if [[ "${#drift_info_rows[@]}" -eq 0 ]]; then
        echo "| (none) | | | |"
    else
        for row in "${drift_info_rows[@]}"; do
            IFS='|' read -r d_ln d_ts d_drift d_excerpt <<< "$row"
            d_excerpt="${d_excerpt//|/\\|}"
            echo "| ${d_ln} | \`${d_ts}\` | ${d_drift} | \`${d_excerpt}\` |"
        done
    fi
    echo
    echo "## Summary"
    echo
    echo "Structural violations:"
    echo "- ISO-8601 T...Z synthetic timestamps: **${iso_t_count}**"
    echo "- Same-second clusters (>= ${SAME_SEC_THRESHOLD} rows): **${cluster_count}**"
    echo "- Rows in same-second clusters: **${cluster_rows}**"
    echo "- Non-monotonic rows: **${nonmono_count}**"
    echo "- Unparseable rows: **${unparseable_count}**"
    echo
    echo "Informational:"
    echo "- Drift vs file mtime (> 24h): ${drift_info_count}"
    echo
    total=$(( iso_t_count + cluster_count + nonmono_count + unparseable_count ))
    if [[ "$total" -eq 0 ]]; then
        echo "**Verdict:** No structural integrity violations detected. Note: this scan checks structural consistency only — it does NOT prove the timestamps were emitted by \`audit.sh\` at the times they claim."
    else
        echo "**Verdict:** Suspect rows above warrant manual review. Future analysis on this case must re-emit \`forensic_audit.log\` entries via \`audit.sh\` only — direct \`>>\` / \`tee\` writes are denied at the harness level by the post-hardening PreToolUse hook."
    fi
} > "$REPORT"

echo "[audit-retrofit] report written to ${REPORT}"
echo "[audit-retrofit] iso-t=${iso_t_count} clusters=${cluster_count} nonmono=${nonmono_count} unparseable=${unparseable_count} drift-info=${drift_info_count}"
