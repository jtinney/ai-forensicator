#!/usr/bin/env bash
# zeek_suricata_parallel.sh — single-pass network-forensics baseline.
#
# Replaces the serial Tier-1 baseline (tshark cheap-signals → Zeek → Suricata)
# with a fan-out of independent subprocesses against the original pcap. The
# first reader warms the OS page cache; subsequent readers stream from RAM at
# memory bandwidth, so wall clock is bounded by the slowest single tool, not
# their sum. No fifo / tee plumbing — each tool opens the pcap directly via
# libpcap.
#
# What runs in parallel (when the corresponding tool is on PATH):
#   * zeek -C -r        — structured protocol logs         (./analysis/network/zeek/)
#   * suricata -r       — IDS alerts                       (./analysis/network/suricata/)
#   * tcpdump -w (×3)   — per-protocol slice pcaps         (./exports/network/slices/)
#
# After Zeek finishes:
#   * conn_to_flow_index.py — derive flow-index.csv from conn.log (cheap
#     IP-pair lookup for investigators; replaces a redundant tshark conv,ip
#     pass since Zeek already classifies every flow)
#
# This script does NOT run tshark in Tier-1. Zeek's dns.log / http.log /
# ssl.log already cover what the legacy 7-tshark cheap-signal block produced;
# adding tshark to the batch would be duplicate work. The Tier-2 fallback
# (`tshark_wide.py`) is documented in network-forensics/SKILL.md for hosts
# without Zeek installed.
#
# Forensic posture:
#   * Original pcap is opened read-only by every consumer. Never modified.
#   * Source pcap sha256 computed once at start; recorded in every audit row
#     that produces a derivative.
#   * Slice pcaps live under ./exports/network/slices/ — the existing
#     audit-exports.sh PostToolUse hook auto-hashes them into
#     analysis/exports-manifest.md (chain-of-custody, no extra code).
#   * Every step appends to ./analysis/forensic_audit.log via audit.sh
#     (direct >> writes are denied at hook level).
#
# Usage:
#   bash zeek_suricata_parallel.sh <pcap>
#   bash zeek_suricata_parallel.sh <pcap> [--skip-zeek] [--skip-suricata]
#                                        [--skip-slices]
#                                        [--out-analysis <dir>] [--out-exports <dir>]
#
# Exit codes:
#   0 — every requested step succeeded
#   1 — one or more required steps failed (see audit log + per-tool stderr)
#   2 — bad arguments / pcap missing / mandatory tool missing

set -u  # NOT -e: backgrounded tools may legitimately fail; we capture rc per-tool

# ─── argument parsing ────────────────────────────────────────────────────────
PCAP=""
SKIP_ZEEK=0; SKIP_SURICATA=0; SKIP_SLICES=0
OUT_ANALYSIS="./analysis/network"
OUT_EXPORTS="./exports/network"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-zeek)     SKIP_ZEEK=1 ;;
        --skip-suricata) SKIP_SURICATA=1 ;;
        --skip-slices)   SKIP_SLICES=1 ;;
        --out-analysis)  OUT_ANALYSIS="$2"; shift ;;
        --out-exports)   OUT_EXPORTS="$2";  shift ;;
        -h|--help)
            sed -n '/^# Usage:/,/^# Exit codes:/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*)
            echo "unknown flag: $1" >&2; exit 2 ;;
        *)
            if [[ -z "$PCAP" ]]; then PCAP="$1"
            else echo "unexpected positional arg: $1" >&2; exit 2
            fi ;;
    esac
    shift
done

if [[ -z "$PCAP" ]]; then
    echo "usage: zeek_suricata_parallel.sh <pcap> [flags]" >&2
    exit 2
fi
if [[ ! -f "$PCAP" ]]; then
    echo "pcap not found: $PCAP" >&2; exit 2
fi

# Resolve to absolute path so the Zeek subshell (which cd's into the zeek dir)
# can still find the source.
PCAP_ABS="$(readlink -f "$PCAP")"

# ─── locate audit.sh + sibling parsers ───────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SH="${SCRIPT_DIR}/../../dfir-bootstrap/audit.sh"
CONN_FLOW_INDEX="${SCRIPT_DIR}/conn_to_flow_index.py"
if [[ ! -x "$AUDIT_SH" && ! -f "$AUDIT_SH" ]]; then
    echo "audit.sh not found at $AUDIT_SH" >&2; exit 2
fi
audit() { bash "$AUDIT_SH" "$1" "$2" "$3" >/dev/null; }

# ─── output dirs ─────────────────────────────────────────────────────────────
ZEEK_DIR="${OUT_ANALYSIS}/zeek"
SURICATA_DIR="${OUT_ANALYSIS}/suricata"
SLICE_DIR="${OUT_EXPORTS}/slices"
LOG_DIR="${OUT_ANALYSIS}/_parallel_logs"
mkdir -p "$ZEEK_DIR" "$SURICATA_DIR" "$SLICE_DIR" "$LOG_DIR" "$OUT_ANALYSIS"

# ─── source pcap hash (once) ─────────────────────────────────────────────────
PCAP_SHA="$(sha256sum "$PCAP_ABS" | awk '{print $1}')"
PCAP_SIZE="$(stat -c %s "$PCAP_ABS" 2>/dev/null || stat -f %z "$PCAP_ABS")"

audit "zeek_suricata_parallel.sh start" \
      "src=$PCAP_ABS sha256=$PCAP_SHA size=$PCAP_SIZE" \
      "fan-out zeek/suricata/slices; wait"

# ─── tool presence check ─────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }

if (( ! SKIP_ZEEK ))     && ! have zeek;     then SKIP_ZEEK=1;     audit "skip zeek"   "zeek not on PATH (Tier-2 fallback: run tshark_wide.py manually)" "consider install-tools.sh"; fi
if (( ! SKIP_SURICATA )) && ! have suricata; then SKIP_SURICATA=1; audit "skip suricata" "suricata not on PATH" "consider apt install suricata"; fi
if (( ! SKIP_SLICES ))   && ! have tcpdump;  then SKIP_SLICES=1;   audit "skip slices" "tcpdump not on PATH" "consider apt install tcpdump"; fi

# ─── slice definitions ───────────────────────────────────────────────────────
# name|filename|BPF filter — keep filters narrow and well-known so reviewers
# can re-run the same slice from the source pcap deterministically.
SLICES=(
    "dns|dns.pcap|port 53 or port 5353"
    "http|http.pcap|tcp port 80 or tcp port 8080 or tcp port 8000"
    "tls|tls.pcap|tcp port 443 or tcp port 8443"
)

# ─── launch parallel jobs ────────────────────────────────────────────────────
declare -A PIDS=()    # job_name -> pid
declare -A LOGS=()    # job_name -> log path
declare -A RCS=()     # job_name -> exit code

launch() {
    local name="$1"; shift
    local logf="${LOG_DIR}/${name}.log"
    LOGS[$name]="$logf"
    ( "$@" ) >"$logf" 2>&1 &
    PIDS[$name]=$!
}

if (( ! SKIP_ZEEK )); then
    # zeek writes logs to cwd; isolate by cd-ing into the zeek output dir.
    launch "zeek" bash -c "cd '$ZEEK_DIR' && zeek -C -r '$PCAP_ABS'"
fi

if (( ! SKIP_SURICATA )); then
    SURICATA_CONF=""
    if [[ -f /etc/suricata/suricata.yaml ]]; then
        SURICATA_CONF="-c /etc/suricata/suricata.yaml"
    fi
    # shellcheck disable=SC2086
    launch "suricata" bash -c "suricata -r '$PCAP_ABS' -l '$SURICATA_DIR' -k none $SURICATA_CONF"
fi

if (( ! SKIP_SLICES )); then
    for entry in "${SLICES[@]}"; do
        IFS='|' read -r sname sfile sfilter <<< "$entry"
        sout="${SLICE_DIR}/${sfile}"
        launch "slice_${sname}" tcpdump -r "$PCAP_ABS" -w "$sout" "$sfilter"
    done
fi

if [[ ${#PIDS[@]} -eq 0 ]]; then
    audit "zeek_suricata_parallel.sh end" \
          "no jobs launched (every tool skipped)" \
          "install missing tools or drop --skip flags"
    exit 1
fi

# ─── wait ────────────────────────────────────────────────────────────────────
for name in "${!PIDS[@]}"; do
    pid="${PIDS[$name]}"
    wait "$pid"
    RCS[$name]=$?
done

# ─── audit per-job + slice hashes ────────────────────────────────────────────
overall_rc=0
for name in "${!RCS[@]}"; do
    rc="${RCS[$name]}"
    log="${LOGS[$name]}"
    last_err="$(tail -n 3 "$log" 2>/dev/null | tr '\n' ';' | head -c 240)"
    if [[ "$rc" -eq 0 ]]; then
        case "$name" in
            slice_*)
                sname="${name#slice_}"
                # Find the produced file
                for entry in "${SLICES[@]}"; do
                    IFS='|' read -r en ef ebpf <<< "$entry"
                    if [[ "$en" == "$sname" ]]; then
                        sout="${SLICE_DIR}/${ef}"
                        if [[ -f "$sout" ]]; then
                            ssha="$(sha256sum "$sout" | awk '{print $1}')"
                            ssize="$(stat -c %s "$sout" 2>/dev/null || stat -f %z "$sout")"
                            # capinfos -c surfaces zero-packet slices that
                            # would otherwise look successful (tcpdump exits
                            # 0 even when the BPF matched nothing — file is
                            # the 24-byte global header alone).
                            if command -v capinfos >/dev/null 2>&1; then
                                spkts="$(capinfos -c "$sout" 2>/dev/null | awk -F': ' '/Number of packets/ {gsub(/[ ,]/,"",$2); print $2; exit}')"
                                spkts="${spkts:-?}"
                            else
                                spkts="?"
                            fi
                            audit "tcpdump slice ${sname}" \
                                  "src_sha256=$PCAP_SHA bpf=\"$ebpf\" out=$sout packets=$spkts out_sha256=$ssha out_size=$ssize" \
                                  "investigators read $sout instead of original"
                        else
                            audit "tcpdump slice ${sname}" \
                                  "src_sha256=$PCAP_SHA bpf=\"$ebpf\" rc=0 but $sout missing" \
                                  "investigate $log"
                            overall_rc=1
                        fi
                    fi
                done
                ;;
            *)
                audit "$name parallel ok" \
                      "src_sha256=$PCAP_SHA log=$log" \
                      "downstream consumes ${OUT_ANALYSIS}"
                ;;
        esac
    else
        audit "$name parallel FAIL" \
              "src_sha256=$PCAP_SHA rc=$rc tail=$last_err" \
              "re-run serially or check $log"
        overall_rc=1
    fi
done

# ─── post-step: derive flow-index.csv from Zeek conn.log ─────────────────────
# Zeek classifies every flow with full protocol/service context, so a
# Zeek-derived flow index is more accurate than an ASCII-table parse of
# tshark's `-z conv,ip` output. This step is post-Zeek (not parallel) because
# it consumes Zeek's output; it is fast (single TSV scan, no pcap re-read).
ZEEK_RC="${RCS[zeek]:-1}"
CONN_LOG="${ZEEK_DIR}/conn.log"
FLOW_INDEX="${OUT_ANALYSIS}/flow-index.csv"
FLOW_LOG="${LOG_DIR}/flow_index.log"
if (( ! SKIP_ZEEK )) && [[ "$ZEEK_RC" -eq 0 && -f "$CONN_LOG" ]]; then
    if python3 "$CONN_FLOW_INDEX" "$CONN_LOG" --out "$FLOW_INDEX" \
            > "$FLOW_LOG" 2>&1; then
        flow_sha="$(sha256sum "$FLOW_INDEX" 2>/dev/null | awk '{print $1}')"
        flow_rows="$(grep -c '^"' "$FLOW_INDEX" 2>/dev/null || echo 0)"
        # First row is the header (also starts with " when QUOTE_ALL); subtract.
        (( flow_rows > 0 )) && flow_rows=$(( flow_rows - 1 ))
        audit "conn_to_flow_index.py" \
              "src_pcap_sha256=$PCAP_SHA src=$CONN_LOG out=$FLOW_INDEX rows=$flow_rows out_sha256=$flow_sha" \
              "investigators read flow-index.csv for cheap IP-pair lookups"
    else
        audit "conn_to_flow_index.py FAIL" \
              "src_pcap_sha256=$PCAP_SHA src=$CONN_LOG see $FLOW_LOG" \
              "re-run conn_to_flow_index.py manually"
        overall_rc=1
    fi
elif (( ! SKIP_ZEEK )); then
    audit "conn_to_flow_index.py skipped" \
          "src_pcap_sha256=$PCAP_SHA zeek rc=$ZEEK_RC conn.log=$([[ -f $CONN_LOG ]] && echo present || echo missing)" \
          "investigate ${LOGS[zeek]:-zeek log missing}"
fi

audit "zeek_suricata_parallel.sh end" \
      "overall_rc=$overall_rc jobs=${#PIDS[@]} src_sha256=$PCAP_SHA" \
      "downstream: zeek_triage.py / suricata_eve.py / conn_beacon.py"

exit "$overall_rc"
