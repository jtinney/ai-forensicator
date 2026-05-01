#!/usr/bin/env bash
# DFIR case scaffold — idempotent; safe to re-run.
# Creates ./analysis, ./exports, ./reports with the layout every skill expects
# and seeds forensic_audit.log with a header. Does NOT pre-create findings.md
# files: the surveyor and investigator phases write them on first append, so an
# empty / missing findings.md unambiguously means "no analyst output yet."
#
# Layout: this project uses a master `cases/` directory; each case lives
# under `cases/<CASE_ID>/` with its own `evidence/`, `analysis/`, `exports/`,
# `reports/`. case-init.sh auto-resolves the case dir under the project root
# (located via $CLAUDE_PROJECT_DIR or by walking up for a `.claude/` marker)
# and cd's into it before scaffolding. Run from anywhere inside the project;
# the script does the right thing.

set -u

CASE_ID="${1:-UNSET}"
UTC_NOW="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"

if [[ "$CASE_ID" == "UNSET" ]]; then
    echo "usage: case-init.sh <CASE_ID>" >&2
    echo "       CASE_ID is any free-form case identifier (e.g. 2020JimmyWilson, INC-2026-042)" >&2
    exit 2
fi

# ---------- project root + case dir resolution ----------
# Resolve the location of THIS script (and its sibling helpers) BEFORE any
# cd, otherwise relative $BASH_SOURCE lookups break once we move into the
# case dir. SCRIPT_DIR is the canonical install path of the bootstrap skill.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"

# Find the project root (where .claude/ lives). Prefer CLAUDE_PROJECT_DIR
# when set by the harness; otherwise walk up from CWD looking for .claude/.
if [[ -n "${CLAUDE_PROJECT_DIR:-}" && -d "${CLAUDE_PROJECT_DIR}/.claude" ]]; then
    PROJECT_ROOT="$CLAUDE_PROJECT_DIR"
else
    PROJECT_ROOT="$(pwd)"
    while [[ "$PROJECT_ROOT" != "/" && ! -d "$PROJECT_ROOT/.claude" ]]; do
        PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
    done
fi

# When the project has a cases/ master directory (the standard layout for this
# repo), every case lives under cases/<CASE_ID>/. Resolve and cd there before
# scaffolding so all the relative paths below land inside the case workspace.
# Backward-compat: if neither cases/ nor .claude/ is present at PROJECT_ROOT,
# fall back to the legacy "CWD IS the case dir" mode.
if [[ -d "${PROJECT_ROOT}/.claude" ]]; then
    CASE_DIR="${PROJECT_ROOT}/cases/${CASE_ID}"
    mkdir -p "${CASE_DIR}/evidence"
    cd "${CASE_DIR}" || { echo "[case-init] cannot enter ${CASE_DIR}" >&2; exit 1; }
fi

echo "[case-init] Case:    $CASE_ID"
echo "[case-init] Project: $PROJECT_ROOT"
echo "[case-init] Workdir: $(pwd)"
echo "[case-init] UTC:     $UTC_NOW"

# ---------- directory tree ----------
dirs=(
    "./analysis"
    "./analysis/filesystem"
    "./analysis/timeline"
    "./analysis/windows-artifacts"
    "./analysis/windows-artifacts/hives"
    "./analysis/windows-artifacts/evtx"
    "./analysis/windows-artifacts/prefetch"
    "./analysis/windows-artifacts/recyclebin"
    "./analysis/windows-artifacts/lnk"
    "./analysis/windows-artifacts/mft"
    "./analysis/memory"
    "./analysis/network"
    "./analysis/network/zeek"
    "./analysis/network/suricata"
    "./analysis/yara"
    "./analysis/sigma"
    "./analysis/sigma/jsonl"
    "./analysis/sigma/hits"
    "./analysis/_extracted"
    "./exports"
    # Canonical exports/ taxonomy — see dfir-discipline/DISCIPLINE.md
    # "Layer model" subsection. Pre-scaffolded so domain skills do not
    # race against audit-exports.sh's depth-unbounded find walk on
    # lazy-mkdir. Filename-encoding (artifact-EVID.ext) is the default
    # for multi-evidence cases per Rule L; per-EVID subdirs are the
    # required exception for tools that emit directory trees.
    "./exports/files"
    "./exports/carved"
    "./exports/yara_hits"
    "./exports/sigma_hits"
    "./exports/evtx"
    "./exports/evtx/parsed"
    "./exports/evtx/xml"
    "./exports/registry"
    "./exports/shimcache"
    "./exports/prefetch"
    "./exports/amcache"
    "./exports/mft"
    "./exports/srum"
    "./exports/shellbags"
    "./exports/jumplists"
    "./exports/lnk"
    "./exports/recyclebin"
    "./exports/browser"
    "./exports/browser/parsed"
    "./exports/WindowsTimeline"
    "./exports/dumpfiles"
    "./exports/malfind"
    "./exports/memdump"
    "./exports/network"
    "./exports/network/slices"
    "./exports/network/carved"
    "./exports/network/http_objects"
    "./exports/network/tcpflow"
    "./exports/network/streams"
    "./exports/tsk_recover"
    "./reports"
)

for d in "${dirs[@]}"; do
    mkdir -p "$d"
done
echo "[case-init] directory tree OK"

# ---------- audit log ----------
AUDIT="./analysis/forensic_audit.log"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"
if [[ ! -f "$AUDIT" ]]; then
    # Fresh case: write a clean canonical header and a single open-of-case row.
    # Do NOT carry over noise from prior `claude` sessions in the same dir —
    # if those exist they are not part of this case's chain of custody.
    cat > "$AUDIT" <<EOF
# Forensic audit log — $CASE_ID
# Format: <UTC timestamp> | <action> | <finding/result> | <next step>
# Initialized: $UTC_NOW
# Append ONLY via: bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next>"
# Direct >>, tee -a, sed -i, cp, mv, python open() are denied at the harness level.
EOF
    bash "$AUDIT_SH" "case-init" "scaffold created for $CASE_ID" "run preflight.sh + intake interview" >/dev/null 2>&1 \
        || echo "$UTC_NOW | case-init | scaffold created for $CASE_ID | run preflight.sh + intake interview" >> "$AUDIT"
    echo "[case-init] forensic_audit.log initialized (clean)"
else
    # Pre-existing log: do not modify history. If the log carries pre-case
    # noise (entries dated before this scaffold), archive it so chain-of-
    # custody for THIS case starts here. Detect by reading the first
    # timestamp; if older than 24h before the scaffold, archive.
    first_ts="$(grep -m1 -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC' "$AUDIT" 2>/dev/null || true)"
    if [[ -n "$first_ts" ]]; then
        first_epoch="$(date -u -d "$first_ts" +%s 2>/dev/null || echo 0)"
        now_epoch="$(date -u +%s)"
        gap_h=$(( (now_epoch - first_epoch) / 3600 ))
        if [[ "$first_epoch" -gt 0 && "$gap_h" -gt 24 ]]; then
            archive="${AUDIT}.pre-${CASE_ID}.archive"
            cp "$AUDIT" "$archive" 2>/dev/null && {
                cat > "$AUDIT" <<EOF
# Forensic audit log — $CASE_ID
# Format: <UTC timestamp> | <action> | <finding/result> | <next step>
# Re-initialized: $UTC_NOW (prior log archived to $(basename "$archive"))
# Append ONLY via: bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next>"
EOF
                bash "$AUDIT_SH" "case-init" "scaffold re-initialized for $CASE_ID; pre-case noise archived to $(basename "$archive")" "continue analysis" >/dev/null 2>&1 || true
                echo "[case-init] pre-case audit log archived to $(basename "$archive")"
            }
        else
            bash "$AUDIT_SH" "case-init" "scaffold re-verified for $CASE_ID" "continue prior analysis" >/dev/null 2>&1 \
                || echo "$UTC_NOW | case-init | scaffold re-verified for $CASE_ID | continue prior analysis" >> "$AUDIT"
            echo "[case-init] forensic_audit.log already existed — appended re-init entry"
        fi
    fi
fi

# ---------- evidence bundle expansion + per-member hashing ----------
# When ./evidence/ contains an archive (zip/tar/tar.gz/tar.bz2/7z), expand it
# under ./analysis/_extracted/<basename>/ so analytic units (each member) can
# be hashed and tracked individually. Idempotent: skips if dest non-empty.
# Disk-bounded: skips if estimated expanded size > 50% of free disk.
#
# Issue #4 — BULK_EXTRACT gate. When triage's extraction-plan.sh returns
# `mode: sequential` (combined decompressed estimate exceeds free disk), the
# triage agent invokes us with BULK_EXTRACT=0; the bundle-expansion loop then
# records the bundle's hash + a `bundle:<kind>` manifest row but skips the
# unzip/tar/7z expansion and per-member hashing. The orchestrator drives
# extract->survey->investigate->cleanup->next-stage cycles per the plan.
# Default (unset/non-zero) preserves the legacy bulk-extract behaviour so
# direct `case-init.sh` calls outside the orchestrator remain unchanged.
BULK_EXTRACT="${BULK_EXTRACT:-1}"
EVIDENCE_DIR="./evidence"
EXTRACT_DIR="./analysis/_extracted"
MANIFEST="./analysis/manifest.md"

# Initialize manifest.md (header) if not already present. Triage may also
# write to it; case-init seeds the header so per-bundle expansion can append.
if [[ ! -f "$MANIFEST" ]]; then
    cat > "$MANIFEST" <<EOF
# Evidence Manifest — $CASE_ID

| evidence_id | filename | path | type | size | sha256 | parent | notes |
|---|---|---|---|---|---|---|---|
EOF
    echo "[case-init] manifest.md initialized"
fi

# Helper: human-readable size
hsize() { local b="$1"; numfmt --to=iec --suffix=B "$b" 2>/dev/null || echo "${b}B"; }

# Helper: estimate compressed-archive expanded size (best-effort)
estimate_expanded_size() {
    local arch="$1"; local kind="$2"
    case "$kind" in
        zip)        unzip -l "$arch" 2>/dev/null | awk 'END{print $1+0}' ;;
        gzip-tar|tar) tar -tvf "$arch" 2>/dev/null | awk '{s+=$3} END{print s+0}' ;;
        7z)         7z l "$arch" 2>/dev/null | awk '/^[0-9]/ {s+=$4} END{print s+0}' ;;
        *)          echo 0 ;;
    esac
}

# Helper: append manifest row
append_manifest_row() {
    local ev_id="$1" fname="$2" fpath="$3" ftype="$4" fsize="$5" fsha="$6" parent="$7" notes="$8"
    # Escape pipes in any user-derived field
    fname="${fname//|/\\|}"; fpath="${fpath//|/\\|}"; notes="${notes//|/\\|}"
    printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n" \
        "$ev_id" "$fname" "$fpath" "$ftype" "$(hsize "$fsize")" "$fsha" "$parent" "$notes" \
        >> "$MANIFEST"
}

# Helper: ensure ./analysis/leads.md exists with the canonical 8-column header.
# leads.md is normally created by dfir-triage step 7, but case-init.sh runs
# BEFORE triage and may need to record BLOCKED leads (L-EVIDENCE-EMPTY-NN,
# L-EXTRACT-DISK-NN, L-EXTRACT-FAIL-NN) when bundle expansion fails. Header
# shape mirrors extraction-plan.sh and dfir-triage.md so leads-check.sh
# parses it cleanly.
LEADS="./analysis/leads.md"
ensure_leads_md() {
    if [[ ! -f "$LEADS" ]]; then
        mkdir -p ./analysis
        cat > "$LEADS" <<'EOF'
| lead_id | evidence_id | domain | hypothesis | pointer | priority | status | notes |
|---------|-------------|--------|------------|---------|----------|--------|-------|
EOF
    fi
}

# Helper: pick the next L-<PREFIX>-NN id given a numeric prefix.
# Reuses the pattern extraction-plan.sh uses for L-EXTRACT-DISK-NN: walk
# leads.md, find the highest existing N for this prefix, return N+1
# zero-padded to 2 digits. Idempotent — re-running with the same hypothesis
# string is de-duped by the caller via grep -F before append.
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

# Helper: append a BLOCKED lead row, idempotent on hypothesis match.
# Echoes the lead id of the row (newly written or pre-existing) so callers
# can include it in their stderr message and audit row.
append_blocked_lead() {
    local prefix="$1" ev_id="$2" hypothesis="$3" pointer="$4" notes="$5"
    ensure_leads_md
    # Escape pipes in user-derived fields so the table parses cleanly
    local hyp_safe="${hypothesis//|/\\|}"
    local notes_safe="${notes//|/\\|}"
    if grep -qF "$hyp_safe" "$LEADS" 2>/dev/null; then
        # Already recorded — surface the existing lead id rather than
        # double-appending. Pull the first L-<PREFIX>-NN id from the row
        # whose hypothesis matches.
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

# Determine next EV slot from existing manifest rows
next_ev_id() {
    local last
    last=$(grep -oE '^\| EV[0-9]{2,}' "$MANIFEST" 2>/dev/null \
            | grep -oE 'EV[0-9]+' | sed 's/EV//' | sort -n | tail -1)
    if [[ -z "$last" ]]; then echo "EV01"
    else printf "EV%02d" $((10#$last + 1))
    fi
}

if [[ -d "$EVIDENCE_DIR" ]]; then
    # ---- evidence directory hardening ----
    # Strip write permission from every evidence file and the directory
    # itself BEFORE we walk it. This is belt-and-suspenders: the
    # PreToolUse hook denies write attempts at the harness level, and the
    # filesystem itself denies them at the kernel level. Combined, an
    # accidental `>` redirect or `mv` cannot mutate evidence.
    #
    # Owner can still re-add write with `chmod u+w` if a legitimate
    # custodial action requires it (re-acquisition, evidence return).
    # But no agent operating under default permissions can mutate a file.
    #
    # Idempotent: skips if mode is already locked.
    chmod -R a-w "$EVIDENCE_DIR" 2>/dev/null || true
    chmod a-w "$EVIDENCE_DIR" 2>/dev/null || true
    bash "$AUDIT_SH" "case-init evidence-lock" \
        "stripped write bits from $EVIDENCE_DIR (a-w on dir + recursive)" \
        "chmod u+w only with documented chain-of-custody justification" >/dev/null 2>&1 || true
    echo "[case-init] $EVIDENCE_DIR locked read-only (a-w)"

    # Use a NUL-delimited, DEPTH-UNBOUNDED sweep of evidence/. Issue #12
    # root cause: the prior `-maxdepth 1` only saw immediate children of
    # evidence/, so `evidence/Archives/*.zip` (case12 layout) was silently
    # skipped — the loop iterated over the directory entry, [[ -f ]] failed,
    # and case-init exited with an empty manifest. Walk every regular file
    # at any depth; ignore directories. Sort the listing so re-runs produce
    # deterministic EV-id assignments (matching extraction-plan.sh).
    # grep -c exits non-zero when no matches, so wrap with `|| true` and
    # default the empty string to 0 — chaining `|| echo 0` would emit
    # "0\n0" (grep's own zero count + the fallback) which then breaks the
    # numeric -eq comparison below.
    EVID_ROWS_BEFORE=$(grep -cE '^\| EV[0-9]{2,}' "$MANIFEST" 2>/dev/null || true)
    EVID_ROWS_BEFORE="${EVID_ROWS_BEFORE:-0}"
    rows_appended_this_run=0
    walk_count=0

    # Track the path strings already-manifested so the idempotency check
    # below can match against either the absolute form or the
    # relative-from-evidence form. The pre-#12 rows used the absolute form
    # (./evidence/foo.zip); the new rows use the relative form
    # (Archives/foo.zip). Both must be honored to avoid double-listing.

    mapfile -d '' all_evidence_files < <(find "$EVIDENCE_DIR" -mindepth 1 -type f -print0 2>/dev/null \
                                          | LC_ALL=C sort -z)

    for f in "${all_evidence_files[@]}"; do
        [[ -f "$f" ]] || continue
        walk_count=$((walk_count + 1))

        bn="$(basename "$f")"
        [[ "${bn:0:1}" == "." ]] && continue

        # Relative-from-evidence/ form for traceability across deep layouts.
        # e.g. ./evidence/Archives/sample.zip -> Archives/sample.zip.
        rel_path="${f#"${EVIDENCE_DIR}"/}"
        rel_path="${rel_path#./}"

        # Skip if already manifested (idempotent re-run). Match against
        # either the relative form (new) or the absolute-with-dot form (old)
        # so a re-run after the depth-walk fix doesn't duplicate rows from
        # cases scaffolded under the old layout.
        if grep -qF "| ${rel_path} |" "$MANIFEST" 2>/dev/null \
           || grep -qF "| ${f} |" "$MANIFEST" 2>/dev/null; then
            continue
        fi

        size=$(stat -c%s "$f" 2>/dev/null || echo 0)
        sha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
        ftype_raw=$(file -b "$f" 2>/dev/null || echo unknown)

        # Classify archive type for expansion routing
        kind=""
        case "$ftype_raw" in
            *"Zip archive"*)              kind="zip" ;;
            *"7-zip archive"*)            kind="7z" ;;
            *"gzip compressed"*)
                # only auto-extract gz wrapping a tar
                if file -b "$f" 2>/dev/null | grep -q 'tar archive' \
                   || tar -tzf "$f" >/dev/null 2>&1; then
                    kind="gzip-tar"
                fi ;;
            *"POSIX tar"*|*"tar archive"*) kind="tar" ;;
        esac

        ev_id=$(next_ev_id)

        if [[ -n "$kind" ]]; then
            # Expansion dest. Strip the (possibly secondary) extension for
            # .tar.gz / .tar.bz2 so the dest dir name is human-readable.
            dest_subdir="${bn%.*}"
            [[ "$dest_subdir" == *.tar ]] && dest_subdir="${dest_subdir%.tar}"
            dest="${EXTRACT_DIR}/${dest_subdir}"
            mkdir -p "$dest"

            # Issue #4 BULK_EXTRACT=0 path. The extraction planner has decided
            # the case runs sequentially (sum exceeds free disk). Record the
            # bundle's intake hash + a deferred bundle row, but DO NOT expand
            # or hash members. The orchestrator stages archives one at a time.
            if [[ "$BULK_EXTRACT" == "0" ]]; then
                append_manifest_row "$ev_id" "$bn" "$rel_path" "bundle:${kind}" "$size" "$sha" "-" "expansion deferred (sequential mode per extraction-plan.md)"
                rows_appended_this_run=$((rows_appended_this_run + 1))
                bash "$AUDIT_SH" "case-init bundle-deferred" \
                    "BULK_EXTRACT=0; recorded $ev_id ($bn) intake hash without expansion" \
                    "orchestrator stages archive per extraction-plan.md" >/dev/null 2>&1 || true
                continue
            fi

            # Idempotency tightening (issue #12): if the dest dir already
            # contains files, cross-check the on-disk member count against
            # the bundle-member rows already in manifest.md for this ev_id.
            # Mismatch (partial extraction from a prior failed run) =
            # poisoned dest — refuse to re-use it and halt with an
            # actionable message. Operator clears the dir and re-runs.
            if [[ -n "$(ls -A "$dest" 2>/dev/null)" ]]; then
                disk_member_count=$(find "$dest" -type f 2>/dev/null | wc -l)
                # Resolve which ev_id (if any) already owns this dest by
                # matching the absolute dest path in the manifest's notes
                # column on prior bundle rows. If no prior bundle row
                # references this dest, then bytes are present without a
                # custodial trail — refuse.
                prior_ev=$(grep -F "| bundle:" "$MANIFEST" 2>/dev/null \
                           | grep -F "${dest}" \
                           | grep -oE '^\| EV[0-9]+' | head -1 | tr -d '| ')
                manifest_member_count=0
                if [[ -n "$prior_ev" ]]; then
                    manifest_member_count=$(grep -cE "^\| ${prior_ev}-M[0-9]+ \| " "$MANIFEST" 2>/dev/null || echo 0)
                fi
                if [[ "$disk_member_count" -ne "$manifest_member_count" ]] \
                   || [[ -z "$prior_ev" ]]; then
                    bash "$AUDIT_SH" "case-init bundle-poisoned" \
                        "$dest_subdir: on-disk members=${disk_member_count} but manifest bundle-member rows=${manifest_member_count} for prior_ev='${prior_ev:-none}'" \
                        "operator: rm -rf $dest then re-run case-init" >/dev/null 2>&1 || true
                    lid=$(append_blocked_lead "L-EXTRACT-POISON" "$ev_id" \
                        "Partial-expansion poison at ${dest}: on-disk member count (${disk_member_count}) does not match manifest rows (${manifest_member_count})" \
                        "analysis/manifest.md" \
                        "operator: rm -rf ${dest} and re-run case-init.sh; preserve prior manifest rows for forensic record")
                    echo "[case-init] HALT — bundle ${dest_subdir} is poisoned (partial prior extraction)" >&2
                    echo "[case-init]   on-disk members=${disk_member_count}, manifest rows=${manifest_member_count}" >&2
                    echo "[case-init]   logged BLOCKED lead ${lid}; clear ${dest} and re-run" >&2
                    exit 1
                fi
                echo "[case-init] $bn already expanded at $dest (idempotent skip; ${disk_member_count} members)"
            else
                # Disk safety guard. The combined-corpus case is owned by
                # extraction-plan.sh (which writes BLOCKED leads at plan
                # time when the largest-archive doesn't fit). This per-
                # archive 50%-of-free check is the LAST-resort guard for
                # callers that bypassed the planner (legacy direct
                # `case-init.sh` invocations). When BULK_EXTRACT=1 (the
                # default) AND the estimate exceeds 50% of free disk,
                # halt — silent-skip with `sha256 = -` is the case12
                # silent-skip foot-gun this rewrite eliminates.
                avail_kb=$(df --output=avail "$dest" 2>/dev/null | tail -1)
                avail_b=$(( avail_kb * 1024 ))
                est_b=$(estimate_expanded_size "$f" "$kind")
                # Test knob: CASE_INIT_FORCE_DISK_PRESSURE=1 forces the
                # disk-pressure halt path regardless of actual free space.
                # Used by the issue #12 regression suite under /tmp/. Has
                # no effect when BULK_EXTRACT=0 (sequential mode bypasses
                # the per-archive halt — extraction-plan.sh owns the
                # combined-corpus disk check).
                force_dp="${CASE_INIT_FORCE_DISK_PRESSURE:-0}"
                triggered_dp=0
                if [[ "$BULK_EXTRACT" != "0" \
                      && "$force_dp" == "1" ]]; then
                    triggered_dp=1
                elif [[ "$BULK_EXTRACT" != "0" \
                      && "$est_b" -gt 0 \
                      && "$avail_b" -gt 0 \
                      && "$est_b" -gt $(( avail_b / 2 )) ]]; then
                    triggered_dp=1
                fi
                if [[ "$triggered_dp" -eq 1 ]]; then
                    deficit=$(( est_b - (avail_b / 2) ))
                    hyp="Disk-pressure halt: ${rel_path} estimated $(hsize "$est_b") exceeds 50% of free $(hsize "$avail_b")"
                    notes="required-free-space-delta=$(hsize "$deficit") (${deficit} bytes); free disk and re-run, OR run extraction-plan.sh + invoke case-init.sh with BULK_EXTRACT=0 for sequential mode"
                    lid=$(append_blocked_lead "L-EXTRACT-DISK" "$ev_id" "$hyp" \
                        "analysis/manifest.md" "$notes")
                    bash "$AUDIT_SH" "case-init bundle-blocked" \
                        "halt $bn — estimated $(hsize "$est_b") > 50% of $(hsize "$avail_b") free; lead=${lid}" \
                        "free disk and re-run, OR run extraction-plan.sh for sequential mode" >/dev/null 2>&1 || true
                    echo "[case-init] HALT — disk pressure on $bn" >&2
                    echo "[case-init]   estimated expand=$(hsize "$est_b"), free=$(hsize "$avail_b"), 50% threshold=$(hsize "$(( avail_b / 2 ))")" >&2
                    echo "[case-init]   logged BLOCKED lead ${lid}; resolution paths in $LEADS" >&2
                    exit 1
                fi

                # Expand. Capture stderr so a halt records the failing
                # tool's actual error message rather than a generic
                # "WARN: tar failed" (issue #12 acceptance).
                extract_err=""
                case "$kind" in
                    zip)
                        if ! extract_err=$(unzip -q "$f" -d "$dest" 2>&1 >/dev/null); then
                            tool="unzip"
                        else
                            tool=""
                        fi ;;
                    gzip-tar)
                        if ! extract_err=$(tar -xzf "$f" -C "$dest" 2>&1 >/dev/null); then
                            tool="tar -xzf"
                        else
                            tool=""
                        fi ;;
                    tar)
                        if ! extract_err=$(tar -xf "$f" -C "$dest" 2>&1 >/dev/null); then
                            tool="tar -xf"
                        else
                            tool=""
                        fi ;;
                    7z)
                        if ! extract_err=$(7z x -y -bb0 -bd -o"$dest" "$f" 2>&1 >/dev/null); then
                            tool="7z x"
                        else
                            tool=""
                        fi ;;
                esac
                if [[ -n "$tool" ]]; then
                    # Trim the captured stderr to a single line for the
                    # leads.md notes column. Full stderr is preserved in
                    # the audit log row.
                    err_oneline="$(printf '%s' "$extract_err" | tr '\n' ' ' | sed -e 's/  */ /g' -e 's/^ //' -e 's/ $//')"
                    err_short="${err_oneline:0:240}"
                    hyp="Extraction failure on ${rel_path}: ${tool} returned non-zero"
                    notes="stderr=${err_short}; operator: investigate archive integrity (was sha256=${sha}); rm -rf ${dest} before retrying"
                    lid=$(append_blocked_lead "L-EXTRACT-FAIL" "$ev_id" "$hyp" \
                        "analysis/manifest.md" "$notes")
                    bash "$AUDIT_SH" "case-init bundle-error" \
                        "$tool failed for $rel_path: $err_oneline" \
                        "investigate archive corruption; lead=${lid}" >/dev/null 2>&1 || true
                    echo "[case-init] HALT — extraction failed for $rel_path ($tool)" >&2
                    echo "[case-init]   stderr: $err_oneline" >&2
                    echo "[case-init]   logged BLOCKED lead ${lid}" >&2
                    exit 1
                fi
                echo "[case-init] expanded $bn -> $dest"
            fi

            # Manifest the bundle itself
            append_manifest_row "$ev_id" "$bn" "$rel_path" "bundle:${kind}" "$size" "$sha" "-" "expanded to $dest"
            rows_appended_this_run=$((rows_appended_this_run + 1))

            # Manifest each member (depth-unbounded; bundle members analytic units)
            mi=0
            while IFS= read -r -d '' m; do
                [[ -d "$m" ]] && continue
                mi=$((mi + 1))
                m_id=$(printf "%s-M%03d" "$ev_id" "$mi")
                m_size=$(stat -c%s "$m" 2>/dev/null || echo 0)
                m_sha=$(sha256sum "$m" 2>/dev/null | awk '{print $1}')
                m_bn="$(basename "$m")"
                append_manifest_row "$m_id" "$m_bn" "$m" "bundle-member" "$m_size" "$m_sha" "$ev_id" ""
                rows_appended_this_run=$((rows_appended_this_run + 1))
            done < <(find "$dest" -type f -print0 2>/dev/null)

            bash "$AUDIT_SH" "case-init bundle-expand" \
                "expanded $ev_id ($bn) to $mi member(s) under $dest" \
                "surveyor reads manifest.md for bundle-member rows" >/dev/null 2>&1 || true
        else
            # Plain blob — just hash and manifest
            append_manifest_row "$ev_id" "$bn" "$rel_path" "blob" "$size" "$sha" "-" "$ftype_raw"
            rows_appended_this_run=$((rows_appended_this_run + 1))
            bash "$AUDIT_SH" "case-init blob-hash" \
                "hashed $ev_id ($bn) sha256=${sha}" \
                "surveyor classifies and proceeds per dfir-triage protocol" >/dev/null 2>&1 || true
        fi
    done

    # Empty-walk hard fail (issue #12). If walk_count is 0 (no regular
    # files at any depth under evidence/) AND no manifest rows exist for
    # this case yet, treat as misconfigured: write L-EVIDENCE-EMPTY-NN
    # BLOCKED lead and exit 1. Re-runs after a manifest already has
    # EV rows (idempotent skip for every file) do NOT trigger this —
    # walk_count > 0 even when no rows are appended this run.
    if [[ "$walk_count" -eq 0 && "$EVID_ROWS_BEFORE" -eq 0 ]]; then
        hyp="Evidence directory is empty: no regular files under ${EVIDENCE_DIR} at any depth"
        notes="operator: drop evidence into ${EVIDENCE_DIR} (any depth) and re-run case-init.sh; an empty evidence dir is a misconfigured case, not a successful no-op"
        lid=$(append_blocked_lead "L-EVIDENCE-EMPTY" "-" "$hyp" "analysis/manifest.md" "$notes")
        bash "$AUDIT_SH" "case-init evidence-empty" \
            "0 regular files under $EVIDENCE_DIR (depth-unbounded walk)" \
            "operator drops evidence and re-runs case-init.sh; lead=${lid}" >/dev/null 2>&1 || true
        echo "[case-init] HALT — no evidence found under $EVIDENCE_DIR" >&2
        echo "[case-init]   logged BLOCKED lead ${lid}" >&2
        exit 1
    fi

    echo "[case-init] evidence manifest updated -> $MANIFEST (walk=${walk_count}, rows_appended=${rows_appended_this_run})"
fi

# ---------- 00_intake.md ----------
INTAKE="./reports/00_intake.md"
if [[ ! -f "$INTAKE" ]]; then
    cat > "$INTAKE" <<EOF
# Case Intake — $CASE_ID

**Opened:** $UTC_NOW
**Examiner:** $(whoami 2>/dev/null || echo unknown)
**Host:** $(hostname 2>/dev/null || echo unknown)

## Chain of custody
- Source:
- Acquired:
- Received:
- Evidence hash (SHA-256):
- Integrity verification:

## Evidence inventory
| # | Filename | Size | Hash | Notes |
|---|---|---|---|---|

## Preflight summary
See \`./analysis/preflight.md\`. Flag any skill that is RED/YELLOW here before proceeding.

## Initial scope
- Reported incident:
- Analyst priorities:
- Operator constraints:

## Working hypotheses
1.

## Pivots taken
(Append as analysis progresses — mirrors entries in per-domain \`findings.md\` files.)
EOF
    echo "[case-init] reports/00_intake.md seeded"
else
    echo "[case-init] reports/00_intake.md already exists — not modified"
fi

# ---------- .gitignore check ----------
if [[ -f ./.gitignore ]]; then
    if ! grep -qE '^(analysis|\./analysis)/?$' ./.gitignore 2>/dev/null \
       || ! grep -qE '^(exports|\./exports)/?$' ./.gitignore 2>/dev/null \
       || ! grep -qE '^(reports|\./reports)/?$' ./.gitignore 2>/dev/null; then
        echo "[case-init] WARNING: ./.gitignore may not exclude analysis/ exports/ reports/ — verify before committing"
    fi
fi

# ---------- intake interview (chain-of-custody fields are NOT optional) ----------
# If 00_intake.md has any blank chain-of-custody field, run the interview.
# In TTY mode the operator is prompted. In non-TTY mode the script writes
# ./analysis/.intake-pending and exits nonzero — Phase 1 (triage) then
# surfaces the pending interview to the user via the orchestrator.
INTAKE_CHECK_SH="${SCRIPT_DIR}/intake-check.sh"
INTAKE_INTERVIEW_SH="${SCRIPT_DIR}/intake-interview.sh"
if [[ -x "$INTAKE_CHECK_SH" ]]; then
    if ! bash "$INTAKE_CHECK_SH" >/dev/null 2>&1; then
        echo "[case-init] intake has blank fields — launching interview"
        if [[ -x "$INTAKE_INTERVIEW_SH" ]]; then
            bash "$INTAKE_INTERVIEW_SH" || {
                rc=$?
                if [[ $rc -eq 3 ]]; then
                    echo "[case-init] WARN: no TTY available for intake interview;"
                    echo "[case-init]       wrote ./analysis/.intake-pending — orchestrator must surface to user"
                else
                    echo "[case-init] WARN: intake interview exited $rc — re-run manually"
                fi
            }
        else
            echo "[case-init] WARN: $INTAKE_INTERVIEW_SH not executable — fix permissions"
        fi
    else
        echo "[case-init] intake fields already populated — skipping interview"
    fi
fi

echo "[case-init] done. Next: run preflight.sh and drop evidence into ./evidence/ (gitignored)."
