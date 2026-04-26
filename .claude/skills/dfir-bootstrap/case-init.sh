#!/usr/bin/env bash
# DFIR case scaffold — idempotent; safe to re-run.
# Creates ./analysis, ./exports, ./reports with the layout every skill expects,
# seeds forensic_audit.log with a header, and drops findings.md stubs so analysts
# cannot silently forget the Analysis Discipline contract.

set -u

CASE_ID="${1:-UNSET}"
PROJECT_ROOT="$(pwd)"
UTC_NOW="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"

if [[ "$CASE_ID" == "UNSET" ]]; then
    echo "usage: case-init.sh <CASE_ID>" >&2
    echo "       CASE_ID is any free-form case identifier (e.g. 2020JimmyWilson, INC-2026-042)" >&2
    exit 2
fi

echo "[case-init] Case: $CASE_ID"
echo "[case-init] Root: $PROJECT_ROOT"
echo "[case-init] UTC:  $UTC_NOW"

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
    "./analysis/_extracted"
    "./exports"
    "./exports/files"
    "./exports/carved"
    "./exports/yara_hits"
    "./exports/network"
    "./exports/network/http_objects"
    "./exports/network/tcpflow"
    "./exports/network/streams"
    "./exports/network/carved"
    "./reports"
)

for d in "${dirs[@]}"; do
    mkdir -p "$d"
done
echo "[case-init] directory tree OK"

# ---------- audit log ----------
AUDIT="./analysis/forensic_audit.log"
AUDIT_SH="$(dirname "${BASH_SOURCE[0]}")/audit.sh"
if [[ ! -f "$AUDIT" ]]; then
    cat > "$AUDIT" <<EOF
# Forensic audit log — $CASE_ID
# Format: <UTC timestamp> | <action> | <finding/result> | <next step>
# Initialized: $UTC_NOW
# Append with: bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next>"
EOF
    # Use audit.sh so the scaffold entry has the canonical wall-clock timestamp
    bash "$AUDIT_SH" "case-init" "scaffold created for $CASE_ID" "run preflight.sh + intake evidence" >/dev/null 2>&1 \
        || echo "$UTC_NOW | case-init | scaffold created for $CASE_ID | run preflight.sh + intake evidence" >> "$AUDIT"
    echo "[case-init] forensic_audit.log initialized"
else
    bash "$AUDIT_SH" "case-init" "scaffold re-verified for $CASE_ID" "continue prior analysis" >/dev/null 2>&1 \
        || echo "$UTC_NOW | case-init | scaffold re-verified for $CASE_ID | continue prior analysis" >> "$AUDIT"
    echo "[case-init] forensic_audit.log already existed — appended re-init entry"
fi

# ---------- evidence bundle expansion + per-member hashing ----------
# When ./evidence/ contains an archive (zip/tar/tar.gz/tar.bz2/7z), expand it
# under ./analysis/_extracted/<basename>/ so analytic units (each member) can
# be hashed and tracked individually. Idempotent: skips if dest non-empty.
# Disk-bounded: skips if estimated expanded size > 50% of free disk.
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
    # Use a NUL-delimited, depth-1 sweep of evidence/. Skip dotfiles.
    while IFS= read -r -d '' f; do
        [[ -d "$f" ]] && continue
        bn="$(basename "$f")"
        [[ "${bn:0:1}" == "." ]] && continue

        # Skip if already manifested (idempotent re-run)
        # Match the path field exactly so two evidence items with identical
        # basenames in different dirs are kept distinct.
        if grep -qF "| ${f} | " "$MANIFEST" 2>/dev/null; then
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
                if file -b "$f" 2>/dev/null | grep -q 'tar archive'; then
                    kind="gzip-tar"
                fi ;;
            *"POSIX tar"*|*"tar archive"*) kind="tar" ;;
        esac

        ev_id=$(next_ev_id)

        if [[ -n "$kind" ]]; then
            # Expand bundle if dest dir is empty (idempotent)
            dest_subdir="${bn%.*}"
            # Strip secondary extension for `.tar.gz`/`.tar.bz2`
            [[ "$dest_subdir" == *.tar ]] && dest_subdir="${dest_subdir%.tar}"
            dest="${EXTRACT_DIR}/${dest_subdir}"
            mkdir -p "$dest"

            if [[ -z "$(ls -A "$dest" 2>/dev/null)" ]]; then
                # Disk safety: skip if expanded size > 50% of free disk
                avail_kb=$(df --output=avail "$dest" 2>/dev/null | tail -1)
                avail_b=$(( avail_kb * 1024 ))
                est_b=$(estimate_expanded_size "$f" "$kind")
                if [[ "$est_b" -gt 0 && "$avail_b" -gt 0 && "$est_b" -gt $(( avail_b / 2 )) ]]; then
                    bash "$AUDIT_SH" "case-init bundle-skip" \
                        "skip $bn — estimated $(hsize "$est_b") > 50% of $(hsize "$avail_b") free" \
                        "free disk or expand manually outside the case dir" >/dev/null 2>&1 || true
                    append_manifest_row "$ev_id" "$bn" "$f" "bundle:${kind}" "$size" "$sha" "-" "skipped expansion (est $(hsize "$est_b") > 50% free)"
                    continue
                fi

                # Expand
                case "$kind" in
                    zip)        unzip -q "$f" -d "$dest" 2>/dev/null \
                                    || { echo "[case-init] WARN: unzip failed for $f"; continue; } ;;
                    gzip-tar)   tar -xzf "$f" -C "$dest" 2>/dev/null \
                                    || { echo "[case-init] WARN: tar -xz failed for $f"; continue; } ;;
                    tar)        tar -xf  "$f" -C "$dest" 2>/dev/null \
                                    || { echo "[case-init] WARN: tar failed for $f"; continue; } ;;
                    7z)         7z x -y -bb0 -bd -o"$dest" "$f" >/dev/null 2>&1 \
                                    || { echo "[case-init] WARN: 7z failed for $f (need p7zip-full?)"; continue; } ;;
                esac
                echo "[case-init] expanded $bn -> $dest"
            else
                echo "[case-init] $bn already expanded at $dest (idempotent skip)"
            fi

            # Manifest the bundle itself
            append_manifest_row "$ev_id" "$bn" "$f" "bundle:${kind}" "$size" "$sha" "-" "expanded to $dest"

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
            done < <(find "$dest" -type f -print0 2>/dev/null)

            bash "$AUDIT_SH" "case-init bundle-expand" \
                "expanded $ev_id ($bn) to $mi member(s) under $dest" \
                "surveyor reads manifest.md for bundle-member rows" >/dev/null 2>&1 || true
        else
            # Plain blob — just hash and manifest
            append_manifest_row "$ev_id" "$bn" "$f" "blob" "$size" "$sha" "-" "$ftype_raw"
            bash "$AUDIT_SH" "case-init blob-hash" \
                "hashed $ev_id ($bn) sha256=${sha}" \
                "surveyor classifies and proceeds per dfir-triage protocol" >/dev/null 2>&1 || true
        fi
    done < <(find "$EVIDENCE_DIR" -maxdepth 1 -mindepth 1 -print0 2>/dev/null)

    echo "[case-init] evidence manifest updated -> $MANIFEST"
fi

# ---------- findings.md stubs ----------
findings_template() {
    local domain="$1"; local outpath="$2"
    if [[ -f "$outpath" ]]; then
        return 0  # never clobber existing findings
    fi
    cat > "$outpath" <<EOF
# Findings — $domain — $CASE_ID

> Append one entry per pivot. Each entry: artifact reviewed, finding, interpretation,
> and the next pivot it triggered. If a skill session produces no entries here,
> that is a discipline failure — fix before moving on.

<!-- Template
## <UTC timestamp> — <artifact reviewed>
- **Finding:** <what you observed>
- **Interpretation:** <what it means for the case>
- **Next pivot:** <next action>
-->
EOF
}

findings_template "filesystem"        "./analysis/filesystem/findings.md"
findings_template "windows-artifacts" "./analysis/windows-artifacts/findings.md"
findings_template "memory"            "./analysis/memory/findings.md"
findings_template "network"           "./analysis/network/findings.md"
findings_template "timeline"          "./analysis/timeline/findings.md"
findings_template "yara"              "./analysis/yara/findings.md"
echo "[case-init] per-domain findings.md stubs OK"

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

echo "[case-init] done. Next: run preflight.sh and drop evidence into ./evidence/ (gitignored)."
