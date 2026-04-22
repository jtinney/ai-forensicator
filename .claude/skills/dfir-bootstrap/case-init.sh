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
    "./analysis/yara"
    "./exports"
    "./exports/files"
    "./exports/carved"
    "./exports/yara_hits"
    "./reports"
)

for d in "${dirs[@]}"; do
    mkdir -p "$d"
done
echo "[case-init] directory tree OK"

# ---------- audit log ----------
AUDIT="./analysis/forensic_audit.log"
if [[ ! -f "$AUDIT" ]]; then
    cat > "$AUDIT" <<EOF
# Forensic audit log — $CASE_ID
# Format: <UTC timestamp> | <action> | <finding/result> | <next step>
# Initialized: $UTC_NOW
# Append with: bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next>"
EOF
    echo "$UTC_NOW | case-init | scaffold created for $CASE_ID | run preflight.sh + intake evidence" >> "$AUDIT"
    echo "[case-init] forensic_audit.log initialized"
else
    echo "$UTC_NOW | case-init | scaffold re-verified for $CASE_ID | continue prior analysis" >> "$AUDIT"
    echo "[case-init] forensic_audit.log already existed — appended re-init entry"
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
