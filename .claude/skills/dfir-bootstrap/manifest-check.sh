#!/usr/bin/env bash
# manifest-check.sh — verify that ./analysis/manifest.md is a complete and
# trustworthy ledger of every byte under ./evidence/ + ./working/.
#
# Walks evidence/ depth-unbounded and confirms:
#   1. every regular file under evidence/ has a row in manifest.md keyed by
#      ev_id; the path column matches the relative-from-evidence/ form (or
#      the legacy absolute-with-dot form for cases scaffolded before the
#      issue #12 depth-walk fix)
#   2. every archive (zip / tar / 7z / gzip-tar) has a `bundle:<kind>` row
#      AND at least one `bundle-member` row keyed `<ev_id>-M001..M###`
#   3. the bundle-member count for each archive matches the on-disk
#      `find working/<basename>/ -type f | wc -l` count
#   4. no row has `sha256 = -` UNLESS there is a documented `bundle-skipped`
#      reason in analysis/leads.md acknowledged by the operator (agent-only
#      acknowledgements are rejected — yields to operator only, mirroring
#      intake-check.sh's discipline)
#   5. no bespoke hash files live alongside manifest.md (a case12-style
#      workaround pattern). Refuses if analysis/ contains any of:
#      archive_hashes.{txt,csv,md}, derivative_hashes.{txt,csv,md},
#      hashes.{txt,csv,md}, *-hashes.{txt,csv,md}, or any other
#      analysis/*hash* file other than manifest.md / exports-manifest.md.
#
# The check exists because case12 hit the case-init.sh:314 depth-1 walk bug
# (12 archives at depth-2 were silently skipped, manifest.md came out empty,
# the agent invented analysis/archive_hashes.txt as a bespoke ledger). With
# the depth-walk fixed in case-init.sh, this gate ensures that every
# downstream agent dispatch refuses to run on a manifest that the depth-walk
# couldn't fully populate (corrupt archive, partial expansion, etc.).
#
# Exit conventions match intake-check.sh / leads-check.sh:
#   0   manifest is sound
#   1   manifest is BLOCKED (one or more violations; missing rows listed)
#   2   misuse / preconditions wrong (no analysis dir, malformed manifest)
#
# Usage:
#   bash .claude/skills/dfir-bootstrap/manifest-check.sh                  # text to stdout/stderr
#   bash .claude/skills/dfir-bootstrap/manifest-check.sh --quiet          # silent unless violations
#   bash .claude/skills/dfir-bootstrap/manifest-check.sh --json           # JSON to stdout
#
# In --quiet mode the script suppresses stdout and only emits stderr
# violations (one per line) plus a one-line summary. The PreToolUse hook
# uses --quiet so the harness audit doesn't fill with normal-pass noise.
#
# Side effects on violation:
#   - On bespoke-hash-file refusal: appends an L-MANIFEST-BESPOKE-NN
#     BLOCKED lead to analysis/leads.md. The lead names the offending
#     file and asks the operator to reconcile (the file may contain
#     useful work that needs migrating into manifest.md, not deletion).
#   - Audit log: writes a "manifest-check FAIL" row via audit.sh on
#     non-zero exit. (No row on PASS — the orchestrator's own audit row
#     is sufficient.)

set -u

# ---- argv ----
MODE="text"   # text | --quiet | --json
case "${1:-}" in
    "")        MODE="text" ;;
    --quiet)   MODE="quiet" ;;
    --json)    MODE="json" ;;
    -h|--help)
        sed -n '2,/^$/p' "$0" | sed -E 's/^# ?//'
        exit 0 ;;
    *)
        echo "manifest-check: unknown argument '$1' (use --quiet or --json)" >&2
        exit 2 ;;
esac

ANALYSIS_DIR="./analysis"
EVIDENCE_DIR="./evidence"
EXTRACT_DIR="./working"
MANIFEST="${ANALYSIS_DIR}/manifest.md"
LEADS="${ANALYSIS_DIR}/leads.md"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
AUDIT_SH="${SCRIPT_DIR}/audit.sh"

# ---- preconditions ----
if [[ ! -d "$ANALYSIS_DIR" ]]; then
    if [[ "$MODE" == "json" ]]; then
        printf '{"manifest":"missing-analysis-dir","violations":[]}\n'
    elif [[ "$MODE" != "quiet" ]]; then
        echo "manifest-check: $ANALYSIS_DIR not found (run from case workspace)" >&2
    fi
    exit 2
fi

if [[ ! -d "$EVIDENCE_DIR" ]]; then
    if [[ "$MODE" == "json" ]]; then
        printf '{"manifest":"missing-evidence-dir","violations":[]}\n'
    elif [[ "$MODE" != "quiet" ]]; then
        echo "manifest-check: $EVIDENCE_DIR not found (run from case workspace)" >&2
    fi
    exit 2
fi

if [[ ! -f "$MANIFEST" ]]; then
    if [[ "$MODE" == "json" ]]; then
        printf '{"manifest":"missing","violations":[{"kind":"manifest-missing","fix":"run case-init.sh to seed manifest.md"}]}\n'
    elif [[ "$MODE" != "quiet" ]]; then
        echo "manifest-check: FAIL — $MANIFEST not found" >&2
        echo "  fix: bash .claude/skills/dfir-bootstrap/case-init.sh <CASE_ID>" >&2
    else
        echo "manifest-check: FAIL — $MANIFEST not found" >&2
    fi
    exit 1
fi

# Delegate the bulk of the work to Python — robust across whitespace,
# UTF-8, and the bytes-vs-text edge cases shell finds painful.
exec python3 - "$MANIFEST" "$EVIDENCE_DIR" "$EXTRACT_DIR" "$ANALYSIS_DIR" "$LEADS" "$MODE" "$AUDIT_SH" <<'PY'
import json, os, re, subprocess, sys

manifest, evidence_dir, extract_dir, analysis_dir, leads_path, mode, audit_sh = sys.argv[1:8]

# ---- 1. parse manifest.md into a row list ----
# Header shape: | evidence_id | filename | path | type | size | sha256 | parent | notes |
ROW_RE = re.compile(r"^\|\s*(EV\S+)\s*\|")

rows = []
with open(manifest, "r", encoding="utf-8", errors="replace") as fh:
    for i, ln in enumerate(fh, start=1):
        if not ROW_RE.match(ln):
            continue
        # Strip leading/trailing | and split on |
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) < 8:
            continue
        rows.append({
            "ev_id":   cells[0],
            "name":    cells[1],
            "path":    cells[2],
            "type":    cells[3],
            "size":    cells[4],
            "sha256":  cells[5],
            "parent":  cells[6],
            "notes":   cells[7],
            "line":    i,
        })

# Index by path (relative-from-evidence form OR absolute-with-dot legacy form)
# and by ev_id
by_path = {}
by_ev   = {}
for r in rows:
    by_path[r["path"]] = r
    by_ev[r["ev_id"]] = r

violations = []

# ---- 2. walk evidence/ depth-unbounded ----
# For each regular file, confirm a manifest row exists keyed by either the
# relative-from-evidence form (Archives/foo.zip) or the legacy
# absolute-with-dot form (./evidence/Archives/foo.zip).
walked = []
for root, dirs, files in os.walk(evidence_dir):
    for fname in sorted(files):
        if fname.startswith("."):
            continue
        abs_path = os.path.join(root, fname)
        rel_path = os.path.relpath(abs_path, evidence_dir)
        # Normalize to forward slashes for cross-platform consistency
        rel_path = rel_path.replace(os.sep, "/")
        legacy_abs = "./" + abs_path.lstrip("./").replace(os.sep, "/")

        walked.append({"abs": abs_path, "rel": rel_path, "legacy_abs": legacy_abs})

        if rel_path not in by_path and legacy_abs not in by_path:
            violations.append({
                "kind":     "evidence-not-manifested",
                "path":     rel_path,
                "fix":      f"file under evidence/ has no manifest row; re-run case-init.sh to hash + manifest it (path: {rel_path})",
            })

# ---- 3. archives must have bundle row + member rows ----
# Detect kind by `file -b` (matches case-init.sh's classifier).
ARCHIVE_KINDS = ("zip", "7z", "gzip-tar", "tar", "bzip-tar")

def classify_archive(path):
    try:
        out = subprocess.check_output(["file", "-b", path], stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except Exception:
        return None
    if "Zip archive" in out:
        return "zip"
    if "7-zip archive" in out:
        return "7z"
    if "gzip compressed" in out:
        # only if it wraps a tar
        try:
            if "tar archive" in subprocess.check_output(["file", "-b", path], stderr=subprocess.DEVNULL).decode("utf-8", "replace"):
                return "gzip-tar"
            subprocess.check_call(["tar", "-tzf", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "gzip-tar"
        except Exception:
            return None
    if "POSIX tar" in out or "tar archive" in out:
        return "tar"
    if "bzip2 compressed" in out:
        try:
            subprocess.check_call(["tar", "-tjf", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "bzip-tar"
        except Exception:
            return None
    return None

# For each archive, check (a) bundle row exists, (b) >=1 bundle-member row,
# (c) member count matches on-disk count under working/<basename>/.
for w in walked:
    rel = w["rel"]
    legacy_abs = w["legacy_abs"]
    abs_path = w["abs"]
    kind = classify_archive(abs_path)
    if not kind:
        continue
    bundle_row = by_path.get(rel) or by_path.get(legacy_abs)
    if not bundle_row:
        # already flagged as evidence-not-manifested above
        continue
    if not bundle_row["type"].startswith("bundle:"):
        violations.append({
            "kind":     "archive-row-not-bundle",
            "path":     rel,
            "fix":      f"archive {rel} is in manifest as type='{bundle_row['type']}' but should be 'bundle:{kind}'; re-run case-init.sh after clearing the manifest row",
        })
        continue
    ev_id = bundle_row["ev_id"]

    # Count member rows whose parent column matches this ev_id
    member_rows = [r for r in rows if r["type"] == "bundle-member" and r["parent"] == ev_id]

    # Bundles with `expansion deferred` notes (BULK_EXTRACT=0 sequential
    # mode) are intentionally member-less until staged. Skip the member
    # checks for these rows — extraction-plan.sh already wrote an
    # extraction-plan.md describing the schedule.
    if "expansion deferred" in bundle_row["notes"].lower():
        continue

    if not member_rows:
        violations.append({
            "kind":     "bundle-no-members",
            "path":     rel,
            "ev_id":    ev_id,
            "fix":      f"bundle {ev_id} ({rel}) has zero bundle-member rows; re-run case-init.sh after clearing working/<basename>/",
        })
        continue

    # On-disk count under working/<basename>/. The basename is
    # whatever case-init.sh used as the dest_subdir (filename minus
    # extension; .tar.gz / .tar.bz2 strip the .tar too).
    bn = os.path.basename(rel)
    if "." in bn:
        dest_subdir = bn.rsplit(".", 1)[0]
        if dest_subdir.endswith(".tar"):
            dest_subdir = dest_subdir[:-4]
    else:
        dest_subdir = bn
    dest = os.path.join(extract_dir, dest_subdir)

    if not os.path.isdir(dest):
        violations.append({
            "kind":     "bundle-extracted-dir-missing",
            "path":     rel,
            "ev_id":    ev_id,
            "fix":      f"bundle {ev_id} has {len(member_rows)} member rows but {dest} is missing; clear the manifest rows for {ev_id} and re-run case-init.sh",
        })
        continue

    on_disk_count = 0
    for r2, _, fs2 in os.walk(dest):
        on_disk_count += len(fs2)

    if on_disk_count != len(member_rows):
        violations.append({
            "kind":     "bundle-member-count-mismatch",
            "path":     rel,
            "ev_id":    ev_id,
            "fix":      f"bundle {ev_id} has {len(member_rows)} member rows but {on_disk_count} files on disk under {dest}; partial expansion — operator clears {dest} and re-runs case-init.sh",
        })

# ---- 4. sha256 = '-' must be paired with a documented bundle-skipped reason ----
# Read leads.md (if present); look for an L-EXTRACT-* row that names the
# offending ev_id and includes the literal token "operator-acknowledged".
leads_text = ""
if os.path.exists(leads_path):
    with open(leads_path, "r", encoding="utf-8", errors="replace") as fh:
        leads_text = fh.read()

for r in rows:
    if r["sha256"].strip() != "-":
        continue
    # bundle-deferred rows are explicitly allowed (sequential mode)
    if r["type"].startswith("bundle:") and "deferred" in r["notes"].lower():
        continue
    # Look for an operator acknowledgment in leads.md keyed to this ev_id
    ev_id = r["ev_id"]
    has_ack = False
    for line in leads_text.splitlines():
        if ev_id in line and "operator-acknowledged" in line.lower():
            has_ack = True
            break
    if not has_ack:
        violations.append({
            "kind":     "manifest-row-unhashed",
            "ev_id":    ev_id,
            "path":     r["path"],
            "fix":      f"manifest row {ev_id} has sha256='-' without an 'operator-acknowledged' lead in leads.md; chain-of-custody requires a hash or a documented operator override",
        })

# ---- 5. bespoke hash files refusal ----
# Walk analysis/ depth-1 (intentional — bespoke files appear at the
# analysis root, not nested) for case-insensitive matches. Reject any
# *hash* file other than the canonical ledgers.
import fnmatch
allowed_basenames = {"manifest.md", "exports-manifest.md"}
bespoke = []
if os.path.isdir(analysis_dir):
    for entry in sorted(os.listdir(analysis_dir)):
        full = os.path.join(analysis_dir, entry)
        if not os.path.isfile(full):
            continue
        if entry in allowed_basenames:
            continue
        # Lowercased basename for case-insensitive pattern match
        lname = entry.lower()
        for pat in (
            "archive_hashes.*",
            "derivative_hashes.*",
            "hashes.*",
            "*-hashes.*",
            "*hash*",        # catch-all
        ):
            if fnmatch.fnmatch(lname, pat):
                bespoke.append(entry)
                break
for entry in bespoke:
    violations.append({
        "kind":     "bespoke-hash-file",
        "path":     os.path.join(analysis_dir, entry),
        "fix":      f"bespoke hash file '{entry}' lives outside the canonical ledger (manifest.md / exports-manifest.md); operator: reconcile its rows into manifest.md (do not blindly delete — it may contain real work) then remove the bespoke file",
    })

# ---- 6. on bespoke-hash-file violation, append L-MANIFEST-BESPOKE-NN ----
def ensure_leads_md(path):
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("| lead_id | evidence_id | domain | hypothesis | pointer | priority | status | notes |\n")
        fh.write("|---------|-------------|--------|------------|---------|----------|--------|-------|\n")

def next_lead_id(path, prefix):
    if not os.path.exists(path):
        return f"{prefix}-01"
    last_n = 0
    pat = re.compile(r"\| " + re.escape(prefix) + r"-(\d+)")
    with open(path, "r", encoding="utf-8") as fh:
        for ln in fh:
            m = pat.search(ln)
            if m:
                n = int(m.group(1))
                if n > last_n:
                    last_n = n
    return f"{prefix}-{last_n + 1:02d}"

bespoke_violations = [v for v in violations if v["kind"] == "bespoke-hash-file"]
if bespoke_violations:
    ensure_leads_md(leads_path)
    with open(leads_path, "r", encoding="utf-8") as fh:
        existing = fh.read()
    with open(leads_path, "a", encoding="utf-8") as fh:
        for v in bespoke_violations:
            entry = os.path.basename(v["path"])
            hyp = f"Bespoke hash file at analysis/{entry} bypasses the canonical manifest.md ledger"
            if hyp in existing:
                continue
            lid = next_lead_id(leads_path, "L-MANIFEST-BESPOKE")
            notes = "operator must reconcile rows into manifest.md before removing the bespoke file (it may carry forensic work that needs migration, not deletion)"
            fh.write(f"| {lid} | - | bootstrap | {hyp} | {v['path']} | high | blocked | {notes} |\n")
            v["lead_id"] = lid

# ---- 7. emit + audit ----
verdict = "PASS" if not violations else "FAIL"

if violations:
    # Audit one summary row.
    counts = {}
    for v in violations:
        counts[v["kind"]] = counts.get(v["kind"], 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    if os.path.exists(audit_sh) and os.access(audit_sh, os.X_OK):
        try:
            subprocess.run(
                ["bash", audit_sh, "manifest-check FAIL",
                 f"violations: {summary}",
                 "operator: review analysis/leads.md and the manifest-check output before re-dispatching agents"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception:
            pass

if mode == "json":
    counts = {}
    for v in violations:
        counts[v["kind"]] = counts.get(v["kind"], 0) + 1
    print(json.dumps({
        "manifest":   verdict.lower() if verdict == "PASS" else "blocked",
        "verdict":    verdict,
        "rows_total": len(rows),
        "files_walked": len(walked),
        "counts":     counts,
        "violations": violations,
    }, indent=2))
    sys.exit(0 if not violations else 1)

if mode == "quiet":
    if violations:
        # One-line summary on stderr; one violation per line.
        print(f"manifest-check: FAIL — {len(violations)} violation(s)", file=sys.stderr)
        for v in violations:
            kind = v["kind"]
            path = v.get("path", "")
            print(f"  [{kind}] {path}", file=sys.stderr)
        print("  fix: bash .claude/skills/dfir-bootstrap/manifest-check.sh   # full output", file=sys.stderr)
    sys.exit(0 if not violations else 1)

# default text mode
if not violations:
    print(f"manifest-check: PASS — {len(rows)} manifest rows, {len(walked)} files under {evidence_dir}")
    sys.exit(0)

print(f"manifest-check: FAIL — {len(violations)} violation(s) across {len(rows)} manifest rows", file=sys.stderr)
counts = {}
for v in violations:
    counts[v["kind"]] = counts.get(v["kind"], 0) + 1
print("  counts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())), file=sys.stderr)
print("", file=sys.stderr)
for v in violations:
    kind = v["kind"]
    path = v.get("path", "")
    ev = v.get("ev_id", "")
    head = f"  [{kind}]"
    if ev:
        head += f" {ev}"
    if path:
        head += f" {path}"
    print(head, file=sys.stderr)
    print(f"    -> {v['fix']}", file=sys.stderr)
sys.exit(1)
PY
