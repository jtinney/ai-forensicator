#!/usr/bin/env bash
# mitre-validate.sh — verify every `MITRE:` line in a findings.md (or any
# markdown file) references a known enterprise ATT&CK technique ID. Returns
# 0 if every cited ID parses and is present in the offline reference TSV,
# nonzero otherwise.
#
# Reference data: .claude/skills/dfir-bootstrap/reference/mitre-attack.tsv
# Format on disk: <id>\t<tactic>\t<name>, comments start with '#'.
#
# `MITRE:` line shape (the line is OPTIONAL on a finding entry; if present
# it must validate):
#
#   - **MITRE:** T1059.001 (Execution — PowerShell), T1027 (Defense Evasion — Obfuscated Files)
#   - MITRE: T1078, T1078.002
#
# The validator extracts every T#### / T####.### token from any line that
# matches `^[*-]?\s*\**\s*MITRE\b` (case-insensitive, allowing markdown
# bullet/bold prefixes). Tokens are checked for syntactic shape (T followed
# by 4 digits, optionally a dot and 3 more digits) AND for presence in the
# allowed-list TSV. Anything else is reported.
#
# Usage:
#   bash .claude/skills/dfir-bootstrap/mitre-validate.sh <findings.md>      # exits 0/1/2
#   bash .claude/skills/dfir-bootstrap/mitre-validate.sh --json <path>      # JSON to stdout
#
# Exit codes:
#   0  — file readable AND all MITRE: lines validate (or none present)
#   1  — at least one malformed or unknown technique ID
#   2  — usage error (file missing / reference TSV missing)

set -u

MODE="text"
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) MODE="json"; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0 ;;
        --) shift; TARGET="${1:-}"; shift || true ;;
        -*)
            echo "mitre-validate: unknown flag: $1" >&2
            exit 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "mitre-validate: usage: $0 [--json] <path-to-findings.md>" >&2
    exit 2
fi

if [[ ! -f "$TARGET" ]]; then
    echo "mitre-validate: target file not found: $TARGET" >&2
    exit 2
fi

# Resolve reference TSV. Look for it relative to this script's directory so
# the validator works whether it's invoked from inside a case workspace, the
# project root, or via $CLAUDE_PROJECT_DIR.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REF_TSV="${SCRIPT_DIR}/reference/mitre-attack.tsv"

if [[ ! -f "$REF_TSV" ]]; then
    echo "mitre-validate: reference TSV missing: $REF_TSV" >&2
    exit 2
fi

exec python3 - "$TARGET" "$REF_TSV" "$MODE" <<'PY'
import json, re, sys

target_path, ref_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]

# Load allowed IDs from the TSV (skip blank / comment lines).
allowed = {}    # id -> (tactic, name)
with open(ref_path, "r", encoding="utf-8") as fh:
    for ln in fh:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split("\t")
        if len(parts) < 3:
            continue
        tid, tactic, name = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if tid:
            allowed[tid] = (tactic, name)

# Match a line that introduces a MITRE: tag. Allow markdown bullet + bold
# prefixes ("- **MITRE:**", "* MITRE:", "MITRE:"). Case-insensitive on the
# keyword, but the T-numbers themselves must be uppercase T.
mitre_line = re.compile(r"^\s*[*\-]?\s*\**\s*MITRE\b", re.IGNORECASE)

# Strict shape: T then 4 digits, optionally .NNN. Anchored with word boundaries
# so we don't pick up stray tokens like "T10590" (5 digits — malformed).
strict_token = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Scanner used to *find* candidate tokens in a line. Looser than the strict
# regex so we can flag malformed shapes ("T123", "t1059.1", "T10591") rather
# than silently ignoring them.
candidate_token = re.compile(r"\b[Tt]\d+(?:\.\d+)?\b")

errors = []     # list of {line, kind, token, message}
ok_ids = []     # list of validated IDs (for the JSON summary)

with open(target_path, "r", encoding="utf-8") as fh:
    for i, raw in enumerate(fh.readlines(), start=1):
        if not mitre_line.match(raw):
            continue
        # Strip the leading "MITRE:" segment so we look only at the content
        # after the keyword. This avoids picking up nothing-tokens from
        # surrounding markdown.
        content = re.sub(r"^.*?MITRE\b[:\s]*", "", raw, count=1, flags=re.IGNORECASE).rstrip()
        tokens = candidate_token.findall(content)
        if not tokens:
            errors.append({
                "line":    i,
                "kind":    "empty-tag",
                "token":   "",
                "message": "MITRE: line has no T#### token",
            })
            continue
        for tok in tokens:
            # Reject lowercase 't' immediately — IDs are uppercase T per the
            # MITRE convention. This also catches "t1059" typos.
            if not strict_token.fullmatch(tok):
                errors.append({
                    "line":    i,
                    "kind":    "malformed",
                    "token":   tok,
                    "message": f"'{tok}' does not match shape T#### or T####.###",
                })
                continue
            if tok not in allowed:
                errors.append({
                    "line":    i,
                    "kind":    "unknown-id",
                    "token":   tok,
                    "message": f"'{tok}' is not in the allowed-list (extend reference/mitre-attack.tsv if this is a real technique)",
                })
                continue
            ok_ids.append(tok)

if mode == "json":
    print(json.dumps({
        "target":    target_path,
        "reference": ref_path,
        "validated": sorted(set(ok_ids)),
        "errors":    errors,
        "verdict":   "PASS" if not errors else "FAIL",
    }, indent=2))
    sys.exit(0 if not errors else 1)

if not errors:
    n = len(set(ok_ids))
    if n == 0:
        print(f"mitre-validate: PASS — no MITRE: lines in {target_path}")
    else:
        print(f"mitre-validate: PASS — {n} unique technique ID(s) validated in {target_path}")
    sys.exit(0)

print(f"mitre-validate: FAIL — {len(errors)} error(s) in {target_path}", file=sys.stderr)
for e in errors:
    print(f"  line {e['line']:>4}  [{e['kind']}]  {e['token']!s:14s}  {e['message']}", file=sys.stderr)
sys.exit(1)
PY
