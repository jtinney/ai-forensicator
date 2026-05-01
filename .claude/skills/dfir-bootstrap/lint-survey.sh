#!/usr/bin/env bash
# lint-survey.sh — structural lint for survey output (Phase 2).
#
# A surveyor's `./analysis/<DOMAIN>/survey-EV<NN>.md` is the primary input
# to investigator dispatch. Variance in structure forces every downstream
# consumer (orchestrator, investigator, correlator, QA) to handle multiple
# shapes, which silently degrades quality. This script enforces the
# canonical layout defined in
# `.claude/skills/dfir-discipline/templates/survey-template.md`.
#
# Usage:
#   bash .claude/skills/dfir-bootstrap/lint-survey.sh <path/to/survey-EV01.md>
#   bash .claude/skills/dfir-bootstrap/lint-survey.sh --json <path>
#
# Exit codes:
#   0 — survey is compliant
#   1 — one or more violations (printed to stderr)
#   2 — preconditions wrong (file missing / unreadable / bad arguments)
#
# Each violation prints a single line on stderr in the form:
#   ERR: <file>: <kind>: <message>
# so a calling agent can grep for `^ERR:` and react.

set -u

MODE="text"
SURVEY=""

for arg in "$@"; do
    case "$arg" in
        --json) MODE="json" ;;
        -h|--help)
            cat <<EOF
lint-survey.sh — validate a survey-EV<NN>.md file against the canonical
template at .claude/skills/dfir-discipline/templates/survey-template.md.

Usage: lint-survey.sh [--json] <path-to-survey>

Exit 0 if compliant; 1 with structured ERR: lines if not; 2 on bad input.
EOF
            exit 0
            ;;
        *) SURVEY="$arg" ;;
    esac
done

if [[ -z "$SURVEY" ]]; then
    echo "usage: lint-survey.sh [--json] <path-to-survey>" >&2
    exit 2
fi
if [[ ! -f "$SURVEY" ]]; then
    echo "ERR: $SURVEY: missing-file: file does not exist" >&2
    exit 2
fi
if [[ ! -r "$SURVEY" ]]; then
    echo "ERR: $SURVEY: unreadable: cannot read file" >&2
    exit 2
fi
if [[ ! -s "$SURVEY" ]]; then
    echo "ERR: $SURVEY: empty-file: zero bytes" >&2
    exit 1
fi

exec python3 - "$SURVEY" "$MODE" <<'PY'
import json
import os
import re
import sys

SURVEY_PATH = sys.argv[1]
MODE = sys.argv[2]

REQUIRED_SECTIONS = [
    ("# Header",                "header"),
    ("## Tools run",            "tools-run"),
    ("## Findings of interest", "findings-of-interest"),
    ("## Lead summary table",   "lead-summary-table"),
    ("## Negative results",     "negative-results"),
    ("## Open questions",       "open-questions"),
]

HEADER_FIELDS = [
    ("Case ID",                  re.compile(r"\*\*Case ID:\*\*")),
    ("Evidence ID",              re.compile(r"\*\*Evidence ID:\*\*")),
    ("Evidence sha256",          re.compile(r"\*\*Evidence sha256:\*\*")),
    ("Domain",                   re.compile(r"\*\*Domain:\*\*")),
    ("Surveyor agent version",   re.compile(r"\*\*Surveyor agent version:\*\*")),
    ("UTC timestamp",            re.compile(r"\*\*UTC timestamp:\*\*")),
]

# UTC timestamp regex (matches `YYYY-MM-DD HH:MM:SS UTC`)
UTC_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+UTC\b")
# sha256 hex (64 lowercase hex chars)
SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b")
# canonical lead-id format from ORCHESTRATE.md
LEAD_RE = re.compile(r"L-EV[0-9]+-[a-z][a-z0-9\-]*-[0-9]{2,}(?:e[0-9]{2,})?")
# Anywhere a string starts with `L-` and looks lead-shaped (used to catch malformed leads)
LOOSE_LEAD_RE = re.compile(r"`?L-[A-Za-z0-9\-]+`?")
# Filename pattern: survey-EV<NN>.md (zero-padded numeric)
FILENAME_RE = re.compile(r"^survey-EV[0-9]{2,}\.md$")
# Filename pattern (alt): allow EV<NN>-<domain> if the project ever adopts it
FILENAME_RE_ALT = re.compile(r"^survey-EV[0-9]{2,}-[a-z][a-z0-9\-]*\.md$")

errors = []  # list of {kind, message}
warnings = []  # informational, not blocking

def add_err(kind, message):
    errors.append({"kind": kind, "message": message})

def add_warn(kind, message):
    warnings.append({"kind": kind, "message": message})

# 1. Filename pattern check
# Skip the filename check when the file is one of the per-domain
# `reference/example-survey.md` worked examples. Those exist precisely
# so surveyors can see a passing structure without colliding with the
# real `survey-EV<NN>.md` namespace.
basename = os.path.basename(SURVEY_PATH)
in_reference_dir = "/reference/" in SURVEY_PATH.replace(os.sep, "/")
is_example_file = basename == "example-survey.md"
if in_reference_dir and is_example_file:
    pass  # reference example — exempt from filename pattern
elif not (FILENAME_RE.match(basename) or FILENAME_RE_ALT.match(basename)):
    add_err(
        "filename-pattern",
        f"file '{basename}' does not match survey-EV<NN>.md (or survey-EV<NN>-<domain>.md)",
    )

# 2. Read content
with open(SURVEY_PATH, "r", encoding="utf-8") as fh:
    raw = fh.read()
lines = raw.splitlines()

# 3. Required sections — each heading must appear on a line by itself, in order
section_lines = {}  # name -> 1-based line number
section_order_actual = []
for i, ln in enumerate(lines, start=1):
    stripped = ln.strip()
    for heading, name in REQUIRED_SECTIONS:
        if stripped == heading and name not in section_lines:
            section_lines[name] = i
            section_order_actual.append(name)
            break

for heading, name in REQUIRED_SECTIONS:
    if name not in section_lines:
        add_err("missing-section", f"required heading not found: '{heading}'")

# Order check: only meaningful if all sections were found
expected_order = [n for _, n in REQUIRED_SECTIONS]
if all(n in section_lines for n in expected_order):
    if section_order_actual != expected_order:
        add_err(
            "section-order",
            "required sections present but out of order; expected: "
            + " -> ".join(expected_order)
            + "; actual: "
            + " -> ".join(section_order_actual),
        )

# 4. Slice content per section so per-section checks operate on the right block
def section_slice(name):
    """Return the body of a given section (between its heading and the next heading or EOF)."""
    if name not in section_lines:
        return ""
    start = section_lines[name]
    end = len(lines) + 1
    for other_name, other_line in section_lines.items():
        if other_line > start and other_line < end:
            end = other_line
    return "\n".join(lines[start : end - 1])

header_body = section_slice("header")
tools_body  = section_slice("tools-run")
findings_body = section_slice("findings-of-interest")
table_body  = section_slice("lead-summary-table")
negative_body = section_slice("negative-results")
open_body   = section_slice("open-questions")

# 5. Header field presence
if "header" in section_lines:
    for fname, pat in HEADER_FIELDS:
        if not pat.search(header_body):
            add_err("missing-header-field", f"Header section is missing field: '{fname}'")

# 6. UTC timestamp regex match somewhere in Header
if "header" in section_lines and not UTC_RE.search(header_body):
    add_err(
        "missing-utc-timestamp",
        "Header section does not contain a UTC timestamp matching 'YYYY-MM-DD HH:MM:SS UTC'",
    )

# 7. sha256 regex match somewhere in Header (rejects placeholders like <sha256>)
if "header" in section_lines and not SHA256_RE.search(header_body):
    add_err(
        "missing-evidence-sha256",
        "Header section does not contain a 64-char lowercase hex sha256",
    )

# 8. Tools run section — must be non-empty
if "tools-run" in section_lines:
    body = re.sub(r"<!--.*?-->", "", tools_body, flags=re.DOTALL)
    if not re.search(r"^\s*[-*]\s+\S", body, flags=re.MULTILINE):
        add_err("empty-tools-run", "Tools run section has no bullet list entries")

# 9. Findings of interest — must contain at least one bullet with a lead reference
if "findings-of-interest" in section_lines:
    body = re.sub(r"<!--.*?-->", "", findings_body, flags=re.DOTALL)
    findings_bullets = re.findall(r"^\s*[-*]\s+.+$", body, flags=re.MULTILINE)
    if not findings_bullets:
        add_err("empty-findings", "Findings of interest section has no bullet list entries")

# 10. Lead summary table — required columns + at least one data row
if "lead-summary-table" in section_lines:
    body = re.sub(r"<!--.*?-->", "", table_body, flags=re.DOTALL)
    table_rows = [ln for ln in body.splitlines() if ln.strip().startswith("|")]
    # Need at least: header row, separator row, one data row = 3 lines
    if len(table_rows) < 3:
        add_err(
            "table-too-small",
            f"Lead summary table needs header + separator + >=1 data row; found {len(table_rows)} table-formatted line(s)",
        )
    else:
        header_row = table_rows[0].lower()
        required_columns = ["lead_id", "priority", "hypothesis", "next-step", "est-cost"]
        for col in required_columns:
            # Allow flexibility: `next-step query` or `next step` etc.
            col_loose = col.replace("-", "[ -]?")
            if not re.search(col_loose, header_row):
                add_err("missing-table-column", f"Lead summary table header missing column: '{col}'")
        # Data rows: rows below the separator that aren't blank/separator
        data_rows = []
        for r in table_rows[1:]:
            stripped = r.strip()
            # Separator rows are like |---|---|---|...
            if re.match(r"^\|[\s\-:|]+\|?\s*$", stripped):
                continue
            data_rows.append(stripped)
        if not data_rows:
            add_err("empty-table", "Lead summary table has no data rows")
        else:
            # Allow `(no leads)` as an explicit placeholder row
            no_leads_present = any("(no leads)" in r.lower() for r in data_rows)
            if not no_leads_present:
                # Each data row should reference a canonical lead_id
                for row in data_rows:
                    cells = [c.strip().strip("`") for c in row.strip("|").split("|")]
                    if not cells:
                        continue
                    lead_cell = cells[0]
                    if not LEAD_RE.search(lead_cell):
                        add_err(
                            "table-malformed-lead-id",
                            f"Lead summary table row has malformed lead_id (expected 'L-EV<NN>-<domain>-<MM>'): '{lead_cell}'",
                        )

# 11. Negative results — must be populated
if "negative-results" in section_lines:
    body = re.sub(r"<!--.*?-->", "", negative_body, flags=re.DOTALL)
    if not re.search(r"^\s*[-*]\s+\S", body, flags=re.MULTILINE):
        add_err(
            "empty-negative-results",
            "Negative results section has no bullets; write '- (none — every cheap-signal pass produced at least one hit)' if truly empty",
        )

# 12. Open questions — must be populated
if "open-questions" in section_lines:
    body = re.sub(r"<!--.*?-->", "", open_body, flags=re.DOTALL)
    if not re.search(r"^\s*[-*]\s+\S", body, flags=re.MULTILINE):
        add_err(
            "empty-open-questions",
            "Open questions section has no bullets; write '- (none)' if truly empty",
        )

# 13. Lead-ID validation across the whole file
# Any token that LOOKS like a lead but does not match the canonical regex is a violation.
# Skip tokens that fall inside HTML comments (template guidance) or fenced code blocks.
def strip_comments_and_code(text):
    out = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    out = re.sub(r"```.*?```", "", out, flags=re.DOTALL)
    return out

scrub = strip_comments_and_code(raw)
loose_leads = LOOSE_LEAD_RE.findall(scrub)
seen_bad = set()
for tok in loose_leads:
    cleaned = tok.strip("`")
    # Allow correlator-emitted IDs: L-CORR-NN, L-BASELINE-<DOMAIN>-NN.
    # The surveyor MUST NOT emit these, but they may show up as references.
    if cleaned.startswith("L-CORR-") or cleaned.startswith("L-BASELINE-"):
        continue
    # Skip placeholder strings that are clearly template guidance leftovers
    # (caught by the comment/code strip above; defense-in-depth here).
    if "<NN>" in cleaned or "<domain>" in cleaned or "<MM>" in cleaned:
        add_err(
            "placeholder-lead-id",
            f"Survey contains unresolved template placeholder lead-ID: '{cleaned}'",
        )
        continue
    if not LEAD_RE.fullmatch(cleaned):
        if cleaned in seen_bad:
            continue
        seen_bad.add(cleaned)
        add_err(
            "malformed-lead-id",
            f"Lead ID '{cleaned}' does not match canonical 'L-EV<NN>-<domain>-<MM>'",
        )

# 14. Detect lingering literal placeholders in the body (defense-in-depth).
# Any `<sha256>`, `<EV_ID>`, `<CASE_ID>`, etc. outside HTML comments is a fail.
body_no_comments = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL)
PLACEHOLDER_RE = re.compile(r"<(CASE_ID|EV_ID|EV[NM]N|sha256|domain|YYYY-MM-DD[^>]*)>")
placeholders = PLACEHOLDER_RE.findall(body_no_comments)
if placeholders:
    add_err(
        "unfilled-placeholder",
        "Survey contains unresolved template placeholders outside HTML comments: "
        + ", ".join(sorted(set(f"<{p}>" for p in placeholders))),
    )

# ---- Output ----
result = {
    "survey":     SURVEY_PATH,
    "errors":     errors,
    "warnings":   warnings,
    "verdict":    "PASS" if not errors else "FAIL",
}

if MODE == "json":
    print(json.dumps(result, indent=2))
    sys.exit(0 if not errors else 1)

if not errors:
    print(f"lint-survey: PASS — {SURVEY_PATH}")
    sys.exit(0)

print(f"lint-survey: FAIL — {SURVEY_PATH} ({len(errors)} error(s))", file=sys.stderr)
for e in errors:
    print(f"ERR: {SURVEY_PATH}: {e['kind']}: {e['message']}", file=sys.stderr)
sys.exit(1)
PY
