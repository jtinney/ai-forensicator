#!/usr/bin/env bash
# intake-check.sh — verify ./reports/00_intake.md has every chain-of-custody
# field populated. Returns 0 if all required fields are filled, nonzero
# (with the list of missing fields on stdout) otherwise.
#
# Required fields (line prefix → semantic name):
#   "- Source:"                 → who handed over the evidence
#   "- Acquired:"               → when/where it was collected
#   "- Received:"               → when it landed in this case dir
#   "- Evidence hash (SHA-256):"→ at least one hash recorded
#   "- Integrity verification:" → how the hash was verified
#   "- Reported incident:"      → the original report / ticket
#   "- Analyst priorities:"     → what the requester wants answered
#
# A field is "filled" if the line has any non-whitespace text after the
# colon that is NOT a placeholder ("TBD", "TODO", "FIXME", "N/A", "?",
# "-", empty). Marking a field "n/a — <reason>" counts as filled.
#
# Usage:
#   bash .claude/skills/dfir-bootstrap/intake-check.sh             # exits 0/1
#   bash .claude/skills/dfir-bootstrap/intake-check.sh --json      # JSON to stdout

set -u

INTAKE="./reports/00_intake.md"
MODE="${1:-text}"

if [[ ! -f "$INTAKE" ]]; then
    if [[ "$MODE" == "--json" ]]; then
        printf '{"intake":"missing","missing":["Source","Acquired","Received","Evidence hash (SHA-256)","Integrity verification","Reported incident","Analyst priorities"]}\n'
    else
        echo "intake-check: $INTAKE not found" >&2
    fi
    exit 2
fi

# Delegate parsing to Python — robust across whitespace / placeholder edge
# cases without resorting to fragile shell regex.
exec python3 - "$INTAKE" "$MODE" <<'PY'
import re, sys

path, mode = sys.argv[1], sys.argv[2]

required = [
    ("- Source:",                  "Source"),
    ("- Acquired:",                "Acquired"),
    ("- Received:",                "Received"),
    ("- Evidence hash (SHA-256):", "Evidence hash (SHA-256)"),
    ("- Integrity verification:",  "Integrity verification"),
    ("- Reported incident:",       "Reported incident"),
    ("- Analyst priorities:",      "Analyst priorities"),
]

placeholder = re.compile(r"^\s*(?:TBD|TODO|FIXME|N/A|\?|-)?\s*$", re.IGNORECASE)

with open(path, "r", encoding="utf-8") as fh:
    text = fh.read()

missing = []
for prefix, name in required:
    m = re.search(r"^" + re.escape(prefix) + r"(.*)$", text, re.MULTILINE)
    if not m:
        missing.append(name)
        continue
    val = m.group(1).strip()
    if placeholder.match(val):
        missing.append(name)

if mode == "--json":
    if missing:
        items = ",".join('"' + n.replace('"', '\\"') + '"' for n in missing)
        print('{"intake":"incomplete","missing":[' + items + ']}')
    else:
        print('{"intake":"complete","missing":[]}')
    sys.exit(0 if not missing else 1)

if missing:
    print(f"intake-check: FAIL — {len(missing)} blank field(s):", file=sys.stderr)
    for f in missing:
        print(f"  - {f}", file=sys.stderr)
    print("", file=sys.stderr)
    print("Run: bash .claude/skills/dfir-bootstrap/intake-interview.sh", file=sys.stderr)
    sys.exit(1)
else:
    print("intake-check: PASS — all required fields populated")
    sys.exit(0)
PY
