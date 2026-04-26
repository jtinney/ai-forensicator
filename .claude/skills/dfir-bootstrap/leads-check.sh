#!/usr/bin/env bash
# leads-check.sh — verify ./analysis/leads.md satisfies the
# terminal-status invariant. Returns 0 if every lead is in an acceptable
# end-state (or has a documented justification), nonzero otherwise.
#
# Acceptable end-of-case states:
#   - confirmed / refuted               — terminal, no further action
#   - open with priority=low AND notes  — explicit non-blocking deferral
#   - blocked with notes                — external dependency documented
#
# Violations:
#   - escalated whose CHILD lead is terminal (parent must transition too)
#   - escalated with NO child lead (the escalation never produced a lead)
#   - in-progress (the investigator never committed a verdict)
#   - open at priority high/med (must be worked or downgraded with cause)
#
# Usage:
#   bash .claude/skills/dfir-bootstrap/leads-check.sh             # exits 0/1
#   bash .claude/skills/dfir-bootstrap/leads-check.sh --json      # JSON to stdout

set -u

LEADS="./analysis/leads.md"
MODE="${1:-text}"

if [[ ! -f "$LEADS" ]]; then
    if [[ "$MODE" == "--json" ]]; then
        echo '{"leads":"missing","violations":[]}'
    else
        echo "leads-check: $LEADS not found" >&2
    fi
    exit 2
fi

exec python3 - "$LEADS" "$MODE" <<'PY'
import json, re, sys

path, mode = sys.argv[1], sys.argv[2]

# Parse markdown table. We treat any row beginning with "| L-" as a lead.
LEAD_RE = re.compile(r"^\|\s*(L-\S+)\s*\|")

with open(path, "r", encoding="utf-8") as fh:
    lines = fh.readlines()

leads = []   # list of dicts {id, evidence, domain, hypothesis, pointer, priority, status, notes, line}
for i, ln in enumerate(lines, start=1):
    if not LEAD_RE.match(ln):
        continue
    cells = [c.strip() for c in ln.strip().strip("|").split("|")]
    if len(cells) < 7:
        continue
    lead = {
        "id":         cells[0],
        "evidence":   cells[1] if len(cells) > 1 else "",
        "domain":     cells[2] if len(cells) > 2 else "",
        "hypothesis": cells[3] if len(cells) > 3 else "",
        "pointer":    cells[4] if len(cells) > 4 else "",
        "priority":   cells[5] if len(cells) > 5 else "",
        "status":     cells[6] if len(cells) > 6 else "",
        "notes":      cells[7] if len(cells) > 7 else "",
        "line":       i,
    }
    leads.append(lead)

by_id = {l["id"]: l for l in leads}

def child_ids(parent_id):
    # A "direct child" of parent P is a lead Q such that P is the longest
    # known-lead prefix of Q. This ensures grandchildren do not register
    # as children of the original parent — escalation chains go through
    # one hop at a time, and a parent's hypothesis is "answered" when its
    # direct children are terminal, regardless of what follow-on
    # questions those children spawned.
    prefix = parent_id + "-"
    out = []
    for lid in by_id:
        if lid == parent_id or not lid.startswith(prefix):
            continue
        # Walk every other lead; if any is a strictly tighter prefix of
        # lid than parent_id, then parent_id is not lid's nearest ancestor.
        is_direct_child = True
        for other in by_id:
            if other == parent_id or other == lid:
                continue
            if lid.startswith(other + "-") and other.startswith(prefix):
                is_direct_child = False
                break
        if is_direct_child:
            out.append(lid)
    return out

violations = []

for lead in leads:
    lid     = lead["id"]
    status  = lead["status"].lower()
    pri     = lead["priority"].lower()
    notes   = lead["notes"]
    line    = lead["line"]

    # 1. in-progress at end-of-case is always a violation
    if status == "in-progress":
        violations.append({
            "lead_id": lid, "line": line, "kind": "in-progress",
            "fix":     "investigator died mid-run; reset to open or transition to terminal verdict",
        })
        continue

    # 2. escalated parent — child must exist and parent must transition once child is terminal
    if status == "escalated":
        children = child_ids(lid)
        if not children:
            violations.append({
                "lead_id": lid, "line": line, "kind": "escalated-no-child",
                "fix":     "escalated parent with no -eNN child; either create child lead or transition parent to confirmed/refuted",
            })
            continue
        # If any child is terminal, the parent's hypothesis was answered through it
        terminal_children = [c for c in children if by_id[c]["status"].lower() in ("confirmed", "refuted")]
        if terminal_children and len(terminal_children) == len(children):
            violations.append({
                "lead_id": lid, "line": line, "kind": "escalated-terminal-child",
                "fix":     f"all children terminal ({', '.join(terminal_children)}); transition parent to confirmed/refuted matching the child verdict",
                "children": children,
            })
            continue

    # 3. open at high/med priority is a violation unless explicitly deferred
    if status == "open":
        if pri not in ("low",):
            violations.append({
                "lead_id": lid, "line": line, "kind": "open-not-low",
                "fix":     "high/med open lead at case close; either work it or downgrade priority with explicit non-blocking justification in notes",
            })
            continue
        if not notes or len(notes.strip()) < 4:
            violations.append({
                "lead_id": lid, "line": line, "kind": "open-low-no-notes",
                "fix":     "low-priority open lead must document non-blocking justification in notes column",
            })
            continue

    # 4. blocked must have notes documenting the external dependency
    if status == "blocked":
        if not notes or len(notes.strip()) < 4:
            violations.append({
                "lead_id": lid, "line": line, "kind": "blocked-no-notes",
                "fix":     "blocked lead must document the external dependency in notes column",
            })
            continue

    # 5. anything else is a typo / unrecognized status
    if status not in ("confirmed", "refuted", "escalated", "open", "in-progress", "blocked"):
        violations.append({
            "lead_id": lid, "line": line, "kind": "unknown-status",
            "fix":     f"status '{status}' is not one of confirmed/refuted/escalated/open/in-progress/blocked",
        })

# Counts by status (informational)
counts = {}
for l in leads:
    s = l["status"].lower() or "(blank)"
    counts[s] = counts.get(s, 0) + 1

if mode == "--json":
    print(json.dumps({
        "leads_total": len(leads),
        "counts":      counts,
        "violations":  violations,
        "verdict":     "PASS" if not violations else "FAIL",
    }, indent=2))
    sys.exit(0 if not violations else 1)

if not violations:
    print(f"leads-check: PASS — {len(leads)} leads, all in acceptable end-state")
    print("  counts:", ", ".join(f"{k}={v}" for k,v in sorted(counts.items())))
    sys.exit(0)

print(f"leads-check: FAIL — {len(violations)} violation(s) across {len(leads)} leads", file=sys.stderr)
print(f"  counts: " + ", ".join(f"{k}={v}" for k,v in sorted(counts.items())), file=sys.stderr)
print("", file=sys.stderr)
for v in violations:
    print(f"  {v['lead_id']:40s} (line {v['line']:>3}) [{v['kind']}]", file=sys.stderr)
    print(f"    -> {v['fix']}", file=sys.stderr)
sys.exit(1)
PY
