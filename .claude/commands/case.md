---
description: Launch phase-based DFIR orchestration for a new or in-progress case
argument-hint: <CASE_ID> [evidence-path]
---

Run the phase-based multi-agent DFIR orchestration for case **$1**.

## Case workspace

Every case in this project lives under `./cases/<CASE_ID>/`. Your **first
action** must be to create that workspace (if missing) and `cd` into it.
All subsequent paths in `ORCHESTRATE.md` and the domain skills (`./evidence/`,
`./analysis/`, `./exports/`, `./reports/`) are relative to that workspace.

```bash
mkdir -p ./cases/$1/evidence
cd ./cases/$1
```

If the user passed an evidence path as the second argument (`${2:-}`), and
`./evidence/` is empty, copy the contents in (or symlink for large bundles)
before triage. If `./evidence/` is empty AND no second argument was given,
surface that to the user — Phase 2 onward needs at least one evidence item.

## Dispatch

Follow the dispatch protocol in @.claude/skills/ORCHESTRATE.md. The pipeline
runs **six phases**: triage → survey → investigate → correlate → report →
QA. The QA phase has authority to correct numerical / labeling /
lead-status errors in place before sign-off.

**Start by checking whether this is a new case or a resume:**

1. If `./analysis/manifest.md` does not exist → new case. Dispatch
   `dfir-triage` (Phase 1) with the case ID and evidence path.
2. If `./analysis/manifest.md` exists → resume. Follow the Resume Protocol in
   `ORCHESTRATE.md` to determine the lowest-remaining phase and continue
   from there without re-running earlier phases.

Operator preferences (from CLAUDE.md) apply: run fully autonomously, no
check-ins, deliver final findings only. If a phase blocks, pick the most
reasonable path and note it in the per-phase output. **Exception:** if
`./analysis/.intake-pending` exists or `intake-check.sh` reports blank
fields, surface the interview to the user — chain-of-custody intake is
the one place autonomy yields to operator input.

When Phase 6 completes, relay the QA verdict (`PASS` /
`PASS-WITH-CHANGES` / `BLOCKED`), the reporter's executive summary
verbatim, and pointers to `./reports/final.md` and
`./reports/qa-review.md` (paths still relative to the case workspace —
i.e. `./cases/$1/reports/...` from the project root).
