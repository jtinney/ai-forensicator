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

**Manifest gate (issue #12).** After case-init.sh has run (whether by
Phase 1 / dfir-triage on a new case or by a prior invocation on a
resume), run:

```bash
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/manifest-check.sh"
```

If the check exits non-zero, **refuse to dispatch any agent**. The script
appends a `BLOCKED` lead to `./analysis/leads.md` for each violation it
can autopolicy (bespoke hash files); other violations are surfaced on
stderr with a `[kind] path` summary and a one-line `fix:` line per row.
Surface the violations to the user verbatim, do NOT proceed with
triage / survey / investigate / correlate / report / QA, and stop.

The gate exists because case12 (12 archives at `evidence/Archives/*.zip`,
depth-2) hit the pre-#12 `case-init.sh:314` `find -maxdepth 1` walk and
silently produced an empty `manifest.md`. Agents then improvised
`analysis/archive_hashes.txt` outside the canonical ledger. With the
depth-walk fixed and `manifest-check.sh` as a deterministic gate, an
incomplete manifest stops the pipeline before any agent reads evidence.

**Start by checking whether this is a new case or a resume:**

1. If `./analysis/manifest.md` does not exist → new case. Dispatch
   `dfir-triage` (Phase 1) with the case ID and evidence path. After
   triage returns, run `manifest-check.sh` per the gate above before
   continuing to Phase 2.
2. If `./analysis/manifest.md` exists → resume. Run `manifest-check.sh`
   FIRST. If it fails, surface the violations and stop. Otherwise follow
   the Resume Protocol in `ORCHESTRATE.md` to determine the lowest-
   remaining phase and continue from there without re-running earlier
   phases.

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
