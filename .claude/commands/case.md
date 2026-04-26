---
description: Launch phase-based DFIR orchestration for a new or in-progress case
argument-hint: <CASE_ID> [evidence-path]
---

Run the phase-based multi-agent DFIR orchestration for case **$1** with
evidence at `${2:-./evidence/}`.

Follow the dispatch protocol in @.claude/skills/ORCHESTRATE.md. The
pipeline runs **six phases**: triage → survey → investigate → correlate
→ report → QA. The QA phase has authority to correct numerical /
labeling / lead-status errors in place before sign-off.

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
`./reports/qa-review.md`.
