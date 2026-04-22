---
description: Launch phase-based DFIR orchestration for a new or in-progress case
argument-hint: <CASE_ID> [evidence-path]
---

Run the phase-based multi-agent DFIR orchestration for case **$1** with
evidence at `${2:-./evidence/}`.

Follow the dispatch protocol in @.claude/skills/ORCHESTRATE.md.

**Start by checking whether this is a new case or a resume:**

1. If `./analysis/manifest.md` does not exist → new case. Dispatch
   `dfir-triage` (Phase 1) with the case ID and evidence path.
2. If `./analysis/manifest.md` exists → resume. Follow the Resume Protocol in
   `ORCHESTRATE.md` to determine the lowest-remaining phase and continue
   from there without re-running earlier phases.

Operator preferences (from CLAUDE.md) apply: run fully autonomously, no
check-ins, deliver final findings only. If a phase blocks, pick the most
reasonable path and note it in the per-phase output.

When Phase 5 completes, relay the reporter's executive summary verbatim and
the pointer to `./reports/final.md`.
