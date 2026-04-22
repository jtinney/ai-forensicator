# Skill: Phase-Based Multi-Agent Orchestration

The orchestrator's protocol for running a DFIR case across the five phase
agents. Use this entrypoint when the case involves more than one evidence item
or when context would otherwise balloon past a single session.

## Why phases

Context stays small by pushing every phase's raw output to disk and passing
only pointers + short summaries back to the main context. The orchestrator
holds: case ID, evidence manifest pointer, leads queue pointer, phase state.
Nothing else.

## Agents

| Phase | Agent | Fan-out | Reads | Writes |
|-------|-------|---------|-------|--------|
| 1 Triage | `dfir-triage` | once | evidence dir | `analysis/manifest.md`, `analysis/preflight.md` |
| 2 Survey | `dfir-surveyor` | one per (evidence × domain) | manifest + one evidence item | `analysis/<domain>/survey-*.md`, appends `analysis/leads.md` |
| 3 Investigate | `dfir-investigator` | one per lead | one lead row + its pointer | `analysis/<domain>/findings.md`, may append `leads.md` |
| 4 Correlate | `dfir-correlator` | once per wave | all `findings.md` | `analysis/correlation.md` |
| 5 Report | `dfir-reporter` | once | correlation + findings | `reports/final.md` |

## Dispatch protocol

1. **Phase 1 — Triage** (blocking)
   - Invoke `dfir-triage` with case ID and evidence path.
   - On return, read `analysis/manifest.md` headers only (not full contents).

2. **Phase 2 — Survey** (parallel fan-out)
   - For each evidence item, pick applicable domains from its type:
     - disk → `sleuthkit`, `windows-artifacts`, `plaso-timeline`, `yara-hunting`
     - memory → `memory-analysis`, `yara-hunting`
     - logs / triage-bundle → `windows-artifacts`, `plaso-timeline`
   - Dispatch all `dfir-surveyor` invocations in a single message (parallel).
   - On return, read `analysis/leads.md` for the lead queue.

3. **Phase 3 — Investigate** (parallel waves)
   - Sort `leads.md` by priority (`high` first).
   - Dispatch one `dfir-investigator` per lead, **in parallel batches of ≤4**.
   - Leads that `escalate` will append new rows to `leads.md`; run another
     wave until no new `high` leads remain or you hit the budget cap.
   - Budget cap: 3 waves, or a case-specific cap from the prompt.

4. **Phase 4 — Correlate** (blocking)
   - Invoke `dfir-correlator` once after the last investigation wave.
   - If it appends new `high` leads, run one more investigation wave, then
     re-correlate. Hard stop after the second correlation pass.

5. **Phase 5 — Report** (blocking)
   - Invoke `dfir-reporter` once.
   - Relay its executive summary to the user with a pointer to
     `./reports/final.md`.

## Context hygiene rules (orchestrator)

- Never `Read` a survey file, findings.md, or raw tool output yourself. Those
  live in agents. Read only manifest.md, leads.md (headers/rows), and the
  executive summary from the reporter.
- Never re-run preflight or case-init. Triage owns that.
- When relaying agent output to the user, quote the agent's ≤summary, not the
  underlying artifacts.
- If an agent returns an error or blocker, log the blocker to
  `analysis/forensic_audit.log` and decide: retry with a narrower scope,
  re-assign to a different domain, or mark the lead as blocked in `leads.md`.

## When to use single-phase mode instead

If the case is a specific question against a single evidence item (e.g. "did
user X run cmd.exe on host Y at 14:00 UTC?"), skip this orchestration and
jump straight to the matching domain skill per the routing table in
`CLAUDE.md`. Phase-based orchestration pays off when evidence count ≥ 2 or
when the question is open-ended enough that multiple domains will be touched.

## Leads queue format

`./analysis/leads.md` is the shared queue between phases 2, 3, and 4.

```
| lead_id | evidence_id | domain | hypothesis | pointer | priority | status |
|---------|-------------|--------|------------|---------|----------|--------|
| L001    | EV01        | windows-artifacts | Scheduled task `\Updater` created 2026-04-18 12:03 UTC is not signed | analysis/windows-artifacts/survey-EV01.md#L42 | high | open |
```

- `status`: `open` → `in-progress` → `confirmed` / `refuted` / `escalated` / `blocked`.
- Investigator must update `status` when it finishes a lead.
- Correlator may add new `open` rows; it must not modify existing rows.
