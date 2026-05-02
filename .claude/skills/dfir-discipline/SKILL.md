# Skill: DFIR Discipline (shared rules across all phase agents)

This skill is two parts:

- [`DISCIPLINE.md`](./DISCIPLINE.md) — the mandatory rules every phase
  agent (`dfir-triage`, `dfir-surveyor`, `dfir-investigator`,
  `dfir-correlator`, `dfir-reporter`, `dfir-qa`) must follow at every
  step.
- [`templates/`](./templates/) — canonical document skeletons each phase
  agent should instantiate when producing structured output. See
  [`templates/INVENTORY.md`](./templates/INVENTORY.md) for the full map of
  output types, which have templates, which rely on inline-in-agent specs,
  and which are mechanically enforced. Today this directory contains:
  - [`templates/survey-template.md`](./templates/survey-template.md) —
    Phase-2 surveyor output; lint enforced by
    `.claude/skills/dfir-bootstrap/lint-survey.sh`.
  - Seven worked `reference/example-survey.md` files under each domain
    skill (`windows-artifacts`, `network-forensics`, `memory-analysis`,
    `plaso-timeline`, `sleuthkit`, `yara-hunting`, `sigma-hunting`) that
    demonstrate the template populated for a realistic synthetic
    evidence item.

## Why this skill exists

The case7 post-mortem surfaced four recurring discipline failures across
multiple phase agents:

- **A** — investigator agents wrote synthetic UTC timestamps directly into
  `forensic_audit.log` instead of going through `audit.sh` (chain-of-custody
  defect). Enforced by the PreToolUse / PostToolUse hooks in
  `.claude/settings.json` and `dfir-bootstrap/audit-{verify,pretool-deny,retrofit}.sh`.
- **F** — investigators went deep on shellcode reverse-engineering before
  running cheap wire-level disconfirmation queries that would have refuted
  the lead in 30 seconds.
- **G** — correlators marked anomalies as "out of scope" even when the
  anomaly, if resolved differently, would have flipped a headline assertion.
- **H** — investigators answered the lead's exact hypothesis but did not
  exhaust the same-domain natural follow-up surface, deferring obvious
  Phase-3 work to Phase 4 correlator gaps.
- **B** — a later correlation pass amended findings via audit-log
  entries but did not back-port the corrections into the headline tables
  in `correlation.md`, leaving the report inconsistent with the audit
  trail.
- **K** — findings described adversary behavior in free text only, so
  technique coverage and per-tactic aggregation across evidence items had
  to be reconstructed manually. Rule K introduces an OPTIONAL `MITRE:`
  line on findings, validated against an offline TSV, and consumed by the
  correlator + reporter.

These rules apply across every agent. Codifying them in one file (instead of
duplicating in five agent prompts) keeps the prompts short and the rules
versionable.

## How agents use it

Every phase-agent prompt opens with:

> **MANDATORY:** read `.claude/skills/dfir-discipline/DISCIPLINE.md` before
> acting; the rules apply at every step. Your first audit-log entry of
> this invocation MUST include the marker `discipline_v2_loaded` in the
> result field.

The marker is a visible self-attestation: a future audit of the case can
grep for `discipline_v2_loaded` and confirm each agent invocation
acknowledged the rules. This is supplementary to (not a replacement for) the
hook-based enforcement.

## Versioning

When DISCIPLINE.md changes substantively, bump the marker (`discipline_v2_loaded`)
in this file and in each agent prompt simultaneously. The marker change makes
old vs. new agent runs distinguishable in the audit log.
