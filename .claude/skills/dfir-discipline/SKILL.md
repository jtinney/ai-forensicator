# Skill: DFIR Discipline (shared rules across all phase agents)

This skill is one file: [`DISCIPLINE.md`](./DISCIPLINE.md). It contains the
mandatory rules that every phase agent (`dfir-triage`, `dfir-surveyor`,
`dfir-investigator`, `dfir-correlator`, `dfir-reporter`, `dfir-qa`) must
follow at every step.

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
> this invocation MUST include the marker `discipline_v1_loaded` in the
> result field.

The marker is a visible self-attestation: a future audit of the case can
grep for `discipline_v1_loaded` and confirm each agent invocation
acknowledged the rules. This is supplementary to (not a replacement for) the
hook-based enforcement.

## Versioning

When DISCIPLINE.md changes substantively, bump the marker (`discipline_v2_loaded`)
in this file and in each agent prompt simultaneously. The marker change makes
old vs. new agent runs distinguishable in the audit log.
