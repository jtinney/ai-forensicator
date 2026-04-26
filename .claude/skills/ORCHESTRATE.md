# Skill: Phase-Based Multi-Agent Orchestration

The orchestrator's protocol for running a DFIR case across the five phase
agents. Use this entrypoint when the case involves more than one evidence item
or when context would otherwise balloon past a single session.

## Why phases

Context stays small by pushing every phase's raw output to disk and passing
only pointers + short summaries back to the main context. The orchestrator
holds: case ID, evidence manifest pointer, leads queue pointer, phase state.
Nothing else.

## Canonical domain names

All agents and orchestrator dispatches use these six `DOMAIN` values. They
match the subdirs `case-init.sh` creates, so the findings.md stubs and
survey/findings output paths line up without translation.

| DOMAIN              | analysis subdir                  | skill file                                      | Purpose                                             |
|---------------------|----------------------------------|-------------------------------------------------|-----------------------------------------------------|
| `filesystem`        | `./analysis/filesystem/`         | `.claude/skills/sleuthkit/SKILL.md`             | TSK, carving, MFT, deleted entries                  |
| `timeline`          | `./analysis/timeline/`           | `.claude/skills/plaso-timeline/SKILL.md`        | Plaso super-timelines, slices                       |
| `windows-artifacts` | `./analysis/windows-artifacts/`  | `.claude/skills/windows-artifacts/SKILL.md`     | EZ Tools, EVTX, registry, Prefetch, Amcache         |
| `memory`            | `./analysis/memory/`             | `.claude/skills/memory-analysis/SKILL.md`       | Volatility 3, Memory Baseliner                      |
| `network`           | `./analysis/network/`            | `.claude/skills/network-forensics/SKILL.md`     | tshark, Zeek, Suricata, pcap triage, beaconing      |
| `yara`              | `./analysis/yara/`               | `.claude/skills/yara-hunting/SKILL.md`          | YARA IOC sweeps, Velociraptor                       |

## Agents

| Phase | Agent | Model | Fan-out | Reads | Writes |
|-------|-------|-------|---------|-------|--------|
| 1 Triage | `dfir-triage` | haiku | once | evidence dir | `analysis/manifest.md`, `analysis/preflight.md`, `analysis/leads.md` header |
| 2 Survey | `dfir-surveyor` | sonnet | one per (evidence × domain) | manifest + one evidence item | `analysis/<domain>/survey-*.md`, appends `leads.md` |
| 3 Investigate | `dfir-investigator` | sonnet | one per lead | one lead row + its pointer | `analysis/<domain>/findings.md`, updates `leads.md` status, may append |
| 4 Correlate | `dfir-correlator` | **opus** | once per wave | all `findings.md` | `analysis/correlation.md`, may append `L-CORR-*` leads |
| 5 Report | `dfir-reporter` | haiku | once | correlation + findings | `reports/final.md` + `reports/stakeholder-summary.md` |

## Lead ID conventions (collision-free under parallel fan-out)

| Source | ID prefix | Example |
|--------|-----------|---------|
| Surveyor (phase 2) | `L-<EVIDENCE_ID>-<DOMAIN>-NN` | `L-EV01-memory-01` |
| Investigator escalation (phase 3) | `L-<EVIDENCE_ID>-<DOMAIN>-eNN` | `L-EV01-memory-e01` |
| Correlator gap (phase 4) | `L-CORR-NN` | `L-CORR-03` |

Each prefix is globally unique per its source, so agents running in parallel
never need shared locks to pick an ID. `NN` is zero-padded and counter-scoped
to the invocation that produced it.

## Dispatch protocol

1. **Phase 1 — Triage** (blocking)
   - Invoke `dfir-triage` with case ID and evidence path.
   - On return, read `analysis/manifest.md` headers only (not full contents).

2. **Phase 2 — Survey** (parallel fan-out)
   - For each evidence item, pick applicable domains from its type:
     - `disk` → `filesystem`, `windows-artifacts`, `timeline`, `yara`
     - `memory` → `memory`, `yara`
     - `logs` / `triage-bundle` → `windows-artifacts`, `timeline`
     - `pcap` → `network`, `yara`, `timeline`
     - `netlog` → `network`, `timeline`
   - Dispatch `dfir-surveyor` invocations in **batches of ≤ 3** (not all at
     once). For batches that include a `network`-domain surveyor, reduce to
     **≤ 2** per batch — Zeek and Suricata are full-pcap replay tools and
     saturate CPU/RAM when run concurrently. Complete each batch before
     starting the next; append leads as each batch returns.
   - On return, read `analysis/leads.md` for the lead queue.

3. **Phase 3 — Investigate** (parallel waves)
   - Sort `leads.md` rows with `status=open` by `priority` (`high` first).
   - Dispatch one `dfir-investigator` per lead in parallel batches. Batch size
     depends on domain:
     - `filesystem`, `windows-artifacts`, `yara`, `timeline` → **≤ 4** per
       batch (I/O-bound; CPU headroom remains)
     - `network`, `memory` → **≤ 2** per batch (CPU/RAM-bound: Zeek, Suricata,
       Volatility)
     Mixed-domain waves: if any lead in the wave is `network` or `memory`, cap
     the entire batch at ≤ 2.
     The investigator flips its lead's status to `in-progress` before it
     starts, so concurrent waves do not double-take a lead.
   - Leads that `escalate` will append new `-e` rows; run another wave until
     no new `high` leads remain or you hit the budget cap.
   - Budget cap: 3 waves, or a case-specific cap from the prompt.

4. **Phase 4 — Correlate** (blocking)
   - **Baseline-artifact gate (BEFORE invoking the correlator):** for each
     domain that has `./analysis/<DOMAIN>/findings.md` non-empty (i.e. an
     investigator wrote to it), run
     `bash .claude/skills/dfir-bootstrap/baseline-check.sh <DOMAIN>`. For each
     domain whose JSON output reports `missing != []`, append a lead row
     `L-CORR-BASELINE-<DOMAIN>-<NN>` to `./analysis/leads.md` at priority
     `high`, status `open`, hypothesis
     `Re-generate <missing-list> for <DOMAIN>`. **Correlation does NOT
     proceed around a baseline gap** — run a focused Phase 3 wave to fill
     the gap, then re-attempt the gate. Hard stop after the third
     baseline-fill wave; if still missing, mark `blocked` and proceed to
     correlation with an explicit "baseline-incomplete" caveat in the
     correlator's output.
   - Invoke `dfir-correlator` once after the gate passes.
   - If it appends new `L-CORR-*` leads (non-baseline), run one more
     investigation wave, then re-correlate. Hard stop after the second
     correlation pass.

5. **Phase 5 — Report** (blocking)
   - Invoke `dfir-reporter` once. It produces two reports:
     - `./reports/final.md` — technical case report (analysts).
     - `./reports/stakeholder-summary.md` — decision-focused briefing for
       non-technical senior stakeholders, written per
       `.claude/skills/exec-briefing/SKILL.md`.
   - Relay the executive summary from `final.md` and the one-line posture
     from the stakeholder briefing, with pointers to both files.

## Context hygiene rules (orchestrator)

- Never `Read` a survey file, findings.md, or raw tool output yourself. Those
  live in agents. Read only `manifest.md`, `leads.md` (rows only), and the
  executive summary from the reporter.
- Never re-run preflight or case-init. Triage owns that.
- When relaying agent output to the user, quote the agent's ≤summary, not the
  underlying artifacts.
- If an agent returns an error or blocker, log the blocker to
  `analysis/forensic_audit.log` and decide: retry with a narrower scope,
  re-assign to a different domain, or mark the lead as `blocked` in
  `leads.md`.

## Resume protocol (when a session stops mid-case)

Case state lives on disk, so the orchestrator can pick up without re-running
earlier phases. On resume:

1. Read `./analysis/manifest.md` — if absent, start from Phase 1.
2. Read `./analysis/leads.md` — if absent or only has the header, start from
   Phase 2 (surveyor fan-out for every evidence item).
2.5. **Baseline-artifact gate (per domain).** For each `./analysis/<DOMAIN>/`
   subdir that contains a `survey-EV*.md`, run
   `bash .claude/skills/dfir-bootstrap/baseline-check.sh <DOMAIN>`. For each
   missing artifact reported, append a lead row
   `L-BASELINE-<DOMAIN>-<NN>` at priority `high`, status `open`, hypothesis
   `Re-generate <missing-list> for <DOMAIN>`. **The next Phase 3 wave runs
   `L-BASELINE-*` leads BEFORE any other open lead** — missing baselines
   mean later pivots are operating on an incomplete picture and may need
   re-doing.
3. Count leads by status:
   - Any `status=in-progress`? That invocation died mid-run. Reset those rows
     to `open` (the investigator is idempotent on re-run because it re-reads
     the pointer and overwrites its own findings entry timestamp).
   - Any `status=open` with priority `high`? Run another Phase 3 wave.
     Sort `L-BASELINE-*` first, then everything else.
   - All leads `confirmed`/`refuted`/`escalated`/`blocked`? Check for
     `./analysis/correlation.md`:
     - Missing → run Phase 4 (which itself has a baseline-artifact gate —
       see Phase 4 above).
     - Present but newer `L-CORR-*` leads are `open` → one more Phase 3 wave,
       then Phase 4 again.
     - Correlation stable → Phase 5.
4. Check for `./reports/final.md`:
   - Missing → run Phase 5.
   - Present → relay its executive summary, confirm done.

Never delete or truncate `leads.md`, `findings.md`, or `correlation.md` on
resume. They are the chain-of-custody trail.

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
| L-EV01-windows-artifacts-01 | EV01 | windows-artifacts | Scheduled task `\Updater` created 2026-04-18 12:03 UTC is not signed | analysis/windows-artifacts/survey-EV01.md#L42 | high | open |
| L-EV01-memory-01 | EV01 | memory | Unsigned DLL loaded by lsass.exe (PID 624) | analysis/memory/survey-EV01.md#L88-L94 | high | open |
| L-EV01-memory-e01 | EV01 | memory | lsass DLL was loaded via reflective injection (escalation from L-EV01-memory-01) | analysis/memory/findings.md#L120 | high | open |
| L-CORR-01 | — | cross | Timestamp gap between Prefetch run (12:03) and memory PID (13:47) needs filesystem pivot | analysis/correlation.md#L55 | high | open |
```

- `pointer` MUST be line-anchored (`<file>#L<n>` or `<file>#L<n>-L<m>`). A
  bare filename forces the investigator to re-scan the survey and wastes
  context.
- `status`: `open` → `in-progress` → `confirmed` / `refuted` / `escalated` / `blocked`.
- Investigator updates its lead's `status` before and after its work.
- Correlator may add `L-CORR-*` rows; it must not modify existing rows.
