# Skill: Phase-Based Multi-Agent Orchestration

<role>
The orchestrator's protocol for running a DFIR case across the six phase
agents. Use this entrypoint when the case involves more than one evidence item
or when context would otherwise balloon past a single session.
</role>

<rules-binding>
This skill binds the orchestrator to DISCIPLINE §A (audit-log integrity), §B
(headline revalidation), §F (hypothesis-first), §G (scope closure), §H (lead
surface), §I (no lead un-worked), §J (intake completeness), §K (ATT&CK
tagging), §L (multi-evidence path encoding), §P-pcap, §P-diskimage, §P-tools,
and §P-yara. Every dispatched agent invocation MUST emit the marker
`discipline_v2_loaded` in its return result; the orchestrator MUST verify
that marker before treating the agent's output as authoritative.
</rules-binding>

## Case workspace

Every case lives under `./cases/<CASE_ID>/`. First action for any new or
resuming case is to `cd` there:

```bash
mkdir -p "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>/evidence"
cd "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>"
```

All `./evidence/`, `./working/`, `./analysis/`, `./exports/`, `./reports/`
paths in this file (and in domain skills, agents, TRIAGE.md) are relative to
that workspace. Project-level scripts live under
`${CLAUDE_PROJECT_DIR}/.claude/skills/...`.

## Why phases

Context stays small by pushing every phase's raw output to disk and passing
only pointers + short summaries back. The orchestrator holds: case ID,
evidence manifest pointer, leads queue pointer, phase state. Nothing else.

## Canonical domain names

All dispatches use these seven `DOMAIN` values; they match the subdirs
`case-init.sh` creates so survey and findings paths line up without
translation. `findings.md` is not pre-created — the surveyor and investigator
write it on first append.

| DOMAIN              | analysis subdir                  | skill file                                      | Purpose                                             |
|---------------------|----------------------------------|-------------------------------------------------|-----------------------------------------------------|
| `filesystem`        | `./analysis/filesystem/`         | `.claude/skills/sleuthkit/SKILL.md`             | TSK, carving, MFT, deleted entries                  |
| `timeline`          | `./analysis/timeline/`           | `.claude/skills/plaso-timeline/SKILL.md`        | Plaso super-timelines, slices                       |
| `windows-artifacts` | `./analysis/windows-artifacts/`  | `.claude/skills/windows-artifacts/SKILL.md`     | EZ Tools, EVTX, registry, Prefetch, Amcache         |
| `memory`            | `./analysis/memory/`             | `.claude/skills/memory-analysis/SKILL.md`       | Volatility 3, Memory Baseliner                      |
| `network`           | `./analysis/network/`            | `.claude/skills/network-forensics/SKILL.md`     | tshark, Zeek, Suricata, pcap triage, beaconing      |
| `yara`              | `./analysis/yara/`               | `.claude/skills/yara-hunting/SKILL.md`          | YARA IOC sweeps, Velociraptor                       |
| `sigma`             | `./analysis/sigma/`              | `.claude/skills/sigma-hunting/SKILL.md`         | Chainsaw / Hayabusa Sigma rule sweeps over EVTX     |

## Agents

| Phase | Agent | Model | Fan-out | Reads | Writes |
|-------|-------|-------|---------|-------|--------|
| 1 Triage | `dfir-triage` | haiku | once | evidence dir | `analysis/manifest.md`, `analysis/preflight.md`, `analysis/leads.md` header, `reports/00_intake.md` (interview-completed) |
| 2 Survey | `dfir-surveyor` | sonnet | one per (evidence × domain) | manifest + one evidence item | `analysis/<domain>/survey-*.md`, appends `leads.md` |
| 3 Investigate | `dfir-investigator` | sonnet | one per lead | one lead row + its pointer | `analysis/<domain>/findings.md`, updates `leads.md` status, appends |
| 4 Correlate | `dfir-correlator` | **opus** | once per correlation-loop iteration (drives Phase 3 re-dispatch until convergence) | all `findings.md` | `analysis/correlation.md`, appends `correlation-history.md` row, appends `L-CORR-*` leads |
| 5 Report | `dfir-reporter` | haiku | once | correlation + findings | `reports/final.md` + `reports/stakeholder-summary.md` |
| 6 QA | `dfir-qa` | **opus** | self-loops to convergence | all case docs + authoritative artifacts | corrects errors in place via `Edit`, transitions non-terminal leads, queues prior phases for re-dispatch via `analysis/.qa-redispatch-pending`, writes `reports/qa-review.md` |

## Lead ID conventions (collision-free under parallel fan-out)

| Source | ID prefix | Example |
|--------|-----------|---------|
| Surveyor (phase 2) | `L-<EVIDENCE_ID>-<DOMAIN>-NN` | `L-EV01-memory-01` |
| Investigator escalation (phase 3) | `L-<EVIDENCE_ID>-<DOMAIN>-eNN` | `L-EV01-memory-e01` |
| Correlator gap (phase 4) | `L-CORR-NN` | `L-CORR-03` |
| Correlator re-extraction (phase 4, sequential mode) | `L-EXTRACT-RE-NN` | `L-EXTRACT-RE-01` |
| Bootstrap disk-pressure block (phase 1) | `L-EXTRACT-DISK-NN` | `L-EXTRACT-DISK-01` |

Each prefix is globally unique per source — parallel agents need no shared
lock. `NN` is zero-padded and counter-scoped to the invocation.

<protocol name="Forward dispatch">

<phase n="1" name="Triage" mode="blocking">
  <step n="1">Invoke `dfir-triage` with case ID and evidence path. Triage runs `extraction-plan.sh` before `case-init.sh`; the resulting `./analysis/extraction-plan.md` decides bulk vs. sequential staging.</step>
  <step n="2">On return, read `analysis/manifest.md` headers only.</step>
  <step n="3">Read the `Mode` field of `./analysis/extraction-plan.md` and branch:
    - `bulk` → advance to Phase 2.
    - `sequential` → enter `<sequential-extraction>` (below) to drive Phases 2/3 stage-by-stage. Do NOT fan out a single Phase 2 wave across all archives.
    - `blocked` → surface the `L-EXTRACT-DISK-NN` lead (planner appended a BLOCKED row to `leads.md`) and stop. Operator frees disk or remounts before any further phase runs.
  </step>
</phase>

<phase n="2" name="Survey" mode="parallel-fan-out">
  <step n="1">For each evidence item, pick applicable domains by type:
    - `disk` → `filesystem`, `windows-artifacts`, `timeline`, `yara`, `sigma`
    - `memory` → `memory`, `yara`
    - `logs` / `triage-bundle` → `windows-artifacts`, `timeline`, `sigma`
    - `pcap` → `network`, `yara`, `timeline`
    - `netlog` → `network`, `timeline`
  </step>
  <step n="2">Dispatch `dfir-surveyor` invocations in batches of **≤ 3**. Batches that include a `network`-domain surveyor cap at **≤ 2** (Zeek and Suricata are full-pcap replay tools and saturate CPU/RAM concurrently). Complete each batch before starting the next; append leads as each batch returns.</step>
  <step n="3" name="survey-lint-gate">After each surveyor returns, run `bash .claude/skills/dfir-bootstrap/lint-survey.sh ./analysis/<DOMAIN>/survey-EV<NN>.md`. Exit 0 = structurally compliant with `.claude/skills/dfir-discipline/templates/survey-template.md`. Nonzero = lint printed `ERR:` lines per violation; **block Phase 3 dispatch for that (evidence × domain) pair** and either (a) re-dispatch the same surveyor with the lint output included so it fixes in place, OR (b) surface as `SURVEY-LINT-FAIL: <pair>` when a re-run does not resolve. Passing lint is a precondition for Phase-3 dispatch off that survey.
  </step>
  <step n="4">On return, read `analysis/leads.md` for the lead queue.</step>
</phase>

<sequential-extraction trigger="extraction-plan.md mode == sequential">
  Triage stages stage 1 (smallest archive). Drive the rest per-archive, NOT in a single Phase 2 wave. For each stage `N` in the plan's stage table (`1..K`):
  1. **Extract** stage `N` if not yet on disk (single-element evidence subdir to case-init's bundle loop, or reuse triage's archive-specific extract). Tree at `./working/<basename>/`. Audit: `[disk] stage N: extract <archive>` via `audit.sh`.
  2. **Survey** — Phase 2 fan-out ONLY for `(stage-N evidence × applicable domains)`. Other stages remain unexpanded; surveyor MUST NOT touch them.
  3. **Investigate** — Phase 3 wave ONLY on `leads.md` rows from stage `N`'s surveys (`L-<EVID-of-stage-N>-...`). Honor the lead terminal-status invariant before advancing.
  4. **Cleanup** — once stage `N`'s investigators settle, run `bash .claude/skills/dfir-bootstrap/extraction-cleanup.sh <basename-of-stage-N>`. Helper deletes ONLY `./working/<basename>/`; `./analysis/<domain>/`, `./exports/**`, `./analysis/manifest.md`, `./analysis/leads.md` preserved. Helper writes its own audit row; orchestrator ALSO writes `[disk] stage N: cleanup <archive> deleted=<N> files`.
  5. **Advance** — increment `N`. `N <= K` repeats from step 1; else proceed to Phase 4.

  `L-EXTRACT-RE-NN` re-extraction leads (correlator-driven; Phase 4) trigger an additional cycle: re-extract the named archive (when the lead names a path subset, restrict via `unzip <archive> "<subset>/*"` or `tar --wildcards`), run a scoped Phase 2/3 mini-wave, then call `extraction-cleanup.sh`.

  All stage-transition audit rows go through `audit.sh` per §A.1 (NEVER `>>` directly): `[disk] stage <N>: extract <archive>` and `[disk] stage <N>: cleanup <archive> deleted=<N> files`.

  <footnote>Per-stage iteration holds the disk-pressure invariant — at most one archive's expanded tree on disk at once — while preserving chain-of-custody via retained `./analysis/`, `./exports/`, and `manifest.md` across cleanups.</footnote>
</sequential-extraction>

<phase n="3" name="Investigate" mode="parallel-waves">
  <step n="1">Sort `leads.md` rows with `status=open` by `priority` (`high` first).</step>
  <step n="2">Dispatch one `dfir-investigator` per lead in parallel batches:
    - `filesystem`, `windows-artifacts`, `yara`, `sigma`, `timeline` → **≤ 4** per batch (I/O-bound)
    - `network`, `memory` → **≤ 2** per batch (CPU/RAM-bound: Zeek, Suricata, Volatility)
    - Mixed-domain waves: any `network` or `memory` lead caps the entire batch at **≤ 2**.
    The investigator flips its lead's status to `in-progress` before starting, so concurrent waves do not double-take a lead.
  </step>
  <step n="3">Leads that `escalate` append new `-e` rows; run another wave until no new `high` leads remain. Investigation waves run as long as new `high`-priority leads keep appearing. The Phase 4 convergence guard is the case-wide terminating condition.</step>
</phase>

<phase n="4" name="Correlate" mode="blocking-convergence-loop">
  <step n="1" name="baseline-artifact-gate">For each domain whose `./analysis/<DOMAIN>/findings.md` is non-empty, run `bash .claude/skills/dfir-bootstrap/baseline-check.sh <DOMAIN>`. Each domain reporting `missing != []` gets a lead `L-BASELINE-<DOMAIN>-<NN>` (priority `high`, status `open`, hypothesis `Re-generate <missing-list> for <DOMAIN>`). **Correlation does NOT proceed around a baseline gap** — run a focused Phase 3 wave to fill it, then re-attempt the gate. When the artifact still cannot be regenerated after remediation, mark the lead `blocked` with a documented external-dependency reason and proceed with an explicit "baseline-incomplete" caveat in the correlator's output.</step>
  <step n="2" name="leads-check-gate">Run `bash .claude/skills/dfir-bootstrap/leads-check.sh`. Nonzero exit forces a focused remediation wave before invoking the correlator.</step>
  <step n="3" name="convergence-loop">For each iteration `n` (starting at `n=1`):
    1. Invoke `dfir-correlator`. It reads the prior `correlation.md` (when present), computes a since-last-correlation diff, then rewrites the file.
    2. Capture `SHA_n = sha256sum analysis/correlation.md | awk '{print $1}'`.
    3. Append a row to `./analysis/correlation-history.md`. On iteration 1, create the file with header `# Correlation-loop convergence ledger` followed by the columns `| utc_timestamp | wave_n | sha256 | new_L-CORR_count | terminal_L-CORR_count |`. `new_L-CORR_count` = `L-CORR-*` leads added this iteration; `terminal_L-CORR_count` = `L-CORR-*` rows in `leads.md` whose status is `confirmed` / `refuted` / `blocked`.
    4. Audit-log row via `audit.sh`: `[correlation] wave <n> sha=<sha> leads_new=<x> leads_terminal=<y>`. Grepping `[correlation]` over `forensic_audit.log` enumerates correlation history.
    5. **Continue** when (a) any `L-CORR-*` lead is non-terminal OR (b) `SHA_n != SHA_(n-1)` — dispatch a focused Phase 3 wave for the open `L-CORR-*` leads and return to step 1. **Exit** when every `L-CORR-*` lead is terminal AND `SHA_n == SHA_(n-1)` — the case has converged; advance to Phase 5.
  </step>
  <step n="4" name="L-EXTRACT-RE-handling">When the correlator appends `L-EXTRACT-RE-NN` re-extraction leads (only valid in `mode: sequential`), drive a focused Phase-2/3 mini-wave: re-stage the named archive (or named path subset), run scoped surveyor + investigator(s), call `extraction-cleanup.sh` to release the bytes, then return to the convergence loop's next iteration. The lead's `hypothesis` field names the archive + path subset and points at the `correlation.md` line that motivated the re-extraction.</step>
  <step n="5" name="pathological-loop-detector">When two consecutive iterations produce identical `correlation.md` hashes (`SHA_n == SHA_(n-1)`) but `L-CORR-*` leads remain non-terminal, the loop has stalled. Halt:
    1. Append audit-log row: `[correlation] pathological-loop halt: hash=<sha> wave=<n> nonterminal_leads=<csv-list>`.
    2. Mark each non-terminal `L-CORR-*` lead `blocked` in `leads.md` with note `convergence reached but lead still non-terminal — manual review required`.
    3. Advance to Phase 5. The QA agent surfaces the halt event in `qa-review.md`.
  </step>
</phase>

<phase n="5" name="Report" mode="blocking">
  <step n="1" name="leads-check-gate">Run `bash .claude/skills/dfir-bootstrap/leads-check.sh`. Nonzero forces remediation before the reporter runs.</step>
  <step n="2" name="intake-check-gate">Run `bash .claude/skills/dfir-bootstrap/intake-check.sh`. Nonzero forces intake completion (§J) before the reporter runs.</step>
  <step n="3">Invoke `dfir-reporter` once. Outputs:
    - `./reports/final.md` — technical case report (analysts).
    - `./reports/stakeholder-summary.md` — decision-focused briefing per `.claude/skills/exec-briefing/SKILL.md`.
  </step>
  <step n="4">Relay the executive summary from `final.md` and the one-line posture from the stakeholder briefing, with pointers to both files. **Do NOT close the case yet** — Phase 6 runs before sign-off.</step>
</phase>

<phase n="6" name="QA" mode="blocking-self-loop">
  <step n="1" name="intake-check-gate">Run `intake-check.sh`. Nonzero forces remediation before invoking QA.</step>
  <step n="2">Invoke `dfir-qa`. It cross-checks every case document against authoritative artifacts on disk, enforces the lead-status terminal invariant, gates on intake completeness, corrects numerical / labeling / lead-status errors in place via `Edit`, **and queues any prior phase for re-dispatch** by appending rows to `./analysis/.qa-redispatch-pending`.</step>
  <step n="3">Verdicts per pass:
    - `PASS` — no changes required this pass.
    - `PASS-WITH-CHANGES` — corrections applied this pass.
    - `BLOCKED` — a fix requires a brand-new investigation hypothesis (not a re-run). Surface the BLOCKED items to the user and route any new hypothesis through correlator → Phase 3.
  </step>
  <step n="4" name="re-dispatch-loop">Read `./analysis/.qa-redispatch-pending` (when present and non-empty). Per row:
    - `phase=1`, `target=EV<NN>` → `dfir-triage` against that single evidence item (pass `EVIDENCE_ID=EV<NN>`; triage is idempotent and re-classifies that row).
    - `phase=2`, `target=EV<NN> × <DOMAIN>` → `dfir-surveyor` with that pair (single invocation; do NOT fan out the full Phase-2 wave).
    - `phase=4` → `dfir-correlator` once. `phase=5` → `dfir-reporter` once.
    Each dispatch emits an audit row whose action starts `[qa-redispatch]` (see "QA re-dispatch directive grammar" below for the format and example). After all queued rows are dispatched, move `./analysis/.qa-redispatch-pending` aside as `./analysis/.qa-redispatch-pending.<sha>.consumed` (preserves directive history) and re-invoke `dfir-qa`.
  </step>
  <step n="5" name="convergence-termination">Stop the QA loop when QA returns ALL of: `Convergence signal: CONVERGED` in its summary, empty/absent `.qa-redispatch-pending`, AND `qa-review.md` sha matches the previous pass's sha (from `./analysis/qa-history.md`). QA computes these itself and reports them in `qa-review.md`'s convergence section.</step>
  <step n="6" name="pathological-loop-guard">When the `qa-review.md` sha is unchanged across two consecutive passes BUT the directive file is non-empty (QA keeps requesting the same re-dispatch and nothing changes), halt the loop, log `[qa-redispatch] HALT: stuck loop` with the duplicated sha and directive contents to `forensic_audit.log`, and surface to the user. Do NOT silently keep looping.</step>
  <step n="7">On convergence, relay the `reports/qa-review.md` pointer to the user and mark the case CLOSED.</step>
</phase>

</protocol>

<resume-protocol>
Case state lives on disk; the orchestrator picks up without re-running
earlier phases. Phase logic is defined once in Forward Dispatch above — this
is a decision tree over on-disk artifacts selecting the next phase to run.

```
manifest.md absent                    → Phase 1
leads.md absent / header-only         → Phase 2 (full surveyor fan-out)
any lead status=in-progress           → reset to open (investigator is idempotent), then resume
baseline-check.sh reports missing     → append L-BASELINE-*; Phase 3 wave on them FIRST
any open high lead                    → Phase 3 wave (L-BASELINE-* first)
all leads terminal:
  correlation.md absent               → Phase 4 (its baseline gate runs first)
  any L-CORR-* non-terminal           → next Phase 4 iteration
  all L-CORR-* terminal AND last two correlation-history.md rows share sha256
                                      → converged; Phase 5
  all L-CORR-* terminal but correlation-history.md absent / single-row
                                      → one more correlation iteration to confirm
final.md absent                       → Phase 5
qa-review.md absent                   → Phase 6
qa-review.md verdict=BLOCKED          → surface BLOCKED; re-dispatch lead/correlator; re-run Phase 5+6
.qa-redispatch-pending non-empty      → resume Phase 6 re-dispatch loop
qa-review.md PASS* + Converged:yes + directive empty
                                      → relay executive summary; CLOSED
qa-review.md PASS* but Converged:no   → re-invoke QA to re-check
```

NEVER delete or truncate `leads.md`, `findings.md`, `correlation.md`, or
`qa-review.md` on resume — chain-of-custody trail.
</resume-protocol>

## QA re-dispatch directive grammar

Rows in `./analysis/.qa-redispatch-pending` are pipe-delimited:
`phase=<n>|target=<EV<NN>[ × <DOMAIN>]>|reason=<one-line justification>`.
Examples: `phase=1|target=EV02`, `phase=2|target=EV02 × memory`, `phase=4`,
`phase=5`. Each dispatched directive emits an audit row prefixed
`[qa-redispatch]` (verbatim into `audit.sh`'s action string) so QA's
discipline-ledger sweep counts rows and confirms the orchestrator honored
every directive. Example invocation:

```bash
bash .claude/skills/dfir-bootstrap/audit.sh \
  "[qa-redispatch] phase=1 target=EV02" \
  "QA flagged manifest mis-classification at analysis/manifest.md#L7" \
  "dispatch dfir-triage on EV02"
```

## Context-hygiene rules

- NEVER `Read` a survey file, `findings.md`, or raw tool output directly — those live in agents. Read only `manifest.md`, `leads.md` rows, and the reporter's executive summary.
- NEVER re-run preflight or case-init. Triage owns that.
- When relaying agent output to the user, quote the agent's ≤summary, NOT the underlying artifacts.
- When an agent returns an error or blocker, log it to `analysis/forensic_audit.log` and decide: retry with narrower scope, re-assign to a different domain, or mark the lead `blocked`.

## Single-phase mode

When the case is a specific question against a single evidence item (e.g.
"did user X run cmd.exe on host Y at 14:00 UTC?"), skip orchestration and
jump to the matching domain skill per `CLAUDE.md`'s routing table. Phase
orchestration pays off only when evidence count ≥ 2 or the question is
open-ended enough to touch multiple domains.

## Leads queue format

`./analysis/leads.md` is the shared queue across phases 2, 3, 4. Columns
`| lead_id | evidence_id | domain | hypothesis | pointer | priority | status |`. Example:
```
| L-EV01-memory-01 | EV01 | memory | Unsigned DLL loaded by lsass.exe (PID 624) | analysis/memory/survey-EV01.md#L88-L94 | high | open |
```
- `pointer` MUST be line-anchored (`<file>#L<n>` or `<file>#L<n>-L<m>`); a bare filename forces an investigator re-scan and wastes context.
- `status`: `open` → `in-progress` → `confirmed` / `refuted` / `escalated` / `blocked`.
- Investigator updates `status` before and after its work. Correlator appends `L-CORR-*` rows ONLY; it MUST NOT modify existing rows.
- All five lead-ID prefixes (surveyor, `-eNN`, `L-CORR-NN`, `L-EXTRACT-RE-NN`, `L-EXTRACT-DISK-NN`) coexist in this single file.

## Lead terminal-status invariant

**No lead sits in `escalated` once its child is terminal.** `escalated` is
transitional ("I delegated my hypothesis to a child"). When the child lands
`confirmed`/`refuted`, the parent transitions to a terminal status too.

Acceptable end-of-case states:
- `confirmed` / `refuted` — terminal.
- `open` — ONLY when `priority=low` AND `notes` carries an explicit non-blocking justification (e.g. "low priority — does not affect any headline").
- `blocked` — ONLY when `notes` documents an external dependency (missing evidence, unavailable tool, awaiting host-side data).

Anything else at case close is a discipline failure caught by Phase 6. QA
transitions lingering `escalated` parents to their child's verdict and
resets stale `in-progress` rows to `open` for re-dispatch. The orchestrator
runs `bash .claude/skills/dfir-bootstrap/leads-check.sh` as a gate before
Phase 4, Phase 5, and Phase 6 — nonzero exit forces a focused remediation
wave before proceeding.
