# Skill: Phase-Based Multi-Agent Orchestration

The orchestrator's protocol for running a DFIR case across the six phase
agents. Use this entrypoint when the case involves more than one evidence item
or when context would otherwise balloon past a single session.

## Case workspace

Every case in this project lives under `./cases/<CASE_ID>/`. The orchestrator's
**first action** for any new or resuming case is to `cd` there:

```bash
mkdir -p "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>/evidence"
cd "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>"
```

Every `./evidence/`, `./analysis/`, `./exports/`, `./reports/` path in this
file (and in the domain skills, agents, and TRIAGE.md) is relative to that
workspace. Project-level scripts live at
`${CLAUDE_PROJECT_DIR}/.claude/skills/...`.

## Why phases

Context stays small by pushing every phase's raw output to disk and passing
only pointers + short summaries back to the main context. The orchestrator
holds: case ID, evidence manifest pointer, leads queue pointer, phase state.
Nothing else.

## Canonical domain names

All agents and orchestrator dispatches use these seven `DOMAIN` values. They
match the subdirs `case-init.sh` creates, so survey and findings output paths
line up without translation. (`findings.md` is not pre-created — the surveyor
and investigator write it on first append.)

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
| 3 Investigate | `dfir-investigator` | sonnet | one per lead | one lead row + its pointer | `analysis/<domain>/findings.md`, updates `leads.md` status, may append |
| 4 Correlate | `dfir-correlator` | **opus** | once per correlation-loop iteration (drives Phase 3 re-dispatch until convergence) | all `findings.md` | `analysis/correlation.md`, appends `correlation-history.md` row, may append `L-CORR-*` leads |
| 5 Report | `dfir-reporter` | haiku | once | correlation + findings | `reports/final.md` + `reports/stakeholder-summary.md` |
| 6 QA | `dfir-qa` | **opus** | self-loops to convergence | all case docs + authoritative artifacts | corrects errors in place via `Edit`, transitions non-terminal leads, may queue prior phases for re-dispatch via `analysis/.qa-redispatch-pending`, writes `reports/qa-review.md` |

## Lead ID conventions (collision-free under parallel fan-out)

| Source | ID prefix | Example |
|--------|-----------|---------|
| Surveyor (phase 2) | `L-<EVIDENCE_ID>-<DOMAIN>-NN` | `L-EV01-memory-01` |
| Investigator escalation (phase 3) | `L-<EVIDENCE_ID>-<DOMAIN>-eNN` | `L-EV01-memory-e01` |
| Correlator gap (phase 4) | `L-CORR-NN` | `L-CORR-03` |
| Correlator re-extraction (phase 4, sequential mode) | `L-EXTRACT-RE-NN` | `L-EXTRACT-RE-01` |
| Bootstrap disk-pressure block (phase 1) | `L-EXTRACT-DISK-NN` | `L-EXTRACT-DISK-01` |

Each prefix is globally unique per its source, so agents running in parallel
never need shared locks to pick an ID. `NN` is zero-padded and counter-scoped
to the invocation that produced it.

## Dispatch protocol

1. **Phase 1 — Triage** (blocking)
   - Invoke `dfir-triage` with case ID and evidence path. Triage runs the
     pre-extraction disk-space planner (`extraction-plan.sh`) before
     `case-init.sh`; the resulting `./analysis/extraction-plan.md` decides
     whether `case-init.sh` bulk-extracts everything (`BULK_EXTRACT=1`) or
     defers to sequential staging.
   - On return, read `analysis/manifest.md` headers only (not full contents).
   - Read the `Mode` field of `./analysis/extraction-plan.md`:
     - `bulk` — proceed to Phase 2 normally.
     - `sequential` — invoke the **Sequential extraction protocol** (below)
       to drive Phases 2 / 3 stage-by-stage; do NOT fan out a single Phase 2
       wave across all archives.
     - `blocked` — surface the `L-EXTRACT-DISK-NN` lead (planner appended a
       BLOCKED row to `leads.md`) and stop. Operator must free disk or
       remount before any further phase runs.

2. **Phase 2 — Survey** (parallel fan-out)
   - For each evidence item, pick applicable domains from its type:
     - `disk` → `filesystem`, `windows-artifacts`, `timeline`, `yara`, `sigma`
     - `memory` → `memory`, `yara`
     - `logs` / `triage-bundle` → `windows-artifacts`, `timeline`, `sigma`
     - `pcap` → `network`, `yara`, `timeline`
     - `netlog` → `network`, `timeline`
   - Dispatch `dfir-surveyor` invocations in **batches of ≤ 3** (not all at
     once). For batches that include a `network`-domain surveyor, reduce to
     **≤ 2** per batch — Zeek and Suricata are full-pcap replay tools and
     saturate CPU/RAM when run concurrently. Complete each batch before
     starting the next; append leads as each batch returns.
   - On return, read `analysis/leads.md` for the lead queue.

### Sequential extraction protocol (between Phase 2 and Phase 3 in `mode: sequential`)

When `./analysis/extraction-plan.md` reports `mode: sequential`, archives
exceed combined free disk but each fits alone. Triage staged stage 1
(smallest archive). The orchestrator then drives the rest of the schedule
per-archive, NOT in a single Phase 2 wave:

For each stage `N` in the plan's stage table (`1..K`):

1. **Extract** — if stage `N` is not yet on disk, run case-init's bundle
   loop against just that one archive (e.g. by feeding a single-element
   evidence subdir) or use the archive-specific extract logic the triage
   agent ran for stage 1. The expanded tree lives at
   `./analysis/_extracted/<basename>/`. Audit row:
   `[disk] stage N: extract <archive>` via `bash audit.sh ...`.
2. **Survey** — fan out Phase 2 (`dfir-surveyor`) only for `(stage-N
   evidence × applicable domains)`. Other stages' archives are not yet
   expanded; the surveyor must NOT touch them.
3. **Investigate** — run a Phase 3 wave only on `leads.md` rows generated
   by stage `N`'s surveys (lead IDs `L-<EVID-of-stage-N>-...`). Honor the
   normal lead terminal-status invariant before advancing.
4. **Cleanup** — once stage `N`'s investigators have settled, run:
   ```bash
   bash .claude/skills/dfir-bootstrap/extraction-cleanup.sh <basename-of-stage-N>
   ```
   This deletes only `./analysis/_extracted/<basename>/`. All
   `./analysis/<domain>/` (findings, surveys, files-examined.tsv),
   `./exports/**` (carved/dumped artifacts), `./analysis/manifest.md`
   (chain-of-custody rows), and `./analysis/leads.md` are preserved. The
   helper writes its own audit row; the orchestrator MUST also write
   `[disk] stage N: cleanup <archive> deleted=<N> files` for the
   stage-aware record.
5. **Advance** — increment `N`. If `N <= K`, repeat from step 1. If `N >
   K`, sequential staging is complete; proceed to Phase 4 (correlation).

`L-EXTRACT-RE-NN` re-extraction leads (correlator-driven; see Phase 4
below) trigger an additional sequential cycle: extract just the named
archive (and, when the lead names a path subset, optionally only that
subdir via `unzip <archive> "<subset>/*"` or a `tar --wildcards` filter
into `./analysis/_extracted/<basename>/`), run a Phase 2/3 mini-wave
scoped to the leads the re-extraction generates, then call
`extraction-cleanup.sh` to release the bytes again.

Audit-log convention for every stage transition:

```
[disk] stage <N>: extract <archive>
[disk] stage <N>: cleanup <archive> deleted=<N> files
```

Both rows go through `bash .claude/skills/dfir-bootstrap/audit.sh`
(DISCIPLINE rule A.1 — never `>>` directly).

3. **Phase 3 — Investigate** (parallel waves)
   - Sort `leads.md` rows with `status=open` by `priority` (`high` first).
   - Dispatch one `dfir-investigator` per lead in parallel batches. Batch size
     depends on domain:
     - `filesystem`, `windows-artifacts`, `yara`, `sigma`, `timeline` → **≤ 4** per
       batch (I/O-bound; CPU headroom remains)
     - `network`, `memory` → **≤ 2** per batch (CPU/RAM-bound: Zeek, Suricata,
       Volatility)
     Mixed-domain waves: if any lead in the wave is `network` or `memory`, cap
     the entire batch at ≤ 2.
     The investigator flips its lead's status to `in-progress` before it
     starts, so concurrent waves do not double-take a lead.
   - Leads that `escalate` will append new `-e` rows; run another wave until
     no new `high` leads remain. Investigation waves run as long as new
     `high`-priority leads keep appearing; the correlation loop's
     convergence guard (Phase 4 below) is the terminating condition for
     the case as a whole.

4. **Phase 4 — Correlate** (blocking; convergence-guarded loop)
   - **Baseline-artifact gate (BEFORE invoking the correlator):** for each
     domain that has `./analysis/<DOMAIN>/findings.md` non-empty (i.e. an
     investigator wrote to it), run
     `bash .claude/skills/dfir-bootstrap/baseline-check.sh <DOMAIN>`. For each
     domain whose JSON output reports `missing != []`, append a lead row
     `L-BASELINE-<DOMAIN>-<NN>` to `./analysis/leads.md` at priority
     `high`, status `open`, hypothesis
     `Re-generate <missing-list> for <DOMAIN>`. **Correlation does NOT
     proceed around a baseline gap** — run a focused Phase 3 wave to fill
     the gap, then re-attempt the gate. If a baseline artifact still
     cannot be regenerated after a remediation wave, mark the
     `L-BASELINE-*` lead `blocked` with a documented external-dependency
     reason and proceed to correlation with an explicit
     "baseline-incomplete" caveat in the correlator's output.
   - **Correlation loop with convergence guard.** The loop drives
     re-correlation until the case converges. There is no fixed wave
     cap; the case-close gates (intake populated, all leads terminal,
     baselines present, QA pass, final report) are the terminating
     condition.

     For each iteration `n` (starting at `n=1`):
     1. Invoke `dfir-correlator`. The correlator reads the prior
        `correlation.md` (if present) and computes a since-last-correlation
        diff before rewriting the file.
     2. Compute `sha256sum analysis/correlation.md | awk '{print $1}'` and
        capture it as `SHA_n`.
     3. Append a row to `./analysis/correlation-history.md`. On the
        first iteration, create the file with this exact header:

        ```
        # Correlation-loop convergence ledger
        | utc_timestamp | wave_n | sha256 | new_L-CORR_count | terminal_L-CORR_count |
        |---------------|--------|--------|------------------|------------------------|
        ```

        Then append the iteration's row in the same format:

        ```
        | <UTC timestamp> | <wave_n> | <sha256> | <new_L-CORR_count> | <terminal_L-CORR_count> |
        ```

        Where `new_L-CORR_count` is the count of `L-CORR-*` leads added by
        this iteration and `terminal_L-CORR_count` is the count of
        `L-CORR-*` rows in `leads.md` whose status is `confirmed` /
        `refuted` / `blocked`.
     4. Append an audit-log row via `audit.sh` using the convention:
        `[correlation] wave <n> sha=<sha> leads_new=<x> leads_terminal=<y>`.
        Grepping `[correlation]` over `forensic_audit.log` enumerates the
        correlation history at any point.
     5. Decide:
        - **Continue** if either (a) any `L-CORR-*` lead is non-terminal,
          OR (b) `SHA_n != SHA_(n-1)` (correlation output changed between
          iterations). Dispatch a focused Phase 3 wave for the open
          `L-CORR-*` leads and return to step 1.
        - **Exit** when both (a) every `L-CORR-*` lead is in a terminal
          status (`confirmed` / `refuted` / `blocked`) AND (b) `SHA_n ==
          SHA_(n-1)` (the correlator's output has not changed since the
          previous iteration). The case has converged; proceed to Phase 5.
   - **`L-EXTRACT-RE-<NN>` handling (sequential mode only).** If the
     correlator appends `L-EXTRACT-RE-NN` re-extraction leads (only
     possible in `mode: sequential` — see Sequential extraction protocol
     above), drive a focused Phase-2/3 mini-wave: re-stage the named
     archive (or named path subset within it), run scoped surveyor +
     investigator(s), call `extraction-cleanup.sh` to release the bytes,
     then return to the convergence loop's next iteration. The
     correlator's `L-EXTRACT-RE-*` lead row names the archive + path
     subset in its `hypothesis` field and points at the
     `correlation.md` line that motivated the re-extraction.
   - **Pathological-loop detector.** If two consecutive iterations
     produce identical `correlation.md` hashes (`SHA_n == SHA_(n-1)`)
     but `L-CORR-*` leads remain non-terminal, the loop has stalled —
     the correlator is not finding new ties and the orchestrator's
     Phase 3 dispatches are not closing the open `L-CORR-*` leads.
     Halt the loop:
     1. Append an audit-log row:
        `[correlation] pathological-loop halt: hash=<sha> wave=<n> nonterminal_leads=<csv-list>`.
     2. Mark each non-terminal `L-CORR-*` lead `blocked` in `leads.md`
        with the note
        `convergence reached but lead still non-terminal — manual review required`.
     3. Proceed to Phase 5. The QA agent will surface the halt event in
        `qa-review.md`.

5. **Phase 5 — Report** (blocking)
   - Invoke `dfir-reporter` once. It produces two reports:
     - `./reports/final.md` — technical case report (analysts).
     - `./reports/stakeholder-summary.md` — decision-focused briefing for
       non-technical senior stakeholders, written per
       `.claude/skills/exec-briefing/SKILL.md`.
   - Relay the executive summary from `final.md` and the one-line posture
     from the stakeholder briefing, with pointers to both files.
   - **Do NOT close the case yet.** Phase 6 must run before sign-off.

6. **Phase 6 — QA** (blocking; gate before sign-off; self-loops to convergence)
   - Invoke `dfir-qa`. It cross-checks every case document against
     the authoritative artifacts on disk, enforces the lead-status
     terminal invariant, gates on intake completeness, corrects
     numerical / labeling / lead-status errors in place via `Edit`,
     **and may queue any prior phase for re-dispatch** by appending
     rows to `./analysis/.qa-redispatch-pending`.
   - Possible verdicts on each pass:
     - `PASS` — no changes required this pass.
     - `PASS-WITH-CHANGES` — corrections applied this pass.
     - `BLOCKED` — a fix would require a brand-new investigation
       hypothesis (not a re-run). Surface the BLOCKED items to the
       user and route any new hypothesis through the correlator →
       Phase 3 path.
   - **Re-dispatch loop.** When QA returns, read
     `./analysis/.qa-redispatch-pending` (if present and non-empty).
     For each row:
     - `phase=1`, `target=EV<NN>` → invoke `dfir-triage` against that
       single evidence item only (pass `EVIDENCE_ID=EV<NN>` in the
       prompt; triage is idempotent and re-classifies that row).
     - `phase=2`, `target=EV<NN> × <DOMAIN>` → invoke `dfir-surveyor`
       with that pair (single invocation; do not fan out the full
       Phase-2 wave).
     - `phase=4` → invoke `dfir-correlator` once.
     - `phase=5` → invoke `dfir-reporter` once.
     Emit one audit-log row per dispatched phase using the
     `[qa-redispatch]` action prefix (see "Audit-log conventions"
     below). After all queued rows are dispatched, move
     `./analysis/.qa-redispatch-pending` aside as
     `./analysis/.qa-redispatch-pending.<sha>.consumed` (preserves the
     directive history) and re-invoke `dfir-qa`. The freshly-invoked
     QA pass will re-read everything and either request more
     re-dispatches or converge.
   - **Convergence-based termination.** The orchestrator stops the
     QA loop when QA returns with **all** of:
     - `Convergence signal: CONVERGED` in its return summary, AND
     - empty / absent `./analysis/.qa-redispatch-pending`, AND
     - the qa-review.md sha matches the previous pass's sha (read
       from `./analysis/qa-history.md`).
     Treat these as a single signal — QA computes them itself and
     reports them via the convergence section of `qa-review.md`.
   - **Pathological-loop guard.** If the qa-review.md sha is
     unchanged across two consecutive passes BUT the directive file
     is non-empty (QA keeps requesting the same re-dispatch and
     nothing changes), halt the loop, log
     `[qa-redispatch] HALT: stuck loop` with the duplicated sha and
     the directive contents to `forensic_audit.log`, and surface to
     the user. Do not silently keep looping.
   - On convergence, relay `reports/qa-review.md` pointer to the user
     and mark the case CLOSED.

### Audit-log conventions for Phase 6 re-dispatch

When the orchestrator picks up a row from
`.qa-redispatch-pending` and dispatches the named phase, it emits an
`audit.sh` row whose `action` field starts with `[qa-redispatch]`.
This distinguishes QA-initiated re-dispatches from the orchestrator's
normal Phase-3 wave dispatches (which use no special prefix).

```
bash .claude/skills/dfir-bootstrap/audit.sh \
  "[qa-redispatch] phase=1 target=EV02" \
  "QA flagged manifest mis-classification at analysis/manifest.md#L7" \
  "dispatch dfir-triage on EV02"
```

The `[qa-redispatch]` prefix is convention only — `audit.sh` itself
takes the action string verbatim. QA's discipline-ledger sweep
(Protocol step 8) counts these rows to confirm the orchestrator
honored every directive row.

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
     `./analysis/correlation.md` and
     `./analysis/correlation-history.md`:
     - `correlation.md` missing → run Phase 4 (which itself has a
       baseline-artifact gate — see Phase 4 above).
     - Any `L-CORR-*` lead `open` / `escalated` → next iteration of the
       Phase 4 convergence loop (run a focused Phase 3 wave for those
       leads, then re-invoke `dfir-correlator`).
     - All `L-CORR-*` leads terminal AND the last two rows of
       `correlation-history.md` have identical `sha256` → converged,
       proceed to Phase 5.
     - All `L-CORR-*` leads terminal but `correlation-history.md` is
       absent or has only one row → run one more correlation iteration
       to confirm convergence (the second hash either matches and we
       exit, or differs and the loop continues).
4. Check for `./reports/final.md`:
   - Missing → run Phase 5.
   - Present → check `./reports/qa-review.md`.
     - Missing → run Phase 6.
     - Present with verdict `BLOCKED` → surface the BLOCKED items;
       re-dispatch a focused Phase 3 lead or correlator-driven
       hypothesis, then re-run Phase 5 / Phase 6.
     - Present and `./analysis/.qa-redispatch-pending` exists and is
       non-empty → resume the Phase 6 re-dispatch loop: dispatch
       each queued phase, then re-invoke QA.
     - Present with verdict `PASS` / `PASS-WITH-CHANGES` AND its
       Convergence section reports `Converged: yes` AND the directive
       file is absent/empty → relay the executive summary from
       `final.md`, confirm done.
     - Present with verdict `PASS` / `PASS-WITH-CHANGES` but
       `Converged: no` (e.g. session died between QA passes) →
       re-invoke QA so it can re-check and converge.

Never delete or truncate `leads.md`, `findings.md`, `correlation.md`, or
`qa-review.md` on resume. They are the chain-of-custody trail.

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
| L-EXTRACT-RE-01 | EV04 | bootstrap | Re-extract `archive-3.zip` `Users/jsmith/AppData/Local/`; the SRUDB.dat hash from `correlation.md#L72` does not match the deferred-bundle row | analysis/correlation.md#L72 | high | open |
| L-EXTRACT-DISK-01 | — | bootstrap | Disk-pressure block: evidence/Archives/big.zip requires 12GB; free 4GB | analysis/extraction-plan.md | high | blocked |
```

- `pointer` MUST be line-anchored (`<file>#L<n>` or `<file>#L<n>-L<m>`). A
  bare filename forces the investigator to re-scan the survey and wastes
  context.
- `status`: `open` → `in-progress` → `confirmed` / `refuted` / `escalated` / `blocked`.
- Investigator updates its lead's `status` before and after its work.
- Correlator may add `L-CORR-*` rows; it must not modify existing rows.

## Lead terminal-status invariant

**No lead may sit in `escalated` once its child is terminal.** `escalated`
is a transitional state: it means "I delegated my hypothesis to a child
lead." When the child lands in `confirmed` / `refuted`, the parent's
hypothesis has been answered through the child and the parent must
transition to a terminal status as well.

Acceptable end-of-case lead states:
- `confirmed` / `refuted` — terminal.
- `open` — only if `priority=low` AND the row's `notes` field carries an
  explicit non-blocking justification (e.g. "low priority — does not
  affect any headline; surfaced for completeness only").
- `blocked` — only if `notes` documents an external dependency (missing
  evidence, unavailable tool, awaiting host-side data).

Anything else at case close is a discipline failure caught by the QA
phase. The QA agent will transition lingering `escalated` parents to
their child's terminal verdict and reset stale `in-progress` rows to
`open` for re-dispatch.

The orchestrator runs `bash .claude/skills/dfir-bootstrap/leads-check.sh`
as a gate before Phase 4 (correlation), Phase 5 (report), and Phase 6
(QA). A nonzero exit forces a focused remediation wave before
proceeding.
