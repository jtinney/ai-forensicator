# CLAUDE.md

Project guidance for Claude Code working in this repository.

## DFIR Orchestrator — SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| Environment | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| Role | Principal DFIR Orchestrator |
| Evidence Mode | Strict read-only (chain of custody) |

See `ARCHITECTURE.md` for the project tree and the canonical location of
every shared concept.

<reference-style>
  - `@.claude/skills/<name>/SKILL.md` — skill-loading hint in prose, agent
    prompts, and skill cross-references.
  - `.claude/skills/<name>/...` — bare paths inside fenced bash blocks.
  - `${CLAUDE_PROJECT_DIR}/.claude/...` — absolute path inside bash when
    CWD is a case workspace and the project root is needed.
</reference-style>

## Five-layer case workspace

The case workspace `./cases/<CASE_ID>/` has five layers. Each layer has
a distinct mutability and integrity contract.

| # | Layer | Path | Mutability | Integrity ledger |
|---|-------|------|------------|------------------|
| 1 | Original evidence | `./evidence/` | Read-only after intake (`chmod a-w`) | `analysis/manifest.md` |
| 2 | Working copies | `./working/<bundle>/`, `./working/mounts/<EV>/p<M>/` | Read-only by convention; mounts read-only by kernel | `analysis/manifest.md` (`bundle-member`, `disk-mount` rows) |
| 3 | Tool reports | `./analysis/<domain>/` | Mutable (recomputable) | None |
| 4 | Derived artifacts | `./exports/<domain>/...` | Write-once | `analysis/exports-manifest.md` (PostToolUse hook) |
| 5 | Reports | `./reports/` | Mutable | None |

**Bytes vs summaries.** Bytes go to `./exports/`. Summaries (CSV, JSON,
markdown) go to `./analysis/`. Layer 2 is the only place under
`./working/` or `./analysis/` where bytes legitimately live.

## Operator preferences

- Run every workflow fully autonomously start-to-finish. Deliver final
  findings only — no check-ins, no confirmations, no "shall I proceed?".
  When blocked, pick the most reasonable path and note the choice in the
  output.
- **EXCEPTION: intake interview.** Chain-of-custody fields in
  `reports/00_intake.md` MUST be populated before Phases 4 / 5 / 6
  run. If `bash .claude/skills/dfir-bootstrap/intake-check.sh` reports
  any blank field, run
  `bash .claude/skills/dfir-bootstrap/intake-interview.sh` and prompt
  the user.

## Case start protocol

1. **Enter the case workspace.** Every case lives at
   `./cases/<CASE_ID>/`. The `/case <CASE_ID>` slash command handles
   this; the manual form is:
   ```bash
   mkdir -p "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>/evidence"
   cd "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>"
   ```
   `./cases/case-xxxx/` is the template — clone it for new cases.
2. **Run preflight:**
   `bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/preflight.sh" | tee ./analysis/preflight.md`.
   Trust preflight over any static tool list.
3. **Scaffold the case:**
   `bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/case-init.sh" <CASE_ID>`.
   Provisions the five top-level folders, hashes evidence, locks
   `./evidence/` read-only, runs the intake-interview gate.
4. **Follow the analysis-discipline contract.** See
   `@.claude/skills/dfir-discipline/DISCIPLINE.md`. Every action emits an
   audit row via `audit.sh`; every pivot writes a finding entry.

### Case-close gates

A case is not CLOSED until all five gates pass:

| Gate | Script | Enforced where |
|------|--------|----------------|
| Intake fields populated | `intake-check.sh` | Phases 4 / 5 / 6 |
| All leads in terminal status | `leads-check.sh` | Phases 4 / 5 / 6 |
| Per-domain baseline artifacts present | `baseline-check.sh` | Phase 4 |
| QA pass produced (`reports/qa-review.md`) | Phase 6 (`dfir-qa`) | Sign-off |
| Final + stakeholder report present | Phase 5 (`dfir-reporter`) | Sign-off |

## Forensic constraints

Project-wide rules. Canonical definitions in
`@.claude/skills/dfir-discipline/DISCIPLINE.md`.

- **Tool order is per-domain priority** (`§P-priority`). Surveyor runs the
  domain's `tier="survey"` tools; investigator / correlator / QA descend
  the list in numeric order as questions escalate. When the next required
  tool is absent, mark the lead BLOCKED with `suggested-fix=<verb>;
  tool-needed=<thing>` in the notes column. Skipping a rank requires an
  `audit.sh` row recording the reason.
- **PCAP order** (`§P-pcap`) is the network entry of `§P-priority`:
  `capinfos` inventory + `zeek` for survey; `suricata`, `tshark`, etc.
  in order for deeper passes.
- **Disk images are mounted read-only via `qemu-nbd`** (and `ewfmount` for E01)
  into `./working/mounts/<EV>/p<M>/` after archive extraction. Tools operate
  off the mount; mounts dismounted at case close. NEVER converted to E01
  (`§P-diskimage`).
- **YARA rules** live at `/opt/yara-rules/`; scans read from there; hits
  write to `./exports/yara_hits/` (`§P-yara`).
- **Sigma rules** live at `/opt/sigma-rules/`; Chainsaw / Hayabusa read
  rules + mappings from there; CSV summaries write to `./analysis/sigma/`
  (`§P-sigma`).
- **Evidence integrity.** Never modify `./evidence/`. The PreToolUse
  hook and `chmod a-w` enforce this.
- **Timestamps** in UTC.
- **Verification.** Verify tool success after every run. On failure:
  read stderr → hypothesize → correct → retry.

## Tool routing

> **Multi-evidence / multi-domain case** — `/case <CASE_ID>` launches
> phase-based orchestration via `@.claude/skills/ORCHESTRATE.md`. Six
> phase agents (`dfir-triage`, `dfir-surveyor`, `dfir-investigator`,
> `dfir-correlator`, `dfir-reporter`, `dfir-qa`) run with raw output on
> disk; the main context holds only pointers.
>
> **Single evidence item, no specific lead** — start at
> `@.claude/skills/TRIAGE.md` (unguided protocol: triage → wide → deep →
> pivot, single context).
>
> **Specific question** — jump to the matching domain skill below.

| Domain | Skill |
|--------|-------|
| Phase-based orchestration | `@.claude/skills/ORCHESTRATE.md` |
| Unguided single-evidence triage | `@.claude/skills/TRIAGE.md` |
| Case start / preflight / fallback parsers | `@.claude/skills/dfir-bootstrap/SKILL.md` |
| Discipline rules | `@.claude/skills/dfir-discipline/DISCIPLINE.md` |
| Filesystem / Sleuth Kit | `@.claude/skills/sleuthkit/SKILL.md` |
| Plaso timelines | `@.claude/skills/plaso-timeline/SKILL.md` |
| Memory / Volatility 3 | `@.claude/skills/memory-analysis/SKILL.md` |
| Windows artifacts | `@.claude/skills/windows-artifacts/SKILL.md` |
| Network forensics | `@.claude/skills/network-forensics/SKILL.md` |
| YARA hunting | `@.claude/skills/yara-hunting/SKILL.md` |
| Sigma hunting | `@.claude/skills/sigma-hunting/SKILL.md` |
| Stakeholder briefings | `@.claude/skills/exec-briefing/SKILL.md` |

`/case <CASE_ID>` (`.claude/commands/case.md`) is the canonical
entrypoint. Idempotent — a second invocation resumes from the
lowest-remaining phase per `@.claude/skills/ORCHESTRATE.md` § Resume
protocol.
