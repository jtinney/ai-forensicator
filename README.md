# ai-forensicator

AI-assisted digital forensics tooling and a 30–40 minute presentation on
applying large language models to DFIR workflows on the SANS SIFT
Workstation.

## Ideology

DFIR is a context problem before it is an AI problem. A real case produces
gigabytes of tool output — Plaso super-timelines, Volatility process trees,
EVTX dumps, YARA hit lists, carved artifact trees — and none of it fits in
a single model context window. The naive move (pipe everything into one
chat) blows context, degrades reasoning, and produces a shiny executive
summary with no chain of custody behind it. This project takes the
opposite stance:

1. **Evidence is read-only. Full stop.** Every skill enforces it; every
   agent respects it. All derived output lands in `./analysis/`,
   `./exports/`, or `./reports/`. Evidence directories are never written
   to. This is not a lint rule — it is the foundation of a defensible
   chain of custody.
2. **Deterministic tools generate facts; the model only reasons over
   them.** Sleuth Kit, Plaso, Volatility 3, YARA, bulk_extractor, the
   network-forensics stack (tshark / Zeek / Suricata), Sigma-driven EVTX
   hunters (Chainsaw / Hayabusa), and (when present) the Zimmerman EZ
   Tools do the parsing. The agent picks which tool, supplies flags,
   verifies exit codes, and interprets the output. It never fabricates
   artifact contents. If a claim is not backed by a tool invocation
   logged in `forensic_audit.log`, it does not go in the report.
3. **Raw output stays on disk. Context holds pointers.** Every phase
   writes its artifacts to a known path; the next phase reads only the
   headers, the leads queue, and line-anchored pointers into those
   artifacts. The orchestrator itself never reads a findings file — it
   holds case ID, manifest pointer, leads pointer, phase state. Nothing
   else.
4. **Specialized agents beat one big prompt.** A surveyor that only
   knows how to run cheap-signal sweeps against one evidence item in one
   domain produces better leads than a generalist trying to hold the
   whole case at once. Phase boundaries are context boundaries.
5. **Chain of custody is a file, not a vibe.** Every distinct action
   appends to `./analysis/forensic_audit.log`. Every pivot appends to the
   relevant `findings.md`. If a skill's workflow ran and neither file
   grew, that is a discipline failure — not a feature.
6. **The operator never gets interrupted mid-case.** Full autonomy from
   case start to final report. If the agent is blocked, it picks the
   most reasonable path, notes the choice, and keeps moving.

## The phased approach

When a case has more than one evidence item or spans multiple domains,
work runs through six phases, each handled by a dedicated sub-agent.
Raw tool output lands on disk; only pointers and short summaries cross
phase boundaries. The canonical doc is `.claude/skills/ORCHESTRATE.md`;
this is the shape of it.

| Phase | Agent | Model | Fan-out | Job |
|-------|-------|-------|---------|-----|
| 1 Triage | `dfir-triage` | haiku | once | Run preflight, scaffold the case tree, inventory and classify every evidence item, emit `manifest.md`. Triggers the intake interview if chain-of-custody fields are blank. |
| 2 Survey | `dfir-surveyor` | sonnet | one per (evidence × domain) | Cheap-signal sweeps in one domain against one evidence item (e.g. Prefetch + Amcache + Run keys for `windows-artifacts`). Emits a short lead list. |
| 3 Investigate | `dfir-investigator` | sonnet | one per lead, parallel waves ≤4 | Deep-dive on exactly one lead. Loads one domain skill, answers one hypothesis, writes one findings entry, updates lead status. |
| 4 Correlate | `dfir-correlator` | **opus** | once per wave | Cross-reference confirmed findings across domains and evidence items — align on timestamps, users, hosts, hashes, IPs. Opus because this is the case's core reasoning step. |
| 5 Report | `dfir-reporter` | haiku | once | Produce `reports/final.md` (technical) and `reports/stakeholder-summary.md` (non-technical, per the `exec-briefing` skill). Reads artifacts only; runs no forensic tools. |
| 6 QA | `dfir-qa` | **opus** | once | Quality-assurance pass with authority to correct mistakes in place. Cross-checks numerical claims against authoritative artifacts, enforces lead-status invariants, applies fixes via Edit/Write before sign-off. Opus because QA is the last reasoning gate before sign-off. |

### Why six phases, and why these six

- **Triage is separate from survey** because case bootstrap is a
  once-per-case, side-effectful step (writing `manifest.md`, initializing
  the audit log). Mixing it with analysis means every re-run risks
  clobbering chain-of-custody files.
- **Survey is separate from investigate** because cheap signals and deep
  dives have incompatible context profiles. A surveyor reads a manifest
  row and emits leads. An investigator reads one lead pointer and emits
  one findings entry. Collapsing the two forces the agent to hold both
  the full artifact set and the hypothesis at once — which is exactly
  the context blowup this design avoids.
- **Correlate is its own phase, on the stronger model**, because
  cross-domain inference ("the Prefetch run at 12:03 matches the memory
  injection at 13:47 on the host from the EVTX 4624 at 11:58") is the
  one step where cheap models reliably underperform. The correlator is
  the only agent allowed to read every `findings.md` at once.
- **Report is separate from analysis** so the write-up is grounded in
  already-confirmed findings and cannot accidentally re-investigate or
  invent claims. The reporter is a translation layer, not an analyst.
- **QA is the last phase, after the report**, because the things most
  likely to be wrong (a count that doesn't match the artifact, a lead
  still marked `in-progress`, a stakeholder summary contradicting
  `final.md`) only become visible once everything else is on disk.
  Putting QA earlier would force re-runs; putting it never would let
  drift survive into sign-off.

### Leads are the backbone

`./analysis/leads.md` is the shared queue between phases 2, 3, and 4. Every
row has a collision-free `lead_id` (`L-<EVIDENCE>-<DOMAIN>-NN` from the
surveyor, `-eNN` suffix for investigator escalations, `L-CORR-NN` for
correlator gaps), a line-anchored pointer into the survey or findings
file, a priority, and a status that moves `open → in-progress →
confirmed | refuted | escalated | blocked`. Parallel investigator waves
never collide because prefixes are unique per source and the investigator
flips its own status before starting.

### Resume is free

Because all case state lives on disk, the orchestrator can pick up a
half-finished case without re-running earlier phases. Missing
`manifest.md` → start at Phase 1. Missing `leads.md` → start at Phase 2.
Any `in-progress` leads → reset to `open` (investigators are idempotent).
Missing `correlation.md` → Phase 4. Missing `reports/final.md` → Phase 5.
The chain-of-custody files (`leads.md`, `findings.md`, `correlation.md`,
`forensic_audit.log`) are append-only on resume — never truncated.

### When not to phase

If the case is a single evidence item with a specific question ("did
user X run cmd.exe on host Y at 14:00 UTC?"), phasing is overkill. Route
directly to the matching domain skill via the table in `CLAUDE.md`, or
use `.claude/skills/TRIAGE.md` for single-evidence unguided work. Phasing
pays off when evidence count ≥ 2 or the question is open-ended enough
that multiple domains will get touched.

## Repository layout

- `CLAUDE.md` — operator contract: case-start protocol, forensic
  constraints, tool-routing table.
- `.claude/skills/` — domain skills (`sleuthkit`, `plaso-timeline`,
  `memory-analysis`, `windows-artifacts`, `network-forensics`,
  `yara-hunting`, `sigma-hunting`), the bootstrap skill
  (`dfir-bootstrap` — preflight, `case-init.sh`, `install-tools.sh`,
  stdlib fallback parsers for when EZ Tools / regipy / python-evtx are
  absent), the shared chain-of-custody rules (`dfir-discipline`), the
  reporting skill (`exec-briefing`), and the two entrypoints
  (`ORCHESTRATE.md`, `TRIAGE.md`).
- `.claude/agents/` — the six phase agents (`dfir-triage`,
  `dfir-surveyor`, `dfir-investigator`, `dfir-correlator`,
  `dfir-reporter`, `dfir-qa`).
- `analysis/`, `exports/`, `reports/` — per-case output roots.

## Case-close gates

A case is not CLOSED until all five gates pass:

| Gate | Script / Phase | Enforced where |
|------|----------------|----------------|
| Intake fields populated (`reports/00_intake.md`) | `intake-check.sh` | Phases 4 / 5 / 6 |
| All leads in terminal status | `leads-check.sh` | Phases 4 / 5 / 6 |
| Per-domain baseline artifacts present | `baseline-check.sh` | Phase 4 |
| QA pass produced | Phase 6 (`dfir-qa`) | Sign-off |
| Final + stakeholder report present | Phase 5 (`dfir-reporter`) | Sign-off |

The intake interview is the **one** place agent autonomy yields to
operator input — chain-of-custody fields are not optional. `case-init.sh`
launches `intake-interview.sh` if any field is blank; in non-TTY mode it
drops `./analysis/.intake-pending` for the orchestrator to surface.

## Case start

```bash
bash .claude/skills/dfir-bootstrap/preflight.sh | tee ./analysis/preflight.md
bash .claude/skills/dfir-bootstrap/case-init.sh <CASE_ID>
```

Preflight inventories what is actually installed on this SIFT instance —
the aspirational tool table in `CLAUDE.md` is often wrong, and preflight
is authoritative. `case-init.sh` scaffolds the output tree with
`findings.md` stubs and an initialized `forensic_audit.log`.

From there, invoke `/case` for phase-based orchestration, or let the
agent route directly to a domain skill when the question is narrow.

## Status

Harness and skills are working end-to-end on SIFT; presentation materials
land next.
