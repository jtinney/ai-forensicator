# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## DFIR Orchestrator — SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |

## Project layout

```
ai-forensicator/                  # project root (cloned repo)
├── CLAUDE.md                     # this file
├── README.md
├── .claude/                      # tooling — shared across every case
│   ├── agents/                   #   six phase agents
│   ├── commands/                 #   /case slash command
│   ├── settings.json             #   permissions + audit hooks
│   └── skills/                   #   ORCHESTRATE, TRIAGE, domain skills
├── cases/                        # one subdirectory per case
│   ├── case-xxxx/                #   blank template (rename / clone)
│   │   └── evidence/             #     drop evidence here
│   └── <CASE_ID>/                #   investigator's case workspace
│       ├── evidence/             #     read-only after case-init
│       ├── analysis/             #     tool output + findings
│       ├── exports/              #     extracted artifacts (carved files etc.)
│       └── reports/              #     final.md, stakeholder-summary.md, qa-review.md
├── VALIDATION.md                 # human-reviewer protocol for verifying case output
└── examples/                     # worked example case (NIST CFREDS Jimmy Wilson, see examples/README.md)
```

**Operating model.** All forensic activity runs with the **case workspace as
CWD** (`./cases/<CASE_ID>/`). Every `./evidence/`, `./analysis/`, `./exports/`,
`./reports/` reference in this file, the agents, and the skills is relative to
that workspace. Project-level scripts are at
`${CLAUDE_PROJECT_DIR}/.claude/skills/...`.

---

## Operator Preferences

- **Run every workflow fully autonomously start-to-finish.** Deliver final findings only — no check-ins, no confirmations, no "shall I proceed?". If blocked, pick the most reasonable path and note that choice in the output.
- **EXCEPTION: intake interview.** Chain-of-custody fields in `reports/00_intake.md` are NOT optional. If `bash .claude/skills/dfir-bootstrap/intake-check.sh` reports any blank field, run `bash .claude/skills/dfir-bootstrap/intake-interview.sh` and ask the user. The interview blocks Phases 4 / 5 / 6 until complete. This is the ONE place agent autonomy yields to operator input — the case has no foundation without intake.

---

## Case Start Protocol

Before touching evidence on a new case or a new SIFT instance:

1. **Create / enter the case workspace.** Every case in this project lives
   under `./cases/<CASE_ID>/`. Drop evidence into `./cases/<CASE_ID>/evidence/`,
   then `cd` into the case directory (every later command is relative to it):
   ```bash
   mkdir -p "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>/evidence"
   cd "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>"
   ```
   The blank `./cases/case-xxxx/` directory is the template — clone or rename
   it as the starting point for new cases.
2. **Run preflight:**
   `bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/preflight.sh" | tee ./analysis/preflight.md`
   This inventories *actually installed* tools (not the aspirational list below).
   Trust the preflight output over this file when they disagree.
3. **Scaffold the case:**
   `bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/case-init.sh" <CASE_ID>`
   Creates `./analysis/`, `./exports/`, `./reports/` inside the case workspace
   and seeds `forensic_audit.log`. `case-init.sh` also auto-resolves the case
   workspace (it walks up to find `.claude/`, then `cd`s to `cases/<CASE_ID>/`),
   so calling it from anywhere inside the project still scaffolds the right
   directory. Does NOT pre-create per-domain `findings.md`; the surveyor and
   investigator phases write those on first append, so the presence of a
   `findings.md` is itself the signal that a domain has produced analyst output.
   **Locks the `./evidence/` directory read-only at the filesystem level
   (`chmod a-w`)** — combined with the PreToolUse harness hook, this gives
   belt-and-suspenders protection against accidental mutation. **Triggers the
   intake interview** if `reports/00_intake.md` has any blank chain-of-custody
   field; in non-TTY mode it leaves `./analysis/.intake-pending` for the
   orchestrator to surface.
4. **Follow the Analysis Discipline contract** (documented in every skill's SKILL.md):
   append an entry to `./analysis/forensic_audit.log` after every distinct action, and
   append a finding entry to the matching `./analysis/<domain>/findings.md` after every
   pivot. If either file has no new entries after a skill's workflow runs, that is a
   discipline failure — backfill before moving on.

### Case-close gates

A case is not CLOSED until all five gates pass:

| Gate | Script | Enforced where |
|------|--------|----------------|
| Intake fields populated | `intake-check.sh` | Phases 4 / 5 / 6 |
| All leads in terminal status | `leads-check.sh` | Phases 4 / 5 / 6 |
| Per-domain baseline artifacts present | `baseline-check.sh` | Phase 4 |
| QA pass produced (`reports/qa-review.md`) | Phase 6 (`dfir-qa`) | Sign-off |
| Final + stakeholder report present | Phase 5 (`dfir-reporter`) | Sign-off |

### Harness security posture

The standing audit of the harness lives in
[issue #3](https://github.com/jtinney/ai-forensicator/issues/3) —
`.claude/settings.json` permission scope, the PreToolUse /
PostToolUse / Stop hooks, the audit-log integrity model, the evidence
read-only lock, archive expansion, and the sudo / curl supply chain in
`install-tools.sh`. Re-run the review after any change to scripts
under `.claude/skills/dfir-bootstrap/` or to `.claude/settings.json`,
and update the issue (or open a follow-up) with the new findings.

---

## Forensic Constraints

- **No hallucinations** — Never guess, assume, or fabricate forensic artifacts, file contents, or system states.
- **Deterministic execution** — Use court-vetted CLI tools to generate facts; ground all conclusions in raw tool output.
- **Evidence integrity** — Never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
- **Output routing** — Write all scripts, CSVs, JSON, and reports to `./analysis/`, `./exports/`, or `./reports/`. Never write to `/` or evidence directories.
- **Timestamps** — Always output in UTC.
- **Verification** — Verify tool success after every run. On failure: read stderr → hypothesize → correct → retry.

---

## Expected Tool Paths (verify with preflight — see above)

> This table describes a FULL SIFT install. Not every SIFT instance has every
> tool. **Run `bash .claude/skills/dfir-bootstrap/preflight.sh` to see what is
> actually installed** before invoking any of these paths. When the preflight
> output disagrees with this table, the preflight is authoritative.

| Tool | Invocation | Presence | Notes |
|------|-----------|---------|-------|
| **Sleuth Kit** | `fls`, `icat`, `ils`, `blkls`, `mactime`, `tsk_recover` | typically present | Reads `.E01` directly via `libewf` — ewfmount NOT required |
| **Plaso** | `log2timeline.py`, `psort.py`, `pinfo.py` | install from GIFT PPA | v20240308 when present |
| **YARA** | `/usr/local/bin/yara` (v4.1.0) | typically present | |
| **bulk_extractor** | `bulk_extractor` (v2.0.3) | typically present | Defaults to 4 threads |
| **photorec** | `sudo photorec` | typically present | File carving by signature |
| **Volatility 3** | `/opt/volatility3/vol.py` (symlink → versioned dir; `install-tools.sh` maintains it) | optional install | Do NOT use `/usr/local/bin/vol.py` — that is Vol2. `vol.py` is executable; baseline.py is not (use `python3 /opt/volatility3/baseline.py`). |
| **Memory Baseliner** | `python3 /opt/volatility3/baseline.py` | optional install (csababarta/memory-baseliner) | Uses Vol3 as a library — files live next to `vol.py`, not in a standalone dir |
| **EZ Tools (root)** | `dotnet /opt/zimmermantools/<Tool>.dll` | **often absent** — verify via preflight | Falls back to `.claude/skills/dfir-bootstrap/parsers/*` |
| **EZ Tools (subdir)** | `dotnet /opt/zimmermantools/<Subdir>/<Tool>.dll` | **often absent** — verify via preflight | e.g. `EvtxeCmd/EvtxECmd.dll` |
| **EWF tools** | `ewfmount`, `ewfinfo`, `ewfverify` | install via `libewf-tools` from GIFT PPA | The Ubuntu package `ewf-tools` is the OLD libewf2 build and conflicts with modern `libewf` — `libewf-tools` (GIFT) is the correct package; provides the same binaries |
| **python3-regipy / python3-evtx** | dpkg packages | **often absent** — verify via preflight | Needed for structured hive / EVTX parsing |
| **dotnet runtime** | `/usr/bin/dotnet` (v9.0.x) | required for EZ Tools | Install `dotnet-runtime-9.0` from Microsoft package feed; runtime-only (no SDK needed) |
| **Wireshark CLI** | `tshark`, `capinfos`, `mergecap`, `editcap` | install `tshark` (pulls `wireshark-common`) | Display-filter pcap analysis; `-T fields` exports CSV-friendly columns |
| **Zeek** | `zeek`, `zeek-cut` | install `zeek` (jammy/universe) or upstream APT | Protocol-aware analyser → structured TSV logs (`conn.log`, `dns.log`, …) |
| **Suricata** | `suricata`, `suricata-update` | install `suricata` + `suricata-update` | Signature-based IDS; `-r` for offline pcap; ET Open via `suricata-update` |
| **tcpdump / tcpflow / ngrep / nfdump / jq** | small CLI helpers | install via apt | Capture-side utilities + flow records + JSON-line triage |
| **Chainsaw** | `chainsaw` (Rust binary, statically linked) | install from `https://github.com/WithSecureLabs/chainsaw/releases` | Sigma + Chainsaw-format hunting against `.evtx` corpus; `chainsaw lint` validates rule schema |
| **Hayabusa** | `hayabusa` (Rust binary, statically linked) | install from `https://github.com/Yamato-Security/hayabusa/releases` | One-shot Sigma-driven EVTX triage timeline |
| **evtx_dump** | `evtx_dump` | install via `cargo install evtx` or apt `evtx-tools` | Raw EVTX → JSONL fallback / pre-filter |

**Not available on any SIFT Linux instance:** MemProcFS, VSCMount (Windows-only).

**Fallbacks when tools above are absent:** see
`.claude/skills/dfir-bootstrap/SKILL.md` for the stdlib-only parsers (Recycle Bin,
Prefetch, registry hive strings, EVTX strings) that substitute for missing EZ Tools
and regipy/python-evtx.

### Shell Aliases (`.bash_aliases`)

```bash
vss_carver            # sudo python /opt/vss_carver/vss_carver.py
vss_catalog_manipulator
lr                    # getfattr -Rn ntfs.streams.list  (list NTFS ADS)
workbook-update       # update FOR508 workbook
```

---

## Tool Routing

> **If the case has ≥2 evidence items, or is open-ended enough to touch
> multiple domains** — use phase-based multi-agent orchestration via
> `@.claude/skills/ORCHESTRATE.md`. The orchestrator dispatches the six
> phase agents (`dfir-triage`, `dfir-surveyor`, `dfir-investigator`,
> `dfir-correlator`, `dfir-reporter`, `dfir-qa`) so raw tool output stays
> on disk and the main context holds only pointers. Phase 6 QA has
> authority to correct numerical / labeling / lead-status mistakes in
> place before sign-off.
>
> **If the case has a single evidence item and no specific lead** — start at
> `@.claude/skills/TRIAGE.md`. It runs the unguided protocol
> (triage → wide → deep → pivot) in one context and routes you into the right
> domain skill once a lead surfaces.
>
> **If the case has a specific question** — jump straight to the matching
> domain skill below. Each skill's "Tool selection" table maps the question to
> the best tool for it; do not default to "the most data" (full Plaso, full
> memmap dump, recursive YARA against the entire image) when a targeted query
> answers the question faster.

**Slash-command entrypoint:** `/case <CASE_ID> [evidence-path]`
launches phase-based orchestration. The command's first action is to
create `./cases/<CASE_ID>/evidence/` (if missing) and `cd` into the case
workspace; every subsequent path the agents write is relative to that
directory. Idempotent — a second invocation on the same case ID resumes
from the lowest-remaining phase rather than re-running earlier work.
Source: `.claude/commands/case.md`.

| Domain | Skill File |
|--------|-----------|
| **Multi-evidence / multi-domain orchestration (phase-based)** | `@.claude/skills/ORCHESTRATE.md` |
| **Unguided examination, single context (triage → pivot loop)** | `@.claude/skills/TRIAGE.md` |
| **Case start / preflight / fallbacks** | `@.claude/skills/dfir-bootstrap/SKILL.md` |
| Case scope & metadata | `@./CLAUDE.md` (project working directory) |
| Timeline generation (Plaso) | `@.claude/skills/plaso-timeline/SKILL.md` |
| File system & carving (Sleuth Kit) | `@.claude/skills/sleuthkit/SKILL.md` |
| Memory forensics (Volatility 3 / Memory Baseliner) | `@.claude/skills/memory-analysis/SKILL.md` |
| Windows artifacts (EZ Tools / Event Logs / Registry) | `@.claude/skills/windows-artifacts/SKILL.md` |
| Network forensics (tshark / Zeek / Suricata / pcap) | `@.claude/skills/network-forensics/SKILL.md` |
| Threat hunting & IOC sweeps (YARA / Velociraptor) | `@.claude/skills/yara-hunting/SKILL.md` |
| Sigma / EVTX hunting (Chainsaw + Hayabusa) | `@.claude/skills/sigma-hunting/SKILL.md` |

EZ Tools prefer native .NET over WINE. GUI tools (TimelineExplorer, RegistryExplorer) require WINE or the Windows analysis VM.

### Worked example — phase-based orchestration

A typical multi-evidence case (`/case CASE-2026-04`) flows like:

0. **Workspace setup** (the slash command's first action): `mkdir -p
   ./cases/CASE-2026-04/evidence && cd ./cases/CASE-2026-04` so the rest of
   the pipeline operates inside the case workspace.
1. **Phase 1 — `dfir-triage`** (haiku): runs `preflight.sh`, `case-init.sh CASE-2026-04`, classifies each item in `./evidence/` (`.E01` → disk, `.mem` → memory, `.pcap` → pcap), seeds `manifest.md`, runs the intake interview, returns `EV01..EVnn` + per-type counts.
2. **Phase 2 — `dfir-surveyor` × N parallel** (sonnet): one invocation per (evidence × domain) pair (e.g. `EV01 × windows-artifacts`, `EV01 × memory`, `EV02 × network`). Each runs cheap-signal passes from its domain skill, writes `survey-EV0N.md`, appends 3-5 leads to `leads.md` with format `L-EV01-memory-01`.
3. **Phase 3 — `dfir-investigator` × N parallel** (sonnet): one per open lead. Sets `status=in-progress` first, runs cheapest disconfirmation queries (DISCIPLINE rule F), writes one findings entry, transitions lead to `confirmed` / `refuted` / `escalated` / `blocked`.
4. **Phase 4 — `dfir-correlator`** (opus): single invocation. Cross-references all `findings.md` on timestamps / users / hosts / hashes / IPs, writes `correlation.md`. Adds `L-CORR-NN` leads for headline-flipping unknowns; the orchestrator dispatches another Phase 3 wave for those before re-running Phase 4.
5. **Phase 5 — `dfir-reporter`** (haiku): writes `final.md` (technical) and `stakeholder-summary.md` (business decision-makers, per `exec-briefing` skill). Runs the forbidden-phrase self-grep before returning.
6. **Phase 6 — `dfir-qa`** (opus): reconciles numerical claims against authoritative artifacts on disk, fixes mismatches in place via `Edit`, writes `qa-review.md`. Verdict: PASS / PASS-WITH-CHANGES / BLOCKED.

A second `/case CASE-2026-04` invocation is idempotent — it resumes at the lowest-remaining phase. The intake interview is the only point where the agent yields control to the operator.
