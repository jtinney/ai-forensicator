# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## DFIR Orchestrator — SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |

---

## Operator Preferences

- **NEVER ask questions during a task.** Run every workflow fully autonomously start-to-finish. No check-ins, no confirmations, no "shall I proceed?". Deliver final findings only. If blocked, pick the most reasonable path and note it in the output.

---

## Case Start Protocol

Before touching evidence on a new case or a new SIFT instance:

1. **Run preflight:** `bash .claude/skills/dfir-bootstrap/preflight.sh | tee ./analysis/preflight.md`
   This inventories *actually installed* tools (not the aspirational list below).
   Trust the preflight output over this file when they disagree.
2. **Scaffold the case:** `bash .claude/skills/dfir-bootstrap/case-init.sh <CASE_ID>`
   Creates `./analysis/`, `./exports/`, `./reports/` with `findings.md` stubs and an
   initialized `forensic_audit.log`.
3. **Follow the Analysis Discipline contract** (documented in every skill's SKILL.md):
   append an entry to `./analysis/forensic_audit.log` after every distinct action, and
   append a finding entry to the matching `./analysis/<domain>/findings.md` after every
   pivot. If either file has no new entries after a skill's workflow runs, that is a
   discipline failure — backfill before moving on.

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
| **Volatility 3** | `python3 /opt/volatility3-2.20.0/vol.py` | optional install | Do NOT use `/usr/local/bin/vol.py` — that is Vol2 |
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
> `@.claude/skills/ORCHESTRATE.md`. The orchestrator dispatches the five
> phase agents (`dfir-triage`, `dfir-surveyor`, `dfir-investigator`,
> `dfir-correlator`, `dfir-reporter`) so raw tool output stays on disk and
> the main context holds only pointers.
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
