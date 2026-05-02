# Skill: DFIR Bootstrap & Preflight

## Use this skill when
- A case is about to start (any case, any host)
- A new SIFT instance / fresh shell needs an inventory before evidence is touched
- An already-bootstrapped case needs `audit.sh` / fallback parser plumbing
- Any other skill reports missing tools and you need to know *what* is missing
  and *what* substitutes are available

**Hand off to** `@.claude/skills/TRIAGE.md` once preflight + case-init are
complete and there is no specific case lead. Hand off to a domain skill
directly if the case prompt names one (e.g., "memory image" → memory-analysis,
"USB exfil" → windows-artifacts).

## Overview
Use this skill at the start of every case, before invoking any other DFIR
skill. It does nine things:

1. **Preflight** — inventories the SIFT instance's available tools and
   libraries so the workflow does not burn calls discovering gaps
   mid-analysis. Verifies the Suricata ET Open ruleset is present and
   populated (a Suricata install without rules silently runs an empty
   IDS pass).
2. **Installer remediation** — `install-tools.sh` reports gaps with
   `--check` and installs missing components without it.
   `suricata-update` is a hard fail when the ET Open sync errors.
3. **Case-init** — provisions the five-folder workspace
   (`./evidence/ ./working/ ./analysis/ ./exports/ ./reports/`),
   walks `./evidence/` depth-unbounded, sha256-hashes every file,
   expands zip / tar / tar.gz / 7z bundles into `./working/<basename>/`,
   hashes every member, and seeds `./analysis/manifest.md` with
   `bundle:*` and `bundle-member` rows so each analytic unit is tracked
   individually. Locks `./evidence/` read-only (`chmod -R a-w` on every
   file plus `chmod a-w` on the dir) so a stray `>` redirect, `mv`, or
   `tee` cannot mutate evidence if the harness hook is bypassed.
   Halt-on-failure contract: an empty `evidence/`, a disk-pressure
   condition, an extraction error, or a poisoned partial-expansion all
   exit nonzero with a BLOCKED lead row written to `analysis/leads.md`
   (`L-EVIDENCE-EMPTY-NN`, `L-EXTRACT-DISK-NN`, `L-EXTRACT-FAIL-NN`,
   `L-EXTRACT-POISON-NN`). After case-init, `manifest-check.sh` verifies
   the ledger against the on-disk evidence and `./working/` trees and
   refuses to PASS when (a) any file under `evidence/` lacks a manifest
   row, (b) any archive's `bundle-member` count does not match
   `find working/<basename>/ -type f | wc -l`, (c) any row carries
   `sha256 = -` without an `operator-acknowledged` lead in `leads.md`,
   or (d) a bespoke hash file lives outside the canonical ledger. The
   `/case` slash-command runs `manifest-check.sh` as a pre-dispatch
   gate; the PreToolUse hook calls `manifest-check.sh --quiet` before
   allowing reads against `./evidence/` or `./working/`.
4. **Intake interview** — `intake-check.sh` returns nonzero if any
   chain-of-custody field in `reports/00_intake.md` is blank;
   `intake-interview.sh` prompts the operator (TTY) or accepts
   `INTAKE_*` env vars (non-TTY) to fill the gaps. Phases 4 / 5 / 6
   refuse to run without it.
5. **Audit-log enforcement** — `audit.sh` is the only sanctioned writer
   of `./analysis/forensic_audit.log`. The PreToolUse hook in
   `.claude/settings.json` denies direct `>>` / `tee -a` / `sed -i`
   writes; the PostToolUse hook (`audit-verify.sh`) detects synthetic
   timestamps written via Python or other bypass paths and appends an
   `INTEGRITY-VIOLATION` row. `audit.sh` rejects vague action names,
   empty result/next-step fields, and rapid-duplicate rows (5-second
   window). The Stop hook (`audit-stop.sh`) logs a session boundary
   only when the prior session produced work. `audit-retrofit.sh` is
   an offline checker for pre-existing audit logs.
6. **Per-domain baseline-artifact contracts** — each domain SKILL.md
   declares a `<!-- baseline-artifacts -->` block listing the
   structured artifacts the surveyor produces. `baseline-check.sh
   <DOMAIN>` parses the block and tests each path; the orchestrator and
   correlator invoke it to surface `L-BASELINE-<DOMAIN>-<NN>` leads when
   a baseline is missing, and that lead runs FIRST in the next
   investigator wave.
7. **Lead terminal-status invariant** — `leads-check.sh` returns
   nonzero if any lead is non-terminal at case close (escalated parents
   whose children are terminal transition; in-progress rows are stale;
   high/med open rows are worked or downgraded with documented
   justification). The orchestrator runs it as a gate before Phases
   4 / 5 / 6.
8. **Stdlib fallback parsers** — Python scripts in `parsers/` that
   substitute for missing EZ Tools / regipy / python-evtx. They cover
   the artifact types cases pivot on (Recycle Bin, Prefetch, registry
   hive strings).
9. **Offline MITRE ATT&CK reference + validator** —
   `reference/mitre-attack.tsv` carries a curated subset of the
   enterprise matrix (id / tactic / name); `mitre-validate.sh
   <findings.md>` parses `MITRE:` lines and exits nonzero on malformed
   shape or unknown IDs. `dfir-qa` runs it against every
   `analysis/<domain>/findings.md` (DISCIPLINE rule K). The TSV is
   offline-only and analyst-extensible — append rows when a real
   technique is missing rather than reaching for a vague parent.

Shared discipline rules that bind every phase agent live in
`.claude/skills/dfir-discipline/DISCIPLINE.md`. Each agent's prompt
loads them at the top.

**Why this exists:** the global `~/.claude/CLAUDE.md` advertises tools
that are not guaranteed to be installed on every SIFT instance.
Preflight reveals what is actually installed before any skill
references it; the audit-log and baseline-artifact gates ensure
chain-of-custody and per-domain coverage hold across phases.

---

## Analysis Discipline (shared contract)

Every DFIR skill writes to the same three places:

- `./analysis/forensic_audit.log` — append-only. Format:
  `<UTC timestamp> | <action> | <finding/result> | <next step>`
  The `action` must name the exact step (e.g. `fls /Users`, `MFTECmd $MFT parse`, `rb_parse.py $I scan`).
  Never use vague text like `analysis update`.
- `./analysis/<domain>/findings.md` — human-written short notes. One entry per pivot.
  Template:
  ```
  ## <UTC timestamp> — <artifact reviewed>
  - **Finding:** <what you observed>
  - **Interpretation:** <what it means for the case>
  - **Next pivot:** <the next action triggered by this finding>
  ```
- `./reports/00_intake.md` or the active case report — update the narrative when a
  finding changes the headline.

`case-init.sh` does NOT pre-create `findings.md`. The surveyor and investigator
phases write the file on first append, so an empty / missing `findings.md` is an
unambiguous signal that the domain has produced no analyst output yet. If you
finish a skill's workflow without having appended a single finding to
`findings.md`, that is a discipline failure — fix it before moving on.

---

## Workflow

### 0. Case workspace

This project keeps a master `cases/` directory at the project root. Every
case lives under `./cases/<CASE_ID>/`, with its own `evidence/`, `working/`,
`analysis/`, `exports/`, `reports/` subtree. Before running any of the steps
below, create that workspace and `cd` into it (every `./...` path in this
skill is relative to the case workspace):

```bash
mkdir -p "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>/evidence"
cd "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>"
```

`case-init.sh` also auto-resolves the case workspace as a safety net
(it walks up to the project root, then `cd`s into `cases/<CASE_ID>/`),
so calling it from anywhere inside the project still scaffolds the right
directory.

### 1. At case start (before evidence arrives)

```bash
# Preflight: run from inside the case workspace; tool path is project-relative
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/preflight.sh" \
    | tee ./analysis/preflight.md
```

Output `./analysis/preflight.md` is a structured inventory:

- Available tools (with version)
- Missing tools (with install command + whether install is feasible)
- Missing Python libraries
- Network status (outbound reachable? sudo usable?)
- Per-skill readiness (green/yellow/red)
- Installer remediation commands (`install-tools.sh --check` and install mode)

Read it before touching evidence. If a skill is red, either ask the user to install
the missing piece, or jump straight to the fallback parser list below.

**Binary vs. dpkg split:** `preflight.sh` uses two independent checks. The Core CLI
section uses `command -v` (binary on `$PATH`). The dpkg section uses `dpkg -s`
(apt-managed packages only). A tool installed from an upstream source (e.g. Zeek from
OpenSUSE OBS at `/usr/local/bin/zeek`) passes the binary check and fails the dpkg
check — both are correct. **The authoritative readiness signal is the `SKILL_STATUS:`
sentinel lines** at the end of the report (`grep '^SKILL_STATUS:' preflight.md`). These
are derived from binary checks, not dpkg, and are what agents must read to determine
which domains are usable. The dpkg rows exist for package-management auditing, not
skill routing.

### 2. Install only what is missing (when preflight has gaps)

```bash
# Dry inventory (non-destructive): exits 0 when fully installed, 2 when gaps exist
bash .claude/skills/dfir-bootstrap/install-tools.sh --check

# Install missing components only
sudo bash .claude/skills/dfir-bootstrap/install-tools.sh
```

After install completes, re-run preflight and save fresh output:

```bash
bash .claude/skills/dfir-bootstrap/preflight.sh | tee ./analysis/preflight.md
```

### 3. Scaffold the case layout

```bash
# Run once per case from the project root
bash .claude/skills/dfir-bootstrap/case-init.sh <CASE_ID>
```

This creates (idempotent — safe to re-run):

```
./analysis/
  forensic_audit.log                  # initialized with header
  preflight.md                        # if preflight.sh was run
  manifest.md                         # evidence manifest header
  filesystem/
  windows-artifacts/
  windows-artifacts/hives/
  windows-artifacts/evtx/
  windows-artifacts/prefetch/
  windows-artifacts/recyclebin/
  memory/
  timeline/
  network/
  yara/
  sigma/
./exports/
  files/
  carved/
  yara_hits/
./reports/
  00_intake.md                        # template seeded with case-id + UTC start
```

> `findings.md` is NOT pre-created. The surveyor / investigator phases write
> the file on first append, so the presence of `./analysis/<domain>/findings.md`
> is itself a signal that the domain has produced analyst output.

### 4. Append audit entries with `audit.sh`

```bash
bash .claude/skills/dfir-bootstrap/audit.sh \
  "fls -r -o 65664 evidence.E01" \
  "11553 entries, NTFS partition at offset 65664" \
  "feed to mactime -> theft-window slice"
```

Writes a properly-formatted line to `./analysis/forensic_audit.log` with a UTC
timestamp. Cheaper than remembering the pipe format every time.

**This is now the only sanctioned writer.** The PreToolUse hook denies any
`>>` / `tee -a` / `sed -i` write to forensic_audit.log:

```bash
echo "..." >> ./analysis/forensic_audit.log     # DENIED at hook level
date | tee -a ./analysis/forensic_audit.log     # DENIED at hook level
bash audit.sh "..." "..." "..."                 # ALLOWED — wall-clock UTC
```

Read access (cat / head / tail / grep / Read tool) is unaffected. Python
writes that bypass the hook are caught by `audit-verify.sh` and recorded as
`INTEGRITY-VIOLATION` rows. See DISCIPLINE.md rule A for the full rationale.

### 5. Verify baseline artifacts per domain

```bash
# Test whether the network domain has its required baselines (capinfos.txt,
# zeek/conn.log, zeek/dns.log, suricata/eve.json) present
bash .claude/skills/dfir-bootstrap/baseline-check.sh network

# Same for any domain
for d in filesystem timeline windows-artifacts memory yara network; do
    bash .claude/skills/dfir-bootstrap/baseline-check.sh "$d"
done
```

Exit codes: `0` no gap, `1` gap (with JSON missing[] list on stdout), `2`
preconditions wrong. The orchestrator's resume protocol and the correlator's
Phase 4 step both call this; missing baselines surface as
`L-BASELINE-<DOMAIN>-<NN>` leads at priority `high`, run first in the next
wave. The contract for each domain lives in the matching SKILL.md as a
`<!-- baseline-artifacts:start --> ... <!-- baseline-artifacts:end -->`
fenced block.

### 6. Retro-audit a pre-existing audit log (offline)

```bash
bash .claude/skills/dfir-bootstrap/audit-retrofit.sh \
    /path/to/old/case/analysis/forensic_audit.log
```

Writes `<audit-dir>/audit-integrity.md` flagging rows with synthetic
timestamps (ISO-8601 `T...Z` form), non-monotonic time jumps, same-second
clusters (>= 4 rows), and unparseable lines. Use to inspect cases that
predate the PreToolUse / PostToolUse hooks. Read-only — never modifies the
audit log.

### 7. Hash extracted artifacts in `./exports/`

The `audit-exports.sh` PostToolUse hook auto-hashes everything written
under `./exports/`. You don't normally call it manually; it fires after
every Bash/Write/Edit when `./analysis/` exists.

`./exports/` and `./analysis/` serve different forensic roles:

| Dir | Role | Integrity model |
|---|---|---|
| `./evidence/` | Original artifacts. | Hashed at intake by case-init (`./analysis/manifest.md` rows). Read-only via permissions deny. |
| `./working/<bundle>/` | Bundle members from a zip/tar/7z in `./evidence/`. | Hashed at intake by case-init (`./analysis/manifest.md` rows with `bundle-member` type). |
| `./analysis/<domain>/*.csv\|json\|txt\|md` | Tool reports / summaries (capinfos, conv-ip, dns.csv, conn.log, eve.json, findings.md, correlation.md). | NOT hashed. Recomputable from original evidence by re-running the tool. |
| `./exports/**` | Extracted analytic units (carved files, reassembled HTTP objects, tcpflow streams, per-stream pcaps, bulk_extractor output, photorec recoveries, vol windows.dumpfiles output). | Hashed at write by `audit-exports.sh` (`./analysis/exports-manifest.md` rows). Mutations flagged. |

Conclusions chained on top of `./exports/` content (e.g. "this carved
binary is malware family X") are grounded in bytes whose sha256 is in
`exports-manifest.md`. A future examiner can verify identity. Mutations
to a recorded export (sha256 differs from its `first-seen` row) produce
a `MUTATED` row — investigate.

To inspect what's been tracked:

```bash
cat ./analysis/exports-manifest.md
# or just count by type
grep -cE '\| first-seen \|' ./analysis/exports-manifest.md
grep -cE '\| MUTATED \|'    ./analysis/exports-manifest.md
```

---

## Fallback Parsers (`parsers/`)

Use these when the corresponding EZ Tool / Python library is not installed. They are
deliberately stdlib-only — no `pip install` required.

| Parser | Replaces | Input | Output |
|---|---|---|---|
| `parsers/rb_parse.py` | RBCmd | Directory containing `$I...` files | CSV: `$I name, SID, original_path, size, deletion_utc` |
| `parsers/prefetch_parse.py` | PECmd | Directory of `.pf` files (Win7/8/10) | CSV: `name, hash, run_count, last_run_utc, version` |
| `parsers/hive_strings.py` | RECmd / regipy | Registry hive file | Extracts UTF-16LE values + ASCII key paths, greppable text dump |
| `parsers/evtx_strings.py` | EvtxECmd / python-evtx | EVTX file | Best-effort UTF-16LE strings dump — NOT structured XML |
| `network-forensics/parsers/pcap_summary.py` | `capinfos` + `tshark -q -z conv,ip` + `-Y dns` | pcap or pcapng file | CSV / JSON: capture metadata, top flows by bytes, top dports, DNS qnames |
| `network-forensics/parsers/zeek_triage.py` | `zeek-cut`/`awk` pipelines | Zeek log directory | CSV: top talkers, DNS qnames, HTTP user agents, TLS SNI/JA3, file extractions, notices |
| `network-forensics/parsers/suricata_eve.py` | `jq` over `eve.json` | Suricata `eve.json` | CSV: alerts grouped by signature/category/destination, file events, anomalies |
| `network-forensics/parsers/conn_beacon.py` | RITA | Zeek `conn.log` or tshark SYN CSV | CSV: ranked beaconing candidates by jitter / count / interval |

**Important caveats:**
- `rb_parse.py` and `prefetch_parse.py` produce the same columns EZ Tools produce for
  the subset of fields needed to tell the case story. Swap in RBCmd/PECmd later for
  completeness if install becomes possible.
- `hive_strings.py` is a workable-but-degraded substitute. It will find usernames,
  typed paths, USBSTOR device names, and file paths — but cannot produce structured
  USBSTOR FirstInstall/LastWrite FILETIMEs, UserAssist ROT13 decodes, or shellbag
  parsing. For those, install `python3-regipy` (`sudo apt install python3-regipy`).
- `evtx_strings.py` is triage-only. It cannot reconstruct 4624 records, LogonType,
  or TargetUserSid. For courtroom-quality logon timelines, install `python-evtx`
  (`sudo apt install python3-evtx`) or run EvtxECmd.

### Invocation examples

```bash
# Recycle Bin — parse all $I files in a directory
python3 .claude/skills/dfir-bootstrap/parsers/rb_parse.py \
  ./analysis/windows-artifacts/recyclebin/ \
  > ./reports/recyclebin_parsed.csv

# Prefetch — parse all .pf files
python3 .claude/skills/dfir-bootstrap/parsers/prefetch_parse.py \
  ./analysis/windows-artifacts/prefetch/ \
  > ./reports/prefetch_parsed.csv

# Hive string dump — extract readable values from SYSTEM hive
python3 .claude/skills/dfir-bootstrap/parsers/hive_strings.py \
  ./analysis/windows-artifacts/hives/SYSTEM \
  > ./analysis/windows-artifacts/hives/SYSTEM.strings.txt

# Grep for USB devices from the string dump
grep -iE "usbstor|disk&ven" ./analysis/windows-artifacts/hives/SYSTEM.strings.txt
```

---

## Key lessons the preflight was built to catch

| Lesson from the field | How preflight surfaces it |
|---|---|
| Global CLAUDE.md lists `ewfmount`/`ewfinfo` but only `libewf2` is installed | Preflight prints `ewf-tools: MISSING` and notes `TSK reads E01 directly — ewfmount NOT required` |
| `/opt/zimmermantools/` does not exist on this instance | Preflight prints `EZ Tools: MISSING — fall back to parsers/ scripts` |
| `pip3` / `python3 -m pip` unavailable → cannot self-install regipy | Preflight notes "no pip, cannot bootstrap new libs — ask user to `sudo apt install`" |
| Outbound network from bash sandbox is blocked | Preflight confirms with a 3-second curl and marks `network: BLOCKED` |
| `sudo apt install` needs TTY — may be unusable from Claude | Preflight reports `sudo: interactive-only (no -S -n)` when relevant |
| Missing tools need remediation quickly | Preflight includes a `Bootstrap Remediation` section with `install-tools.sh --check` and install commands |
| Assuming `.pf` LastRunTime is at offset 0x78 (it is 0x80 on Win7 v23) | Fallback parser encodes the correct offset per version — don't re-derive |

---

## Output Paths

| Output | Path |
|--------|------|
| Preflight report | `./analysis/preflight.md` |
| Audit log | `./analysis/forensic_audit.log` |
| Audit-log integrity report (post-hoc) | `./analysis/audit-integrity.md` |
| Audit-verify sidecar (last-scanned offset) | `./analysis/.audit.lastsize` |
| Evidence manifest (incl. bundle members) | `./analysis/manifest.md` |
| Bundle-expanded evidence | `./working/<basename>/...` |
| Exports manifest (sha256 of extracted artifacts) | `./analysis/exports-manifest.md` |
| Exports-sweep sidecar (last-scan mtime) | `./analysis/.exports.lastscan` |
| Per-domain findings | `./analysis/<domain>/findings.md` |
| Installer log | `/tmp/dfir-install-<UTC timestamp>.log` |
| Recycle Bin CSV | `./reports/recyclebin_parsed.csv` |
| Prefetch CSV | `./reports/prefetch_parsed.csv` |
| Hive string dumps | `./analysis/windows-artifacts/hives/<HIVE>.strings.txt` |

## Bootstrap helpers reference

| Script | Purpose |
|---|---|
| `preflight.sh` | Inventory CLI / Python / EZ Tools / dpkg / ET Open ruleset; emit per-skill GREEN/YELLOW/RED. Idempotent, side-effect-free. |
| `install-tools.sh` | Install missing tools (apt + pip + dotnet + EZ Tools + Sigma hunters: Chainsaw / Hayabusa / evtx_dump). `--check` for dry inventory. ET Open sync is a hard fail if it errors. |
| `case-init.sh <CASE_ID>` | Scaffold `./analysis/`, `./exports/`, `./reports/`. Walk `./evidence/` and expand bundles. Seed manifest.md with sha256 per file + per bundle member. Idempotent — safe to re-run. |
| `audit.sh "<action>" "<result>" "<next>"` | Append one well-formed wall-clock UTC row to forensic_audit.log. Rejects vague actions. The ONLY sanctioned writer of the audit log. |
| `audit-pretool-deny.sh` | PreToolUse hook on Bash. Denies `>>` / `tee -a` / `sed -i` to forensic_audit.log. Allows reads (cat/head/tail/grep/Read). Allows audit.sh / audit-verify.sh / audit-retrofit.sh. |
| `audit-verify.sh` | PostToolUse hook on Bash/Write/Edit. Scans new audit-log appends for ISO-8601 synthetic timestamps and >60s wall-clock drift. Emits `INTEGRITY-VIOLATION` rows via audit.sh. |
| `audit-retrofit.sh <audit-log>` | One-shot offline checker for an existing audit log. Read-only. Writes `audit-integrity.md` flagging suspect rows. |
| `audit-exports.sh` | PostToolUse hook (alongside audit-verify.sh). Sweeps `./exports/` and sha256-tracks every file in `./analysis/exports-manifest.md`. Mutations flagged. Idempotent fast path skips when `./exports/` has no new files. |
| `baseline-check.sh <DOMAIN>` | Per-domain artifact gap detector. Reads the `<!-- baseline-artifacts -->` block in the matching SKILL.md and tests each declared path. Exit 1 with JSON when a `required` artifact is missing. |

---

## Notes

- **Run preflight on every new SIFT instance** — do not cache results
  across hosts. SIFT instances vary in which advertised tools are
  actually installed; per-host inventory is the only reliable signal.
- The bootstrap skill does not replace the other skills — it precedes them. Always
  hand off to `sleuthkit`, `windows-artifacts`, etc. for the actual analysis.
- If the user has asked for autonomous operation, preflight still runs; just log the
  results and proceed with whichever path the inventory dictates. Do not stop to ask.
- The DISCIPLINE.md rules (`.claude/skills/dfir-discipline/DISCIPLINE.md`) are
  loaded by every phase agent prompt with a `MANDATORY:` line. The first
  audit-log entry of each agent invocation includes the marker
  `discipline_v2_loaded` as a self-attestation; bump the version (and update
  every agent prompt simultaneously) when the rules change substantively.
- Bundle expansion in case-init.sh is disk-bounded: if the estimated
  expanded size of an archive exceeds 50% of free disk, the bundle is
  manifested as `bundle:* | skipped expansion` and an audit entry records
  the skip. Free disk and re-run, or manually expand outside the case dir.
- The ET Open ruleset path is `/var/lib/suricata/rules/suricata.rules` on
  Ubuntu 22.04 + suricata-update package. If preflight reports it MISSING,
  `sudo suricata-update` re-syncs it (~50K signatures, 41 MB).
