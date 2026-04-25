# Skill: DFIR Bootstrap & Preflight

## Use this skill when
- A case is about to start (any case, any host)
- A new SIFT instance / fresh shell needs an inventory before evidence is touched
- A previously bootstrapped case needs `audit.sh` / fallback parser plumbing
- Any other skill reports missing tools and you need to know *what* is missing
  and *what* substitutes are available

**Hand off to** `@.claude/skills/TRIAGE.md` once preflight + case-init are
complete and there is no specific case lead. Hand off to a domain skill
directly if the case prompt names one (e.g., "memory image" → memory-analysis,
"USB exfil" → windows-artifacts).

## Overview
Use this skill **at the start of every case**, before invoking any other DFIR skill.
It does four things:

1. **Preflight** — inventories the SIFT instance's actually-available tools/libraries
   so the rest of the workflow doesn't burn calls discovering gaps mid-analysis.
2. **Installer remediation** — `install-tools.sh` checks what is missing and installs
   only missing components when run without `--check`.
3. **Case-init** — creates the full `./analysis/`, `./exports/`, `./reports/` scaffold
   and seeds the audit log + per-domain `findings.md` stubs the other skills expect.
4. **Stdlib fallback parsers** — Python scripts in `parsers/` that substitute for missing
   EZ Tools / regipy / python-evtx when those are absent. They cover the artifact types
   most cases actually pivot on (Recycle Bin, Prefetch, registry hive strings).

**Why this exists:** the global `~/.claude/CLAUDE.md` advertises tools that are not
guaranteed to be installed on every SIFT instance. The 2020JimmyWilson case (2026-04-18)
wasted multiple cycles discovering that `ewf-tools`, `pip`, `python-registry`, `regipy`,
`python-evtx`, and the entire `/opt/zimmermantools/` directory were absent. Run preflight
first — then you know up front what the real toolbox is and which skills need their
fallback path.

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

`case-init.sh` creates empty `findings.md` stubs under every domain folder. If you
finish a skill's workflow without having appended a single finding to `findings.md`,
that is a discipline failure — fix it before moving on.

---

## Workflow

### 1. At case start (before evidence arrives)

```bash
# Run preflight from the project root
bash .claude/skills/dfir-bootstrap/preflight.sh | tee ./analysis/preflight.md
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
  filesystem/findings.md              # stub
  windows-artifacts/findings.md       # stub
  windows-artifacts/hives/
  windows-artifacts/evtx/
  windows-artifacts/prefetch/
  windows-artifacts/recyclebin/
  memory/findings.md                  # stub
  timeline/findings.md                # stub
  yara/findings.md                    # stub
./exports/
  files/
  carved/
  yara_hits/
./reports/
  00_intake.md                        # template seeded with case-id + UTC start
```

### 4. Append audit entries with `audit.sh`

```bash
bash .claude/skills/dfir-bootstrap/audit.sh \
  "fls -r -o 65664 evidence.E01" \
  "11553 entries, NTFS partition at offset 65664" \
  "feed to mactime -> theft-window slice"
```

Writes a properly-formatted line to `./analysis/forensic_audit.log` with a UTC
timestamp. Cheaper than remembering the pipe format every time.

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
| Per-domain findings | `./analysis/<domain>/findings.md` |
| Installer log | `/tmp/dfir-install-<UTC timestamp>.log` |
| Recycle Bin CSV | `./reports/recyclebin_parsed.csv` |
| Prefetch CSV | `./reports/prefetch_parsed.csv` |
| Hive string dumps | `./analysis/windows-artifacts/hives/<HIVE>.strings.txt` |

---

## Notes

- **Run preflight on every new SIFT instance** — do not cache results across hosts.
  The 2020JimmyWilson case was on a SIFT instance missing almost every advertised tool.
- The bootstrap skill does not replace the other skills — it precedes them. Always
  hand off to `sleuthkit`, `windows-artifacts`, etc. for the actual analysis.
- If the user has asked for autonomous operation, preflight still runs; just log the
  results and proceed with whichever path the inventory dictates. Do not stop to ask.
