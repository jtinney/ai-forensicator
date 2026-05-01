# Skill: Memory Forensics (Volatility 3 / Memory Baseliner)

## Use this skill when
- A memory image (`.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`) is in scope
- You need to know what was *actually running* (vs. what disk says was
  installed) — hidden processes, unlinked drivers, in-memory-only payloads
- The case prompt mentions injection, hollowing, fileless malware, lsass
  access, in-memory C2, or "the binary on disk looks clean"
- A disk artifact (Prefetch / Amcache) shows execution but the binary is gone
  — memory may still hold the strings/PE

**Don't reach for memory when** the question is purely on-disk (deletion,
USB, persistence config, file timeline). Memory is irreplaceable but expensive
to triage; spend the budget when on-disk evidence has already pointed at a
process.

## Tool selection — pick by question

| Question | Best plugin | Why |
|---|---|---|
| Is this image valid? OS build / KDBG / kernel base? | `windows.info` | Mandatory first call — fails fast on wrong file type / missing symbols |
| What processes existed at capture (incl. hidden, exited)? | `windows.malware.psxview.PsXView` | Cross-references PsList, PsScan, Thrdproc, Csrss in one pass — the canonical "is this hidden?" answer |
| Parent-child sanity check | `windows.pstree` | Trims to the right cols with `cut -d \| -f 1-11` |
| What was each process's command line? | `windows.cmdline --pid <PID>` | Single fastest "what was it doing" answer |
| What was on the network? | `windows.netscan` (not `netstat`) | Pool scan finds historical / closed too |
| Injected code / shellcode / hollowing — known IOC | `windows.vadyarascan --yara-rules <r.yar>` | Per-PID hit narrows which process to dump; cheaper than `malfind --dump` against everything |
| Injected code / shellcode / hollowing — blind hunt | `windows.malfind --dump` | RWX VAD + PE-header heuristic; dump straight to disk |
| Hidden kernel drivers | `windows.modules` vs `windows.modscan` (delta) | Same logic as psscan vs pslist, kernel-side |
| Hidden services | `windows.svcscan` | Surfaces deleted-but-still-resident services |
| Recover a file from the cache | `windows.filescan` → `windows.dumpfiles --virtaddr` | Use when disk copy is gone or possibly tampered |
| Strings of one process | (1) `vadyarascan` to confirm there's something interesting, (2) `windows.memmap --dump --pid <PID>`, (3) `strings -a -el -n 8` | Don't dump every PID — narrow first |
| Diff vs known-good | Memory Baseliner `-proc` / `-drv` / `-svc` with `--loadbaseline --jsonbaseline` | Rapid stack-rank of "things not in the baseline" |
| Token / privilege escalation indicator | `windows.privs --pid <PID>` | Look for SeDebug / SeTcb in surprising processes |

**Rule of thumb:** start with `windows.info` → `windows.malware.psxview.PsXView` → `windows.pstree` → `windows.cmdline` → `windows.netscan`. Do
not run `memmap --dump` against every process — that's a dozen GB of dumps
nobody triages. Dump only after a lead.

## Overview
Use this skill for all memory image analysis on the SIFT workstation.

**Sudo is NOT required.** Vol3 reads the memory image as a regular file and
caches symbols in the user's `~/.cache/volatility3/` directory (per
`XDG_CACHE_HOME` or `~/.cache/`). Plugins that need root are the *live*
Linux/Mac memory plugins (which read `/dev/mem` / `/proc/kcore`) — not the
dump-analysis path covered here.

The stable invocation path is `/opt/volatility3/vol.py` — a symlink that
`install-tools.sh`'s `ensure_vol3_symlink()` step keeps pointing at the
installed version (`/opt/volatility3-<ver>/`). Skills and commands MUST use
the symlinked path so version bumps don't require edits across every skill
file.

## Analysis Discipline

`./analysis/` is not just a bucket for raw tool output. Keep both a terse audit trail and
human-written findings as you work.

- `./analysis/forensic_audit.log` — the action that triggers the entry must append its own UTC
  line describing that exact action, the tool or artifact reviewed, the result, and why it
  matters.
- `./analysis/memory/findings.md` — append short notes with the artifact reviewed, finding,
  interpretation, and next pivot.
- `./reports/00_intake.md` or the active case report — update it when a finding changes the
  case narrative.

Use this format for audit entries: `<UTC timestamp> | <action> | <finding/result> | <next step>`.
The `action` field must name the exact step that caused the log entry, such as `windows.info EV01`,
`psxview EV01`, `malfind --dump pid 4488`, or `netscan pivot on 10.0.0.5`; never use vague text
like `analysis update` or `progress`.

**Memory-specific entry templates** (copy and adapt the timestamps / PIDs):
```
2026-04-26T14:02:11Z | windows.info EV01 | Win10 19045 build, KDBG resolved at 0xfffff80...; image valid | proceed to psxview
2026-04-26T14:08:44Z | psxview EV01 | PID 4488 (svchost.exe) hidden from pslist+csrss, present in psscan+thrdproc | cmdline+dlllist on PID 4488
2026-04-26T14:14:02Z | malfind --dump pid 4488 | 1 RWX VAD with MZ header dumped to ./exports/malfind/pid.4488.vad.0x... | YARA sweep + parent process check
2026-04-26T14:20:18Z | netscan pivot 185.220.101.42 | Outbound :443 from PID 4488; not in netstat (closed before capture) | DNS cache + Sysmon EVTX 3 on disk
```

Never rely on the stop hook alone. If it only writes a timestamp, blank summary, or text that
does not describe the triggering action, add the missing action-specific context manually before
moving on.

## Tools

| Tool | Binary | Purpose |
|------|--------|---------|
| Volatility 3 | `/opt/volatility3/vol.py` (symlink → `/opt/volatility3-<ver>/`) | Process, network, registry, injection, and artifact extraction |
| Memory Baseliner | `/opt/volatility3/baseline.py` (csababarta/memory-baseliner; `baseline.py` + `baseline_objects.py` copied next to `vol.py` by `install-tools.sh`) | Diff suspect image against clean baseline / data-stack across many images |

> **CRITICAL:** `/usr/local/bin/vol.py` is **Volatility 2** (Python 2) — do NOT use it.
> Always use `/opt/volatility3/vol.py`.

> **Symbol cache:** Vol3 caches PDB symbol tables in `~/.cache/volatility3/` (per
> `XDG_CACHE_HOME` or `~/.cache/`). First use against a new Windows build downloads
> from Microsoft. Use `--offline` to fail fast rather than hanging when offline.
> Pre-staged ISF files can also live in `/opt/volatility3/volatility3/symbols/windows/` —
> read-only is fine; the user-cache fallback handles the writes.

---

## Quick Setup

```bash
# Create output dirs before starting — no sudo needed
mkdir -p ./analysis/memory ./exports/dumpfiles ./exports/malfind ./exports/memdump
```

**Output renderers** (use `-r <renderer>` flag — this skill standardizes on `csv`):

| Renderer | Description |
|----------|-------------|
| `csv` | Comma-separated — **default for this skill**, machine-parseable + opens in LibreOffice / Excel / Timeline Explorer |
| `pretty` | Pipe-delimited table with column headers — used only for `pstree` (tree structure is most readable in this form) |
| `quick` | Default tab-separated — used internally by `--dump` runs where the text output is incidental |
| `json` / `jsonl` | Use when piping into a downstream parser |

---

## Plugin Reference by Category

### Step 0 — Image validation (mandatory first call)

```bash
# Verify the image is parseable; capture OS build / KDBG / kernel base.
# Fails fast (in seconds) on wrong file type, Vol2 image, or unreachable symbols.
/opt/volatility3/vol.py -r csv -f <image.img> windows.info \
  > ./analysis/memory/imageinfo.csv
```

If `windows.info` fails, every subsequent plugin will too — fix the image / symbol /
network issue (see Error Handling) before proceeding.

### Process Enumeration

| Plugin | Method | Notes |
|--------|--------|-------|
| `windows.malware.psxview.PsXView` | Cross-source enumeration | **Canonical** — flags PIDs missing from any of PsList / PsScan / Thrdproc / Csrss |
| `windows.pslist` | EPROCESS linked list walk | Fast; misses unlinked (hidden) processes — kept for raw column detail |
| `windows.psscan` | Pool tag scan (`Proc`) | Finds hidden + exited; kept for raw column detail (offset, exit time) |
| `windows.pstree` | EPROCESS hierarchy | Parent-child relationships |

```bash
# Cross-source enumeration — the truth table for "what was actually running"
/opt/volatility3/vol.py -r csv -f <image.img> windows.malware.psxview.PsXView \
  > ./analysis/memory/psxview.csv

# Raw detail — keep both on disk for follow-up (offset, threads, exit time)
/opt/volatility3/vol.py -r csv -f <image.img> windows.psscan \
  > ./analysis/memory/psscan.csv
/opt/volatility3/vol.py -r csv -f <image.img> windows.pslist \
  > ./analysis/memory/pslist.csv

# Readable pstree (pipe-delimited, trimmed to first 11 columns)
/opt/volatility3/vol.py -r pretty -f <image.img> windows.pstree \
  | cut -d '|' -f 1-11 > ./analysis/memory/pstree.txt

# Filter pstree to a specific PID and its children
/opt/volatility3/vol.py -r pretty -f <image.img> windows.pstree --pid <PID> \
  | cut -d '|' -f 1-11

# Identify exited processes from psscan (ExitTime column not empty)
awk -F',' 'NR==1 || $10!=""' ./analysis/memory/psscan.csv \
  > ./analysis/memory/psscan_exited.csv

# Orphaned processes (PPID not present as any PID in pslist) — full record kept
awk -F',' 'NR>1 {pid[$1]=1; rec[NR]=$0; ppidcol[NR]=$2}
           END {for (i in ppidcol)
                  if (!(ppidcol[i] in pid) && ppidcol[i] != "0" && ppidcol[i] != "")
                    print rec[i]}' \
  ./analysis/memory/pslist.csv > ./analysis/memory/pslist_orphans.csv
```

### Process Details

```bash
# Command lines — most revealing for attacker activity
/opt/volatility3/vol.py -r csv -f <image.img> windows.cmdline \
  > ./analysis/memory/cmdline.csv
/opt/volatility3/vol.py -r csv -f <image.img> windows.cmdline --pid <PID>

# Environment variables (reveals injected env, working directory)
/opt/volatility3/vol.py -r csv -f <image.img> windows.envars \
  > ./analysis/memory/envars.csv

# Security identifiers / account context
/opt/volatility3/vol.py -r csv -f <image.img> windows.getsids --pid <PID> \
  > ./analysis/memory/getsids_<PID>.csv

# Token privileges (look for SeDebugPrivilege, SeTcbPrivilege)
/opt/volatility3/vol.py -r csv -f <image.img> windows.privs --pid <PID> \
  > ./analysis/memory/privs_<PID>.csv

# Loaded DLLs (check for spoofed or injected DLLs)
/opt/volatility3/vol.py -r csv -f <image.img> windows.dlllist --pid <PID> \
  > ./analysis/memory/dlllist_<PID>.csv

# Open handles — full table
/opt/volatility3/vol.py -r csv -f <image.img> windows.handles --pid <PID> \
  > ./analysis/memory/handles_<PID>.csv
```

`--object-type` filters worth knowing (each writes its own `.csv` for the analyst to follow):

| Type | What it tells you |
|------|-------------------|
| `File` | Files this process touched |
| `Mutant` | Mutex names — often hard-coded malware identifiers |
| `Key` | Registry keys held open |
| `Section` | Mapped binaries (PE images backing this process) |
| `Process` | Handles to OTHER processes — lateral / injection candidates |
| `Thread` | Handles to threads in OTHER processes — `CreateRemoteThread` / injection trace |

```bash
# Cross-process handles are the strongest single injection trace from a non-malfind path
/opt/volatility3/vol.py -r csv -f <image.img> windows.handles --pid <PID> --object-type Process \
  > ./analysis/memory/handles_<PID>_process.csv
/opt/volatility3/vol.py -r csv -f <image.img> windows.handles --pid <PID> --object-type Thread \
  > ./analysis/memory/handles_<PID>_thread.csv
/opt/volatility3/vol.py -r csv -f <image.img> windows.handles --pid <PID> --object-type Section \
  > ./analysis/memory/handles_<PID>_section.csv
```

### Network Connections

```bash
# Walk TCP/IP structures (active connections at capture time)
/opt/volatility3/vol.py -r csv -f <image.img> windows.netstat \
  > ./analysis/memory/netstat.csv

# Pool-tag scan (finds closed/historical connections too)
/opt/volatility3/vol.py -r csv -f <image.img> windows.netscan \
  > ./analysis/memory/netscan.csv

# Extract unique remote IPs for IOC pivot (skip header, drop loopback / wildcard)
awk -F',' 'NR>1 && $5 !~ /^(127\.|0\.0\.0\.0)/ {print $5}' \
  ./analysis/memory/netscan.csv | sort -u > ./analysis/memory/netscan_remote_ips.txt
```

`netscan` uses pool scanning and finds historical connections; `netstat` reflects current state.

### Services

```bash
# Enumerate services (pool scan — finds hidden services)
/opt/volatility3/vol.py -r csv -f <image.img> windows.svcscan \
  > ./analysis/memory/svcscan.csv

# Cross-reference service SIDs against known list
/opt/volatility3/vol.py -r csv -f <image.img> windows.getservicesids \
  > ./analysis/memory/getservicesids.csv

# Services with binary paths under user-writable directories (stage / persistence indicator)
grep -iE '\\(temp|appdata|users)\\' ./analysis/memory/svcscan.csv \
  > ./analysis/memory/svcscan_userpath.csv
```

### Registry

```bash
# List all loaded hive virtual addresses
/opt/volatility3/vol.py -r csv -f <image.img> windows.registry.hivelist \
  > ./analysis/memory/hivelist.csv

# Read a specific key
/opt/volatility3/vol.py -r csv -f <image.img> windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" \
  > ./analysis/memory/run_key.csv

/opt/volatility3/vol.py -r csv -f <image.img> windows.registry.printkey \
  --key "SYSTEM\CurrentControlSet\Services" \
  > ./analysis/memory/services_key.csv

# UserAssist — GUI execution evidence (programs launched via Explorer)
/opt/volatility3/vol.py -r csv -f <image.img> windows.registry.userassist \
  > ./analysis/memory/userassist.csv
```

### Code Injection & Anomalous Memory

```bash
# Targeted scan with known IOC YARA rules — fastest path when you have rules
/opt/volatility3/vol.py -r csv -f <image.img> windows.vadyarascan \
  --yara-rules /path/to/rules.yar \
  > ./analysis/memory/vadyarascan.csv
/opt/volatility3/vol.py -r csv -f <image.img> windows.vadyarascan \
  --pid <PID> --yara-rules /path/to/rules.yar \
  > ./analysis/memory/vadyarascan_<PID>.csv

# Blind injection scanner — use when you don't have rules yet
/opt/volatility3/vol.py -r csv -f <image.img> windows.malfind \
  > ./analysis/memory/malfind.csv

# Dump malfind hits to disk — only after triaging the malfind.csv table
/opt/volatility3/vol.py -f <image.img> windows.malfind \
  --dump --output-dir ./exports/malfind/

# VAD (Virtual Address Descriptor) tree — inspect all memory regions for a process
/opt/volatility3/vol.py -r csv -f <image.img> windows.vadinfo --pid <PID> \
  > ./analysis/memory/vadinfo_<PID>.csv

# Kernel module enumeration
/opt/volatility3/vol.py -r csv -f <image.img> windows.modules \
  > ./analysis/memory/modules.csv     # linked list
/opt/volatility3/vol.py -r csv -f <image.img> windows.modscan \
  > ./analysis/memory/modscan.csv     # pool scan (hidden)

# Modules in modscan but NOT in modules = hidden / rootkit driver (join on Base address)
awk -F',' 'NR==FNR {seen[$2]=1; next} FNR==1 || !($2 in seen)' \
  ./analysis/memory/modules.csv ./analysis/memory/modscan.csv \
  > ./analysis/memory/modscan_only.csv
```

### File & Code Extraction

```bash
# List all files cached in memory (use for finding dropped malware)
/opt/volatility3/vol.py -r csv -f <image.img> windows.filescan \
  > ./analysis/memory/filescan.csv

# Dump a file by virtual offset (from filescan)
/opt/volatility3/vol.py -f <image.img> windows.dumpfiles \
  --virtaddr <0xffffff...> \
  --output-dir ./exports/dumpfiles/

# Dump a process executable to disk
/opt/volatility3/vol.py -f <image.img> windows.pslist --dump --pid <PID>

# Dump all mapped memory pages for a process — only after psxview / cmdline / netscan
# pointed at the process. Don't dump every PID.
/opt/volatility3/vol.py -f <image.img> windows.memmap \
  --dump --pid <PID> --output-dir ./exports/memdump/
```

### Strings Extraction from Process Memory

Default flow: `vadyarascan` first to confirm something interesting lives in the
process; only then dump. Skipping the YARA pre-filter and dumping every PID
generates dozens of GB nobody triages.

```bash
# Step 1: targeted YARA pre-filter — confirms there's a reason to dump this PID
/opt/volatility3/vol.py -r csv -f <image.img> windows.vadyarascan \
  --pid <PID> --yara-rules /path/to/rules.yar \
  > ./analysis/memory/vadyarascan_<PID>.csv

# Step 2: dump process memory only if Step 1 hit (or the PID is already flagged
# by psxview / cmdline / netscan and you're hunting blind on it)
/opt/volatility3/vol.py -f <image.img> windows.memmap \
  --dump --pid <PID> --output-dir ./exports/memdump/

# Step 3: extract ASCII and Unicode strings (min 8 chars to reduce noise)
strings -a -n 8     ./exports/memdump/pid.<PID>.dmp \
  > ./analysis/memory/strings_<PID>_ascii.txt
strings -a -el -n 8 ./exports/memdump/pid.<PID>.dmp \
  > ./analysis/memory/strings_<PID>_unicode.txt

# Step 4: hunt for IOC patterns
grep -Ei '(https?://|ftp://|\\\\|cmd\.exe|powershell|regsvr|certutil)' \
  ./analysis/memory/strings_<PID>_ascii.txt \
  > ./analysis/memory/strings_<PID>_ioc.txt
```

### Timeline

```bash
# Generate timeline of all memory artifacts as a TSK-format bodyfile.
# `timeliner` is a top-level (cross-platform) plugin in Vol3 — no `windows.` prefix.
/opt/volatility3/vol.py -f <image.img> timeliner --create-bodyfile \
  > ./analysis/memory/mem_bodyfile.txt
mactime -b ./analysis/memory/mem_bodyfile.txt -z UTC \
  > ./analysis/memory/mem_timeline.txt
```

The bodyfile produced here can be merged with disk-side bodyfiles into a
unified super-timeline via `psort.py` — see `@.claude/skills/plaso-timeline/SKILL.md`.

---

## Memory Baseliner Workflow

See `reference/baseliner.md` for full Memory Baseliner usage (architecture,
both operating modes, comparison vs data-stacking flags, all `-proc/-drv/-svc`
invocations, JSON baseline creation, and the complete flag table).

Quick recall: `python3 /opt/volatility3/baseline.py -proc -i <img>
--loadbaseline --jsonbaseline <baseline.json> -o ./analysis/memory/proc_baseline.tsv`

---

## Six-Step Analysis Methodology

0. **Validate the image** — `windows.info` → `imageinfo.csv`. Confirms OS build, KDBG, kernel base; fails fast on wrong file type / missing symbols. No further plugin can succeed if this fails.
1. **Cross-source process enumeration** — `windows.malware.psxview.PsXView` → `psxview.csv`. PIDs missing from any source (PsList / PsScan / Thrdproc / Csrss) are hidden / hollowed candidates. Keep `pslist.csv` and `psscan.csv` on disk for raw column detail.
2. **Parent-child sanity** — `windows.pstree` → `pstree.txt`. Look for LOLBins under unexpected parents and orphans (PPIDs absent from PIDs — see `pslist_orphans.csv`).
3. **Per-PID context for any anomaly from steps 1-2** — `windows.cmdline`, `windows.envars`, `windows.privs`, `windows.getsids`, `windows.dlllist`, `windows.handles` (especially `--object-type Process|Thread|Section`). Build a profile of each suspect process before pivoting outward.
4. **Network** — `windows.netstat` + `windows.netscan` → `netstat.csv` and `netscan.csv`. Extract unique external remotes (`netscan_remote_ips.txt`) for IOC pivot.
5. **Injection** — `windows.vadyarascan` first if you have rules; `windows.malfind` for blind hunt. Dump only after a hit; don't `memmap --dump` every PID.
6. **Baseline comparison** — Memory Baseliner `-proc/-drv/-svc` if a clean image or JSON baseline exists. Treat any UNKNOWN as a Step-1-equivalent triage hit and drill back through Steps 2-5 for it.

---

## Process Anomaly Indicators

See `reference/anomaly-indicators.md` for the full anomaly table (wrong path,
wrong parent, taskhostw siblings, orphans, missing image path, unsigned
kernel modules, RWX VAD without file backing, cross-process handles, etc.) —
use it after Step-1 / Step-2 flag a candidate.

---

## Error Handling

**Symbol download failure / hanging:**
```bash
# Force offline mode (fail fast on missing symbols)
/opt/volatility3/vol.py --offline -f <image.img> windows.pslist

# Manually pre-download symbols for offline environments.
# ISF files: https://downloads.volatilityfoundation.org/volatility3/symbols/
# Place in: ~/.cache/volatility3/   (or /opt/volatility3/volatility3/symbols/windows/
# if you have write access there).
```

**Plugin error / empty output:**
```bash
# Redirect both stdout and stderr for full diagnostic output
/opt/volatility3/vol.py -f <image.img> windows.pslist 2>&1 \
  | tee ./analysis/memory/plugin_errors.txt

# Confirm image format is recognized
file <image.img>
/opt/volatility3/vol.py -f <image.img> windows.info
```

---

## Output Paths

Routing follows the canonical layer model in
`.claude/skills/dfir-discipline/DISCIPLINE.md` ("Layer model" subsection):
Volatility CSV / TSV / TXT outputs are summary-of-bytes (layer 3) and stay
under `./analysis/memory/`. The byte extracts (`windows.dumpfiles`,
`windows.malfind --dump`, `windows.memmap --dump`) are layer-4 derived
artifacts, hashed by `audit-exports.sh`. Multi-evidence cases use a
per-EVID subdir (`./exports/dumpfiles/EV01/...`) per Rule L because
Volatility's `--dump` emits a directory tree we don't control.

| Output | Path |
|--------|------|
| Image header | `./analysis/memory/imageinfo.csv` |
| Process enumeration (canonical + raw) | `./analysis/memory/psxview.csv`, `psscan.csv`, `pslist.csv`, `pstree.txt`, `pslist_orphans.csv`, `psscan_exited.csv` |
| Per-PID context | `./analysis/memory/cmdline.csv`, `envars.csv`, `privs_<PID>.csv`, `getsids_<PID>.csv`, `dlllist_<PID>.csv`, `handles_<PID>*.csv` |
| Network | `./analysis/memory/netstat.csv`, `netscan.csv`, `netscan_remote_ips.txt` |
| Services | `./analysis/memory/svcscan.csv`, `svcscan_userpath.csv`, `getservicesids.csv` |
| Registry | `./analysis/memory/hivelist.csv`, `userassist.csv`, `run_key.csv`, `services_key.csv` |
| Injection / drivers | `./analysis/memory/vadyarascan*.csv`, `malfind.csv`, `vadinfo_<PID>.csv`, `modules.csv`, `modscan.csv`, `modscan_only.csv` |
| Filescan / dumped files | `./analysis/memory/filescan.csv`, `./exports/dumpfiles/` |
| Malfind dumps | `./exports/malfind/` |
| Process memory dumps | `./exports/memdump/` |
| Strings | `./analysis/memory/strings_<PID>_ascii.txt`, `strings_<PID>_unicode.txt`, `strings_<PID>_ioc.txt` |
| Memory bodyfile / timeline | `./analysis/memory/mem_bodyfile.txt`, `mem_timeline.txt` |
| Baseline comparison TSVs | `./analysis/memory/proc_baseline.tsv`, `drv_baseline.tsv`, `svc_baseline.tsv` |

---

## Required baseline artifacts

This block is parsed by `.claude/skills/dfir-bootstrap/baseline-check.sh memory`.
Missing required artifacts produce a high-priority `L-BASELINE-memory-NN`
lead that runs first in the next investigator wave.

<!-- baseline-artifacts:start -->
required: analysis/memory/imageinfo.csv
required: analysis/memory/psxview.csv
required: analysis/memory/psscan.csv
required: analysis/memory/netscan.csv
required: analysis/memory/malfind.csv
required: analysis/memory/pstree.txt
optional: analysis/memory/pslist.csv
optional: analysis/memory/cmdline.csv
optional: analysis/memory/svcscan.csv
optional: analysis/memory/proc_baseline.tsv
optional: analysis/memory/survey-EV01.md
<!-- baseline-artifacts:end -->

---

## Pivots — what to do with what you found here

| Found here | Pivot to | Skill |
|---|---|---|
| `psxview.csv` row missing from one or more enumeration sources | (a) `cmdline --pid` for context, (b) `dlllist --pid`, (c) `handles --pid` (esp. `Process` / `Thread` types), (d) `vadyarascan` then `malfind --pid` if injection suspected | this skill |
| Suspicious PID with non-standard image path | (a) `cmdline --pid`, (b) `dlllist --pid`, (c) `handles --pid`, (d) on-disk binary at that path → hash + YARA + Prefetch/Amcache | this skill + `windows-artifacts` + `yara-hunting` |
| Orphaned process (PPID missing from PID list) | psxview row for that PID; if also hidden, treat as injection candidate | this skill |
| `malfind` hit | (a) dump it, (b) `strings` + YARA rule, (c) parent process + cmdline, (d) check disk for any backing file | this skill + `yara-hunting` |
| Outbound connection in `netscan` | (a) attribute to PID + cmdline, (b) DNS cache, (c) check disk for Sysmon EVTX 3 records, (d) browser history if userland | this skill + `windows-artifacts` |
| Hidden driver (`modscan_only.csv`) | Dump the driver image, hash, YARA, check signing chain on disk copy | this skill + `yara-hunting` |
| Service surfaced by `svcscan` only | RECmd → `SYSTEM\...\Services\<name>` for binary path + start type; cross-check `7045` install event | `windows-artifacts` |
| Strings in process memory (URL/hash/mutex) | Build a YARA rule, sweep disk + other processes; pivot DNS / netscan | `yara-hunting` + this skill |
| Memory Baseliner non-baseline item | Treat as a Step-1 triage hit: full process / driver / service drill-down | this skill |
| Memory bodyfile entries | Merge with disk bodyfile into super-timeline via `psort.py` | `plaso-timeline` |

## Notes

- `windows.malware.psxview.PsXView` is the canonical cross-source enumerator; `pslist` and `psscan` are kept for raw column detail (offsets, exit times) but are no longer the primary "is this hidden?" answer.
- `windows.malfind` produces false positives (JIT-compiled code, .NET CLR) — triage hits manually before dumping.
- `windows.netscan` may show connections from before image capture time — correlate with disk timeline.
- `windows.svcscan` surfaces services configured but not yet loaded, and deleted services still in memory.
- Vol3 plugins use dotted-namespace names (`windows.malfind`, `windows.registry.printkey`, `windows.malware.psxview.PsXView`, plus the cross-platform `timeliner` with no `windows.` prefix). Copy the exact name from `vol.py -h`.
- All commands in this skill use `/opt/volatility3/vol.py` — the symlinked path. Never reference the version-pinned `/opt/volatility3-<ver>/` directly.
