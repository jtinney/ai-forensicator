# Skill: Windows Artifacts (EZ Tools / Autoruns / Event Logs)

## Use this skill when
- The case is Windows host-based and you have parsed/parseable artifacts:
  registry hives, EVTX, Prefetch, Amcache, MFT, $J, Recycle Bin, LNK, Jump
  Lists, Shellbags, SRUM, browser SQLite
- You can name the *question* — execution / persistence / logon / USB /
  deletion / shellbag history / browser activity. This skill's tool-selection
  table maps question → tool.

**Don't reach for this skill when** you don't yet have the artifact extracted
— go to `sleuthkit` first. Don't reach for it when the case is purely memory
or cross-artifact correlation — go to `memory-analysis` or `plaso-timeline`.

## Tool selection — pick by question

Each row picks the *single best tool* for the question. Lower-priority tools
appear in the deeper sections of this file as corroboration.

| Question | Best tool | Why this and not the others |
|---|---|---|
| Did `<binary>` execute, when, how often? | **PECmd** on `Windows\Prefetch\` | Authoritative: last 8 run times + DLLs/files referenced. Shimcache is weaker (existence only on Win8+); Amcache is good corroboration |
| What was *first installed* on this host recently? | **AmcacheParser** | SHA-1 of binary + first-run UTC; survives binary deletion |
| Did this *exist* on disk at some point? | **AppCompatCacheParser** (Shimcache) | Cheap "did the file ever exist" answer, even if deleted; no execution claim on Win8+ |
| Who logged in, when, from where? | **EvtxECmd** `Security --inc 4624,4625,4634,4647,4672,4648,4776` `--maps` | Maps directory expands payload → use it always |
| RDP source IP for a logon | **EvtxECmd** `TerminalServices-RemoteConnectionManager%4Operational --inc 1149` | Security 4624 only carries the workstation name, not the IP |
| What persistence is configured? | **RECmd** with `Kroll_Batch.reb` over all hives in `./exports/registry/` | One pass covers Run/RunOnce/Services/Image File Execution Options/AppInit/Userinit/Winlogon |
| Scheduled tasks | XML files in `Windows\System32\Tasks\` + EvtxECmd `TaskScheduler%4Operational --inc 106,200,201` | XML is the source of truth; EVTX gives execution history |
| WMI persistence (fileless) | EvtxECmd `WMI-Activity --inc 5860,5861` | 5861 = permanent subscription = persistence |
| What USB devices were plugged in? | **RECmd** `--kn USBSTOR` on `SYSTEM` | Vendor + product + serial + first-connect time; pivot to MountedDevices for drive letter |
| What folders did the user browse? | **SBECmd** on `NTUSER.DAT` + `UsrClass.dat` | Survives folder deletion; only tool for shellbags |
| What files did the user open recently? | **JLECmd** + **LECmd** + RECmd `RecentDocs` + `UserAssist` | Each covers a different launch path; combine for completeness |
| What did this `lnk` point at? | **LECmd** | MAC times, target path, volume serial, network share even if removed |
| Activity / focus history (Win10) | **WxTCmd** on `ActivitiesCache.db` | Per-app start/end + duration |
| Per-app network bytes / CPU / duration | **SrumECmd** on `SRUDB.dat` | Confirms execution AND C2 exfil volumes — high-value, often skipped |
| Browser history / cookies / downloads | **SQLECmd** `-d` over the User Data dir | Multi-browser; one pass |
| What was deleted (recycled)? | **RBCmd** on `\$Recycle.Bin\<SID>\$I*` | Original path + size + deletion UTC + which SID |
| File create/delete/rename history | **MFTECmd** on `$J` | Survives recycle bin emptying; chronological per-file |
| MFT slack-recovered entries | **MFTECmd** `-f $MFT --rs` | Names of partially-overwritten deleted files |
| What event IDs of interest in a channel | **EvtxECmd** `--inc <ids>` `--sd <utc> --ed <utc>` | Always filter by ID + window — full channel parses are slow and noisy |
| Strings inside a suspect binary | **bstrings** with `--lr` | Deep regex hunts on PE/script content |

## Tier reference (what to use when EZ Tools are absent)

| Artifact | Tier 1 (preferred) | Tier 2 | Tier 3 (stdlib fallback) |
|---|---|---|---|
| Prefetch | `PECmd` | — | `.claude/skills/dfir-bootstrap/parsers/prefetch_parse.py` |
| Recycle Bin `$I` | `RBCmd` | — | `.claude/skills/dfir-bootstrap/parsers/rb_parse.py` |
| Registry hives | `RECmd` + Kroll batch | `regipy` / `python-registry` | `parsers/hive_strings.py` (degraded — no FILETIMEs / structured shellbags) |
| EVTX | `EvtxECmd` `--maps` | `python-evtx` `evtx_dump.py` | `parsers/evtx_strings.py` (triage only) |
| MFT / $J | `MFTECmd` | `analyzeMFT`, `pytsk3` | `fls` / `istat` (inode-level only) |
| Shellbags | `SBECmd` | `regipy-shellbags` | (none — install Tier 1/2) |
| LNK | `LECmd` | `LnkParse3` | (none — install Tier 1/2) |
| Amcache | `AmcacheParser` | `regipy` amcache plugin | (none — install Tier 1/2) |

If the answer is "we cannot meaningfully parse this artifact at any tier on
this host," flag it in `./reports/00_intake.md` and request the install rather
than producing a half-answer.

## Overview
Use this skill for Windows host-based artifact analysis on the SIFT workstation.
Covers Eric Zimmerman (EZ) Tools, ASEP/persistence analysis, Windows event log parsing,
and execution/access evidence artifacts.

## Analysis Discipline

`./analysis/` is not just a bucket for raw tool output. Keep both a terse audit trail and
human-written findings as you work.

- `./analysis/forensic_audit.log` — the action that triggers the entry must append its own UTC
  line describing that exact action, the tool or artifact reviewed, the result, and why it
  matters.
- `./analysis/windows-artifacts/findings.md` — append short notes with the artifact reviewed,
  finding, interpretation, and next pivot.
- `./reports/00_intake.md` or the active case report — update it when a finding changes the
  case narrative.

Use this format for audit entries: `<UTC timestamp> | <action> | <finding/result> | <next step>`.
The `action` field must name the exact step that caused the log entry, such as `fls /Users`,
`MFTECmd $MFT parse`, or `netscan pivot on 10.0.0.5`; never use vague text like `analysis
update` or `progress`.
Never rely on the stop hook alone. If it only writes a timestamp, blank summary, or text that
does not describe the triggering action, add the missing action-specific context manually before
moving on.

---

## Preflight first

Run `.claude/skills/dfir-bootstrap/preflight.sh` at case start. Its output tells
you which of the three artifact-parsing tiers is actually available on this SIFT
instance:

| Tier | Tools required | Capability |
|---|---|---|
| **Tier 1 — Full** | `/opt/zimmermantools/` + `dotnet` | All EZ Tools (preferred) |
| **Tier 2 — Python** | `python3-regipy`, `python3-evtx` via dpkg | Structured registry + EVTX |
| **Tier 3 — Fallback** | stdlib only | `dfir-bootstrap/parsers/*` |

Never assume Tier 1. The `/opt/zimmermantools/` directory is an add-on install
and is routinely absent on minimal SIFT deployments. The rest of this skill
documents Tier 1 workflow; the fallback section below maps the same artifacts to
the Tier 2/3 commands when needed.

---

## Fallback workflow (Tier 2/3) — when EZ Tools are absent

See `reference/fallback-workflow.md` for the full Tier-2/3 recipes:
TSK-direct hive extraction (no `ewfmount`), the Recycle Bin / Prefetch /
hive-strings / EVTX-strings stdlib parsers in `dfir-bootstrap/parsers/`,
and the artifact-to-tool fallback matrix listing Tier-1 / Tier-2 / Tier-3
options per artifact type.

---

## EZ Tools — Running on Linux (SIFT)

All EZ Tools are installed at `/opt/zimmermantools/`. On Linux they run via the
.NET runtime using the `.dll` file — **not** the `.exe` (which is a Windows PE binary).

```bash
# Root-level tools:
dotnet /opt/zimmermantools/<ToolName>.dll [options]

# Subdirectory tools:
dotnet /opt/zimmermantools/<Subdir>/<ToolName>.dll [options]
```

> **GUI tools** (TimelineExplorer, RegistryExplorer, MFTExplorer, ShellBagsExplorer)
> are Windows PE applications. Run via `wine` on SIFT, or use the Windows analysis VM.

### Tool Reference

| Tool | Linux Command | Purpose |
|------|--------------|---------|
| PECmd | `dotnet /opt/zimmermantools/PECmd.dll` | Prefetch parser |
| AppCompatCacheParser | `dotnet /opt/zimmermantools/AppCompatCacheParser.dll` | Shimcache parser |
| AmcacheParser | `dotnet /opt/zimmermantools/AmcacheParser.dll` | Amcache.hve parser |
| MFTECmd | `dotnet /opt/zimmermantools/MFTECmd.dll` | MFT / UsnJrnl parser |
| JLECmd | `dotnet /opt/zimmermantools/JLECmd.dll` | Jump list parser |
| LECmd | `dotnet /opt/zimmermantools/LECmd.dll` | LNK file parser |
| WxTCmd | `dotnet /opt/zimmermantools/WxTCmd.dll` | Windows 10 Timeline parser |
| SBECmd | `dotnet /opt/zimmermantools/SBECmd.dll` | Shellbags (CLI) |
| RBCmd | `dotnet /opt/zimmermantools/RBCmd.dll` | Recycle Bin parser |
| bstrings | `dotnet /opt/zimmermantools/bstrings.dll` | Binary string extractor |
| SrumECmd | `dotnet /opt/zimmermantools/SrumECmd.dll` | SRUM database parser |
| EvtxECmd | `dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll` | Event log parser |
| RECmd | `dotnet /opt/zimmermantools/RECmd/RECmd.dll` | Registry batch parser |
| SQLECmd | `dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll` | SQLite artifact parser |
| TimelineExplorer | `wine /opt/zimmermantools/TimelineExplorer/TimelineExplorer.exe` | GUI CSV viewer |
| RegistryExplorer | `wine /opt/zimmermantools/RegistryExplorer/RegistryExplorer.exe` | GUI registry browser |
| VSCMount | **Windows only** — will NOT run on SIFT Linux | Volume Shadow Copy mount tool |

> **VSCMount note:** `dotnet /opt/zimmermantools/VSCMount.dll` prints "Mounting VSCs only
> supported on Windows. Exiting" on Linux. Use TSK's `mmls` + `icat` for VSS access on SIFT.

---

## Execution Evidence

### Prefetch

```bash
# Parse all Prefetch files to CSV
dotnet /opt/zimmermantools/PECmd.dll \
  -d ./exports/prefetch/ \
  --csv ./exports/prefetch/ \
  --csvf prefetch_parsed.csv

# Parse a single file (human-readable console output)
dotnet /opt/zimmermantools/PECmd.dll -f ./exports/prefetch/<FILE>.pf
```

Key: confirms execution + last **8** run timestamps + referenced DLLs and files.
Prefetch is disabled on Windows Server by default.

### Shimcache / AppCompatCache

```bash
dotnet /opt/zimmermantools/AppCompatCacheParser.dll \
  -f ./exports/registry/SYSTEM \
  --csv ./exports/shimcache/ \
  --csvf shimcache.csv

# Specify ControlSet (useful when multiple ControlSets exist — check with hivelist first)
dotnet /opt/zimmermantools/AppCompatCacheParser.dll \
  -f ./exports/registry/SYSTEM \
  --c 1 \
  --csv ./exports/shimcache/ \
  --csvf shimcache_cs1.csv

# Sort by last modified time descending (most recent first)
dotnet /opt/zimmermantools/AppCompatCacheParser.dll \
  -f ./exports/registry/SYSTEM \
  -t \
  --csv ./exports/shimcache/
```

Key: presence confirms the file **existed** on disk. Does NOT confirm execution on Win8+.
Ordered chronologically by last run on Win7; unordered on Win8+.

**AppCompatCacheParser flags:**
| Flag | Description |
|------|-------------|
| `-f <file>` | SYSTEM hive path |
| `--c <N>` | ControlSet number to parse (default: auto-detect) |
| `-t` | Sort output by last modified time descending |
| `--nl` | Ignore transaction logs |
| `--csv <dir>` | Output directory for CSV files |
| `--csvf <name>` | Output CSV filename |

### Amcache

```bash
dotnet /opt/zimmermantools/AmcacheParser.dll \
  -f ./exports/registry/Amcache.hve \
  --csv ./exports/amcache/ \
  --csvf amcache.csv

# Ignore transaction logs (faster, use when hive is not dirty)
dotnet /opt/zimmermantools/AmcacheParser.dll \
  -f ./exports/registry/Amcache.hve \
  --nl \
  --csv ./exports/amcache/

# Filter out known-good hashes (SHA-1 blacklist) to reduce noise
dotnet /opt/zimmermantools/AmcacheParser.dll \
  -f ./exports/registry/Amcache.hve \
  -w /path/to/known_good_sha1s.txt \
  --csv ./exports/amcache/

# Keep only known-bad hashes (SHA-1 whitelist — hunt for specific malware)
dotnet /opt/zimmermantools/AmcacheParser.dll \
  -f ./exports/registry/Amcache.hve \
  -b /path/to/known_bad_sha1s.txt \
  --csv ./exports/amcache/
```

Key: SHA1 hash of executed binaries + first execution time. Use hash for VirusTotal pivots.

**AmcacheParser flags:**
| Flag | Description |
|------|-------------|
| `-f <file>` | Amcache.hve path |
| `--nl` | Ignore transaction logs (faster for forensic copies) |
| `--mp` | High-precision timestamps (nanoseconds) |
| `-w <file>` | Blacklist — exclude entries matching SHA-1s in file |
| `-b <file>` | Whitelist — only return entries matching SHA-1s in file |
| `--csv <dir>` | Output directory for CSV files |
| `--csvf <name>` | Output CSV filename |

### BAM / DAM (Background/Desktop Activity Moderator)

Located in: `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>`

```bash
# Parse via RECmd batch (see RECmd section below)
# Or extract raw key via registry hive viewer
```

Key: Records last execution time for each user's programs. Survived reboots until Win10 1809.

---

## MFT and Change Journal

### MFT

```bash
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/\$MFT \
  --csv ./exports/mft/ \
  --csvf mft_parsed.csv

# Include all timestamps (MACE + MACE for $STANDARD_INFO and $FILE_NAME)
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/\$MFT \
  --at \
  --csv ./exports/mft/ \
  --csvf mft_alltimestamps.csv

# Generate bodyfile output (for integration with mactime / plaso)
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/\$MFT \
  --body ./exports/mft/ \
  --bdl C \
  --bodyf mft_bodyfile.txt

# Recover slack space entries (files that partially overlap deleted records)
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/\$MFT \
  --rs \
  --csv ./exports/mft/ \
  --csvf mft_with_slack.csv

# Dump a specific MFT entry by record number
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/\$MFT \
  --de <record_number>
```

### $UsnJrnl (NTFS Change Journal)

```bash
# The journal is extracted as $UsnJrnl:$J — parse it directly
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/\$J \
  --csv ./exports/mft/ \
  --csvf usnjrnl_parsed.csv

# Parse $J with VSS processing (finds entries from shadow copies)
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ./exports/mft/\$J \
  --vss \
  --csv ./exports/mft/ \
  --csvf usnjrnl_vss.csv

# Or extract $J from the MFT image inode (inode 11 on NTFS) via icat, then parse
```

Key: records every file create/modify/delete/rename with timestamps. Survives deletion.

**MFTECmd flags:**
| Flag | Description |
|------|-------------|
| `-f <file>` | Input: `$MFT`, `$J`, `$Boot`, `$SDS`, or `$I30` |
| `--at` | Include ALL timestamps (both $SI and $FN attribute timestamps) |
| `--rs` | Recover slack space entries from MFT |
| `--vss` | Process Volume Shadow Copy entries in $J |
| `--body <dir>` | Output as bodyfile (for mactime/plaso) |
| `--bdl <letter>` | Drive letter for bodyfile paths (e.g., `C`) |
| `--bodyf <name>` | Bodyfile output filename |
| `--de <record>` | Dump details for specific MFT entry number |
| `--csv <dir>` | CSV output directory |
| `--csvf <name>` | CSV output filename |

---

## Registry Parsing

### RECmd — Batch Mode (Recommended)

RECmd batch mode runs an entire collection of community-maintained queries against
one or more hive files simultaneously, extracting all known forensic artifacts.

```bash
# Single hive batch parse
dotnet /opt/zimmermantools/RECmd/RECmd.dll \
  -f ./exports/registry/NTUSER.DAT \
  --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb \
  --csv ./exports/registry/ \
  --csvf ntuser_batch.csv

# All hives in a directory
dotnet /opt/zimmermantools/RECmd/RECmd.dll \
  -d ./exports/registry/ \
  --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb \
  --csv ./exports/registry/ \
  --csvf all_hives_batch.csv
```

Batch files are in `/opt/zimmermantools/RECmd/BatchExamples/`.
`Kroll_Batch.reb` covers: UserAssist, RecentDocs, TypedPaths, MRU, USB, Run keys,
WordWheelQuery, OpenSaveMRU, and many more.

**RECmd targeted query flags:**
| Flag | Description |
|------|-------------|
| `--kn <name>` | Search for specific key name |
| `--vn <name>` | Search for specific value name |
| `--bn <file>` | Batch file (.reb) for multi-query runs |
| `--base64` | Decode Base64-encoded values in output |
| `--minSize <N>` | Only return values with data size >= N bytes |
| `--nl` | Ignore transaction logs |

### Key Registry Artifacts

| Artifact | Hive | Key Path |
|----------|------|----------|
| Run/RunOnce | NTUSER.DAT / SOFTWARE | `...\Windows\CurrentVersion\Run` |
| UserAssist (GUI execution) | NTUSER.DAT | `...\Explorer\UserAssist\{GUID}\Count` |
| RecentDocs | NTUSER.DAT | `...\Explorer\RecentDocs` |
| TypedPaths (Explorer bar) | NTUSER.DAT | `...\Explorer\TypedPaths` |
| MRU Lists | NTUSER.DAT | Various — use RECmd batch |
| BAM/DAM execution | SYSTEM | `...\Services\bam\State\UserSettings` |
| USB/USBSTOR | SYSTEM | `...\Enum\USBSTOR` |
| USB VID/PID | SYSTEM | `...\Enum\USB` |
| USB drive letter | SYSTEM / NTUSER.DAT | MountedDevices + Explorer\MountPoints2 |
| Services | SYSTEM | `...\Services` |
| Shimcache | SYSTEM | `...\Session Manager\AppCompatCache` |
| Timezone | SYSTEM | `...\Control\TimeZoneInformation` |
| Computer name | SYSTEM | `...\Control\ComputerName\ComputerName` |
| Last shutdown | SYSTEM | `...\Control\Windows` → ShutdownTime |
| Amcache programs | Amcache.hve | `Root\InventoryApplicationFile` |

### USB Device Artifacts (Full Chain)

```bash
# USBSTOR — every USB storage device ever connected
# SYSTEM hive: HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR

# USB VID/PID — manufacturer/product identification
# SYSTEM hive: HKLM\SYSTEM\CurrentControlSet\Enum\USB

# Drive letter assignment (last mounted drive letter)
# SYSTEM hive: HKLM\SYSTEM\MountedDevices

# Volume GUID (links device to drive letter)
# NTUSER.DAT: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

# All parsed automatically by Kroll_Batch.reb
```

---

## Shellbags

Shellbags record folder browsing history (local, network, removable media) — persists
even after directories/drives are removed.

```bash
dotnet /opt/zimmermantools/SBECmd.dll \
  -d ./exports/registry/ \
  --csv ./exports/shellbags/

# Or target NTUSER.DAT directly
dotnet /opt/zimmermantools/SBECmd.dll \
  -f ./exports/registry/NTUSER.DAT \
  --csv ./exports/shellbags/

# Deduplicate entries (removes repeated identical shellbag records)
dotnet /opt/zimmermantools/SBECmd.dll \
  -d ./exports/registry/ \
  --dedupe \
  --csv ./exports/shellbags/

# Force output timezone (default: local — always override to UTC)
dotnet /opt/zimmermantools/SBECmd.dll \
  -d ./exports/registry/ \
  --tz UTC \
  --csv ./exports/shellbags/
```

Key hives: `NTUSER.DAT` (user folders) and `UsrClass.dat` (desktop/network/ZIP).

**SBECmd flags:**
| Flag | Description |
|------|-------------|
| `-f <file>` | Single hive file |
| `-d <dir>` | Directory containing hive files |
| `--dedupe` | Remove duplicate shellbag entries |
| `--tz <zone>` | Output timezone (use `UTC`) |
| `--csv <dir>` | CSV output directory |

---

## Jump Lists & LNK Files

```bash
# Jump lists (AutomaticDestinations + CustomDestinations)
dotnet /opt/zimmermantools/JLECmd.dll \
  -d ./exports/jumplists/ \
  --csv ./exports/jumplists/ \
  --csvf jumplists_parsed.csv

# LNK files (link files from Recent, Desktop, Startup)
dotnet /opt/zimmermantools/LECmd.dll \
  -d ./exports/lnk/ \
  --csv ./exports/lnk/ \
  --csvf lnk_parsed.csv
```

Key: reveals target file paths, MAC times, volume serial numbers, and network shares —
even if the target file no longer exists.

---

## Windows 10 Activity Timeline (WxTCmd)

```bash
dotnet /opt/zimmermantools/WxTCmd.dll \
  -f ./exports/WindowsTimeline/ActivitiesCache.db \
  --csv ./exports/WindowsTimeline/

# ActivitiesCache.db location on disk:
# C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\<ID>\ActivitiesCache.db
```

Key: records application focus events with start/end time and duration (Win10 only).

---

## SRUM (System Resource Usage Monitor)

```bash
dotnet /opt/zimmermantools/SrumECmd.dll \
  -f ./exports/srum/SRUDB.dat \
  --csv ./exports/srum/ \
  --csvf srum_parsed.csv

# Optionally provide SOFTWARE hive for application name resolution
dotnet /opt/zimmermantools/SrumECmd.dll \
  -f ./exports/srum/SRUDB.dat \
  -r ./exports/registry/SOFTWARE \
  --csv ./exports/srum/
```

`SRUDB.dat` is located at `C:\Windows\System32\sru\SRUDB.dat`.

Key: records per-application network bytes sent/received, CPU time, and energy use
with timestamps. Confirms execution and C2 data transfer volumes.

---

## Browser Artifacts (SQLECmd)

```bash
# Parse all SQLite databases SQLECmd knows about (Chrome, Edge, Firefox)
dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll \
  -d ./exports/browser/ \
  --csv ./exports/browser/parsed/

# Key Chrome/Edge profile paths on disk:
# C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\
# C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\
# Relevant files: History, Cookies, Web Data, Login Data, Downloads
```

---

## ASEP Analysis (Autorunsc)

### Standard Collection Command (run on Windows target)
```
autorunsc.exe /accepteula -a * -c -h -s '*' -nobanner
```
Options: `-a *` all categories, `-c` CSV output, `-h` file hashes, `-s` verify signatures.

### ASEP Categories to Review

| Category | Why It Matters |
|----------|---------------|
| **Services** | Common persistence; verify Image Path matches expected binary |
| **Drivers** | Must be signed on 64-bit Windows; unsigned = high priority |
| **Known DLLs** | DLL hijacking target |
| **Logon** | Run/RunOnce keys, startup folders |
| **Tasks** | Scheduled task persistence |
| **Explorer** | Shell extensions, browser helper objects |
| **Boot Execute** | Runs before user-mode — rootkit territory |
| **WMI** | WMI subscriptions used for fileless persistence |

### CLI Analysis of Autorunsc CSV

```bash
# Show column names
head -1 <hostname>-Autorunsc.csv | tr ',' '\n' | nl

# Find unsigned/unverified entries
grep -i "not verified" <hostname>-Autorunsc.csv

# Find enabled entries only
grep -i ",enabled," <hostname>-Autorunsc.csv

# Find entries with blank signer (column 8 in standard CSV)
awk -F',' '$8 == ""' <hostname>-Autorunsc.csv

# Find suspicious image paths (not in Windows or Program Files)
grep -i ",enabled," <hostname>-Autorunsc.csv | \
  grep -iv "c:\\\\windows\|c:\\\\program files\|c:\\\\program files (x86)"

# Extract hashes for VirusTotal pivot
awk -F',' '{print $10}' <hostname>-Autorunsc.csv | sort -u | grep -v "^$\|^Hash"
```

### Timeline Explorer ASEP Filtering Workflow

After collecting Autorunsc CSV, open in Timeline Explorer:
```bash
wine /opt/zimmermantools/TimelineExplorer/TimelineExplorer.exe
```

**Step-by-step triage in Timeline Explorer:**
1. Load the Autorunsc CSV file
2. Filter **Signer** column → select **(Not Verified)** and **(Blanks)** — unsigned or unverifiable entries
3. Filter **Enabled** column → keep only **enabled** entries (active persistence)
4. Review **Image Path** for suspicious locations (`%TEMP%`, `%APPDATA%`, non-standard paths)
5. Cross-reference **Entry Location** (what ASEP category — Driver, Service, Logon, Task, etc.)
6. For drivers: compare against VanillaWindowsReference baseline (see below)

### Driver Baseline (VanillaWindowsReference)

Compare drivers found by Autorunsc against a clean Windows baseline to identify additions:
- **Project:** https://github.com/AndrewRathbun/VanillaWindowsReference
- Contains known-good driver lists for each major Windows version
- Any driver absent from the baseline is high priority for investigation
- A driver that is "not verified" AND absent from baseline = critical finding

### Red Flags
- Executable in `C:\Windows\` with a name that mimics a legitimate tool (typosquatting)
- Service or driver with no valid digital signature
- Driver absent from a clean Windows baseline (VanillaWindowsReference)
- `File not found` in Image Path — artifact of deleted malware
- Scheduled task running from `%TEMP%`, `%APPDATA%`, or unusual paths
- WMI event subscriptions that weren't present in baseline

---

## Windows Event Log Parsing

### EvtxECmd

```bash
# Parse a single EVTX file to CSV
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -f ./exports/evtx/<logname>.evtx \
  --csv ./exports/evtx/parsed/ \
  --csvf <output>.csv

# Parse all EVTX files in a directory (most common usage)
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --csv ./exports/evtx/parsed/

# Use Maps directory for rich field parsing (recommended — enables PayloadData columns)
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --csv ./exports/evtx/parsed/ \
  --maps /opt/zimmermantools/EvtxeCmd/Maps/

# Filter to specific Event IDs only (comma-separated)
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --inc 4624,4625,4648,4672,4688 \
  --csv ./exports/evtx/parsed/ \
  --csvf logon_and_execution.csv

# Exclude noisy Event IDs
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --exc 4688,4689 \
  --csv ./exports/evtx/parsed/

# Filter by date range (UTC)
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ./exports/evtx/ \
  --sd "2023-01-24 00:00:00" \
  --ed "2023-01-26 23:59:59" \
  --csv ./exports/evtx/parsed/ \
  --csvf incident_window.csv

# Export as XML (for manual inspection or custom parsing)
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -f ./exports/evtx/Security.evtx \
  --xml ./exports/evtx/xml/
```

**EvtxECmd flags:**
| Flag | Description |
|------|-------------|
| `-f <file>` | Single EVTX file |
| `-d <dir>` | Directory of EVTX files |
| `--inc <ids>` | Include only specified Event IDs (comma-separated) |
| `--exc <ids>` | Exclude specified Event IDs (comma-separated) |
| `--sd <datetime>` | Start date filter (UTC: `YYYY-MM-DD HH:MM:SS`) |
| `--ed <datetime>` | End date filter (UTC: `YYYY-MM-DD HH:MM:SS`) |
| `--maps <dir>` | Maps directory for structured field parsing |
| `--csv <dir>` | CSV output directory |
| `--csvf <name>` | CSV output filename |
| `--xml <dir>` | XML output directory |

### Key Event IDs

See `reference/event-ids.md` for the full Event-ID reference grouped by EVTX
channel: Logon/Auth, Account & Privilege, Process/Execution, Object Access,
PowerShell (both channels), RDP, Defender, System (incl. 7045 service install),
Scheduled Tasks, and WMI (incl. 5861 permanent subscription = persistence).
Use the IDs from that reference with `EvtxECmd --inc <ids> --maps`.

---

## Recycle Bin

```bash
dotnet /opt/zimmermantools/RBCmd.dll \
  -d ./exports/recyclebin/ \
  --csv ./exports/recyclebin/ \
  --csvf recyclebin_parsed.csv

# Recycle Bin location on disk: C:\$Recycle.Bin\<SID>\
# $I files = metadata (original path, deletion time, size)
# $R files = actual file content
```

---

## Binary String Extraction

```bash
# Extract printable strings from a suspicious binary (min 5 chars)
dotnet /opt/zimmermantools/bstrings.dll -f ./exports/files/<binary> --lr

# Regex hunt within strings
dotnet /opt/zimmermantools/bstrings.dll -f ./exports/files/<binary> \
  --Pattern "(https?://|\\\\\\\\[0-9]{1,3}\\.)"
```

---

## Output Paths

Routing follows the canonical layer model in
`.claude/skills/dfir-discipline/DISCIPLINE.md` ("Layer model" subsection).
EZ Tool CSV outputs live under `./exports/<artifact>/` because they are
treated as the analytic-unit byte view of the underlying registry hive
or EVTX corpus (the parser reformat *is* the artifact downstream
analysis pivots on). Multi-evidence cases append the EVID per Rule L
(e.g. `exports/evtx/parsed/Security-EV01.csv`); directory-tree exports
(full registry batch dumps) use `exports/registry/EV01/...`.

| Output | Path |
|--------|------|
| Event log CSVs | `./exports/evtx/parsed/` |
| Shimcache CSV | `./exports/shimcache/` |
| Prefetch CSV | `./exports/prefetch/` |
| Amcache CSV | `./exports/amcache/` |
| MFT CSV | `./exports/mft/` |
| UsnJrnl CSV | `./exports/mft/` |
| SRUM CSV | `./exports/srum/` |
| Registry batch CSV | `./exports/registry/` |
| Shellbags CSV | `./exports/shellbags/` |
| Jump lists CSV | `./exports/jumplists/` |
| LNK CSV | `./exports/lnk/` |
| Browser artifacts CSV | `./exports/browser/parsed/` |
| Windows Timeline CSV | `./exports/WindowsTimeline/` |
| Recycle Bin CSV | `./exports/recyclebin/` |
| Reports | `./reports/` |

---

## Required baseline artifacts

This block is parsed by `.claude/skills/dfir-bootstrap/baseline-check.sh windows-artifacts`.
Missing required artifacts produce a high-priority
`L-BASELINE-windows-artifacts-NN` lead that runs first in the next
investigator wave.

<!-- baseline-artifacts:start -->
optional: analysis/windows-artifacts/registry-summary.md
optional: analysis/windows-artifacts/evtx-summary.md
optional: analysis/windows-artifacts/prefetch-summary.csv
optional: analysis/windows-artifacts/amcache-summary.csv
optional: analysis/windows-artifacts/survey-EV01.md
<!-- baseline-artifacts:end -->

---

## Pivots — what to do with what you found here

| Found here | Pivot to | Skill |
|---|---|---|
| Prefetch entry for a LOLBin from `\Users\` / `\Temp\` | (a) Amcache for SHA-1, (b) `$J` for create time of the binary, (c) `cmdline` in memory if image present, (d) YARA over the binary | this skill + `memory-analysis` + `yara-hunting` |
| New 7045 service install | (a) `Services` registry tree (RECmd), (b) hash + YARA the service binary, (c) Prefetch for service binary, (d) 4624 around install time | this skill + `yara-hunting` |
| New scheduled task (4698) | (a) read XML in `Tasks\` for action + trigger, (b) hash + YARA action binary, (c) Prefetch for action binary, (d) creator account from event payload | this skill + `yara-hunting` |
| 4624 logon from suspicious IP / type 9 / type 10 | (a) RDP 1149 for source IP, (b) what executed within 5 min on this host, (c) outbound 4624 from same account elsewhere, (d) memory `netscan` if image | this skill + `plaso-timeline --slice` + `memory-analysis` |
| RBCmd `$I` showing recent deletion | (a) `$J` around deletion UTC for the process that did it (Sysmon 23 if available), (b) carve `$R` content if needed, (c) what the user did just before (UserAssist / RecentDocs) | `sleuthkit` + this skill |
| USBSTOR new device | (a) MountedDevices for drive letter, (b) MountPoints2 under each NTUSER for which user mounted it, (c) LNK files referencing that volume serial, (d) `$J` for files copied to/from the drive letter | this skill |
| 1102 / 104 (log clear) | (a) 4720/4724/4728 around same time (account changes pre-clear), (b) what was running then (memory if image), (c) Prefetch for `wevtutil`/`PowerShell` | this skill + `memory-analysis` |
| Defender 5001 (real-time off) | (a) what executed in the next 60 minutes (Prefetch / Amcache / 4688), (b) Defender 1116/1117 immediately prior (was a detection being suppressed?), (c) PowerShell 4104 for `Set-MpPreference` | this skill |
| Suspicious LNK with non-local volume serial | USBSTOR / MountedDevices for that serial → who plugged what in when | this skill |
| Browser download of executable | hash + YARA → Amcache/Prefetch for execution → SRUM for network volumes after | this skill + `yara-hunting` |
| Indicator string (mutex, named pipe, URL, SHA) | Build YARA, sweep `./exports/files/` and memory image | `yara-hunting` |

## Notes

- **Run `dfir-bootstrap/preflight.sh` first.** EZ Tools are NOT guaranteed to be
  installed — `/opt/zimmermantools/` is a manual install and is absent on minimal
  SIFT deployments. Do not attempt `dotnet /opt/zimmermantools/*.dll` blindly.
- **Fallback parsers live in `.claude/skills/dfir-bootstrap/parsers/`.** Use them
  when preflight reports EZ Tools MISSING. They are stdlib-only, no pip required.
- Extract artifacts from the disk image first (see sleuthkit SKILL.md) before parsing
- Cross-reference Autorunsc findings with Prefetch, Amcache, and memory process lists
- A file in Shimcache but absent from the filesystem likely indicates deleted malware
- EZ Tools output Windows-style paths in CSVs — use as pivot points, no need to convert
- RECmd Kroll_Batch.reb covers most common registry forensics in a single pass
- SRUM is highly valuable: confirms execution AND data volumes transferred (C2 exfil)
- $UsnJrnl is the best source for file system activity after an event — predates Prefetch
