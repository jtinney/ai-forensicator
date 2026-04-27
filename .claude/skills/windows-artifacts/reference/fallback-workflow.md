# Windows Artifacts — Tier 2/3 Fallback Workflow

Use these when preflight reports `EZ Tools root: MISSING`. Always append a
`./analysis/windows-artifacts/findings.md` entry after each pivot so the
Analysis Discipline contract is honored even on the fallback path.

## Extract hives + artifacts first (TSK-direct, no mount)

```bash
# Use fls on the E01 directly — no ewfmount needed
fls -r -o <offset> /path/to/image.E01 > ./analysis/filesystem/fls.txt

# Pull inode numbers for config hives from fls output
grep -iE "config/(SYSTEM|SOFTWARE|SECURITY|SAM)$" ./analysis/filesystem/fls.txt

# Extract each hive by inode to ./analysis/windows-artifacts/hives/
icat -o <offset> /path/to/image.E01 <inode> \
  > ./analysis/windows-artifacts/hives/SYSTEM
```

Same pattern works for `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`,
`Windows/Prefetch/*.pf`, `Windows/System32/winevt/Logs/*.evtx`, and the
`$Recycle.Bin` `$I`/`$R` pairs.

## Recycle Bin → CSV (replaces RBCmd)

```bash
python3 .claude/skills/dfir-bootstrap/parsers/rb_parse.py \
  ./analysis/windows-artifacts/recyclebin/ \
  > ./reports/recyclebin_parsed.csv
```

Output columns match what every case pivots on: `i_file, sid, version, size_bytes,
deletion_utc, original_path, source`. The SID is parsed from the enclosing
`$Recycle.Bin/S-1-5-21-...` folder when present — preserve the directory
hierarchy when extracting to keep it.

## Prefetch → CSV (replaces PECmd)

```bash
python3 .claude/skills/dfir-bootstrap/parsers/prefetch_parse.py \
  ./analysis/windows-artifacts/prefetch/ \
  > ./reports/prefetch_parsed.csv
```

Supports SCCA versions 17/23/26/30. Correct LastRunTime offsets encoded per
version — never re-derive from memory, the Win7 (v23) offset is `0x80`, not the
`0x78` documented in some older guides. MAM-compressed Win10 prefetch is detected
and skipped with a warning; use PECmd or decompress first for those.

## Registry hive string extraction (degraded replacement for RECmd)

```bash
python3 .claude/skills/dfir-bootstrap/parsers/hive_strings.py \
  ./analysis/windows-artifacts/hives/SYSTEM \
  > ./analysis/windows-artifacts/hives/SYSTEM.strings.txt

# Then grep for what you care about
grep -iE "USBSTOR#Disk|DiskPeripheral" ./analysis/windows-artifacts/hives/SYSTEM.strings.txt
grep -iE "MountedDevices|\\?{?[0-9a-f-]{32,}" ./analysis/windows-artifacts/hives/SYSTEM.strings.txt
grep -iE "TypedPaths|RecentDocs|UserAssist" ./analysis/windows-artifacts/hives/NTUSER.DAT.strings.txt
```

This is a degraded substitute — it will NOT produce FILETIMEs from cell headers,
UserAssist ROT13-decoded entries, structured shellbag output, or USBSTOR
FirstInstallDate/LastWriteTime. For those artifacts, ask the user to
`sudo apt install python3-regipy` and then use the `regipy` CLI (`regipy-dump`,
`regipy-plugin-runner`).

## EVTX → readable strings (degraded replacement for EvtxECmd)

```bash
python3 .claude/skills/dfir-bootstrap/parsers/evtx_strings.py \
  ./analysis/windows-artifacts/evtx/Security.evtx \
  --grep "4624|4634|LogonType|TargetUserName" \
  > ./analysis/windows-artifacts/evtx/Security.strings.txt
```

Triage only. This cannot reconstruct records, correlate LogonType to 4624, or
produce a structured logon timeline. When you need that, ask the user to
`sudo apt install python3-evtx` and switch to `python-evtx`'s `evtx_dump.py`,
or invoke `EvtxECmd` once EZ Tools are installed.

## Artifact-to-tool fallback matrix

| Artifact | Tier 1 (EZ Tools) | Tier 2 (Python lib) | Tier 3 (stdlib fallback) |
|---|---|---|---|
| Prefetch | PECmd | — | `dfir-bootstrap/parsers/prefetch_parse.py` |
| Recycle Bin ($I) | RBCmd | — | `dfir-bootstrap/parsers/rb_parse.py` |
| Registry hives | RECmd + batch | regipy / python-registry | `dfir-bootstrap/parsers/hive_strings.py` (degraded) |
| EVTX | EvtxECmd | python-evtx | `dfir-bootstrap/parsers/evtx_strings.py` (triage) |
| MFT | MFTECmd | analyzeMFT, pytsk3 | `fls`, `istat` via TSK — inode-level only |
| Shellbags | SBECmd | regipy-shellbags | — install Tier 1 or Tier 2 |
| Shimcache | AppCompatCacheParser | regipy-shimcache | — install Tier 1 or Tier 2 |
| Amcache | AmcacheParser | regipy amcache plugin | — install Tier 1 or Tier 2 |
| LNK | LECmd | LnkParse3 | — install Tier 1 or Tier 2 |
| Jump Lists | JLECmd | — | — install Tier 1 |
| SRUM | SrumECmd | dissect.esedb | — install Tier 1 |

Any cell without a Tier 3 option means you cannot meaningfully parse that
artifact without at least the Tier 2 library installed. Flag it in
`./reports/00_intake.md` and request the install before the case goes
courtroom-ready.
