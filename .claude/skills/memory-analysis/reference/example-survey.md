<!--
  Example survey — memory domain.
  Synthetic case for reference only. Use as a model when instantiating
  `.claude/skills/dfir-discipline/templates/survey-template.md` for a
  real (evidence × memory) pair. This file lints clean against
  `.claude/skills/dfir-bootstrap/lint-survey.sh`.
-->

# Header

- **Case ID:** EXAMPLE-MEM-2026-03
- **Evidence ID:** EV03
- **Evidence sha256:** a14d2e9b6c8f0712304a5b6c7d8e9f001112223344556677889900aabbccddee
- **Domain:** memory
- **Surveyor agent version:** dfir-surveyor / discipline_v2_loaded
- **UTC timestamp:** 2026-04-26 14:25:03 UTC

## Tools run

- `windows.info` -> `python3 /opt/volatility3/vol.py -f ./evidence/JANE-WIN10-DESKTOP.mem windows.info` -> exit 0 -> `./analysis/memory/windows.info.txt`
- `windows.malware.psxview.PsXView` -> `python3 /opt/volatility3/vol.py -f ./evidence/JANE-WIN10-DESKTOP.mem windows.malware.psxview.PsXView -r csv` -> exit 0 -> `./analysis/memory/psxview.csv`
- `windows.pstree` -> `python3 /opt/volatility3/vol.py -f ./evidence/JANE-WIN10-DESKTOP.mem windows.pstree` -> exit 0 -> `./analysis/memory/pstree.txt`
- `windows.cmdline` -> `python3 /opt/volatility3/vol.py -f ./evidence/JANE-WIN10-DESKTOP.mem windows.cmdline` -> exit 0 -> `./analysis/memory/cmdline.txt`
- `windows.netscan` -> `python3 /opt/volatility3/vol.py -f ./evidence/JANE-WIN10-DESKTOP.mem windows.netscan` -> exit 0 -> `./analysis/memory/netscan.txt`
- `windows.malfind` -> `python3 /opt/volatility3/vol.py -f ./evidence/JANE-WIN10-DESKTOP.mem windows.malfind` -> exit 0 -> `./analysis/memory/malfind.txt`
- `Memory Baseliner (proc)` -> `python3 /opt/volatility3/baseline.py -proc -f ./evidence/JANE-WIN10-DESKTOP.mem --loadbaseline ./baselines/win10_19045_clean.json --jsonbaseline -o ./analysis/memory/baseliner-proc.json` -> exit 0 -> `./analysis/memory/baseliner-proc.json`

## Findings of interest

- `windows.info` resolves Win10 build 19045, KDBG at `0xfffff80356a0e2f0`; image valid. Capture timestamp `2026-04-18 12:18:42 UTC` (`./analysis/memory/windows.info.txt#L4-L18`). Lead: `L-EV03-memory-01`
- `psxview` shows PID 4488 (`updater.exe`) listed by `psscan` and `thrdproc` but absent from `pslist` and `csrss_handles` — classic hide-from-pslist pattern; parent PID 624 is `lsass.exe` which is highly anomalous (`./analysis/memory/psxview.csv#L42`). Lead: `L-EV03-memory-02`
- `windows.malfind` reports one RWX VAD inside PID 4488 with valid `MZ` header at `0x000001f3a0000000`, entropy 7.91, no on-disk file backing — strong injected-PE indicator (`./analysis/memory/malfind.txt#L88-L120`). Lead: `L-EV03-memory-03`
- `windows.netscan` shows PID 4488 has an ESTABLISHED TCP connection to `185.220.101.42:443`, owner `NT AUTHORITY\SYSTEM` — same IP as the network-forensics beacon target; pivots cleanly with the network domain (`./analysis/memory/netscan.txt#L73`). Lead: `L-EV03-memory-04`
- Memory Baseliner diff vs `win10_19045_clean.json` flags 3 unique deltas: (a) `updater.exe` PID 4488 (no baseline match), (b) `svchost.exe` PID 1972 with non-default service-host group `netsvcs+UnistackSvcGroup` (rare combination), (c) `winlogon.exe` PID 624 has a non-baseline DLL `crypto32.dll` loaded (`./analysis/memory/baseliner-proc.json#L201-L260`). Lead: `L-EV03-memory-05`

## Lead summary table

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV03-memory-01` | low  | Image is valid; no further action — baseline confirmed | (none — informational) | ~0 s |
| `L-EV03-memory-02` | high | `updater.exe` PID 4488 is hidden from `pslist` via `_EPROCESS->ActiveProcessLinks` unlink, and `lsass.exe`-as-parent points at process hollowing or token theft | `windows.privs --pid 4488` for SeDebug presence; `windows.handles --pid 4488` for unusual `lsass` handle access | ~30 s |
| `L-EV03-memory-03` | high | RWX VAD with MZ header is a reflectively-loaded payload; dump and YARA sweep against known C2 frameworks | `windows.malfind --pid 4488 --dump --dump-dir ./exports/malfind/` then `yara -s rules/cobalt_strike.yar ./exports/malfind/pid.4488.*` | ~2 min |
| `L-EV03-memory-04` | high | The :443 connection to `185.220.101.42` is the live beacon to the same C2 the network capture observes; ties memory and network into one event | `windows.handles --pid 4488 --object-types Token` for impersonation handles; cross-ref to network-forensics findings | ~1 min |
| `L-EV03-memory-05` | med  | `crypto32.dll` in `winlogon.exe` is a likely Mimikatz-style credential-access DLL injected into a privileged process | `windows.dlllist --pid 624` for full path + signing status; `windows.dumpfiles --virtaddr <crypto32 base>` then YARA against `mimikatz.yar` | ~3 min |

## Negative results

- `windows.svcscan` deltas: every service entry matches `pslist`'s parent-of-service mapping; no orphaned-service-control entries. No fileless service persistence in this image.
- `windows.modules` vs `windows.modscan` delta: zero hidden kernel drivers; rootkit at the kernel level is unlikely.
- `windows.filescan` for `*.lnk` in `\Users\jane\Desktop`: no orphan handles to deleted shortcut files; user-shortcut-pivot lead surface is empty.
- Memory Baseliner `-drv` and `-svc` runs returned identical hashes to the clean baseline — drivers and services are not part of this implant's persistence story.

## Open questions

- The `lsass.exe` parent-of-`updater.exe` relationship (PID 624 -> 4488) might be process-hollowing OR token impersonation; cheap disconfirmation is the SeDebug check in `L-EV03-memory-02`. Correlator should not declare "lsass compromise" until that lead is terminal.
- Capture timestamp 2026-04-18 12:18:42 UTC is 6 minutes after the network-side beacon onset (12:13:18 UTC); a tighter capture would have shown earlier injection — possible scope question for the next acquisition cycle.
