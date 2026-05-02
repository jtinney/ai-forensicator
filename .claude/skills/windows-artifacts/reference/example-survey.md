<!--
  Example survey — windows-artifacts domain.
  Synthetic case for reference only. Use as a model when instantiating
  `.claude/skills/dfir-discipline/templates/survey-template.md` for a
  real (evidence × windows-artifacts) pair. This file lints clean
  against `.claude/skills/dfir-bootstrap/lint-survey.sh`.
-->

# Header

- **Case ID:** EXAMPLE-WINART-2026-01
- **Evidence ID:** EV01
- **Evidence sha256:** 9f4a5b7c2d8e1f30a6b8c0d2e4f6081929384756abcdef0123456789abcdef01
- **Domain:** windows-artifacts
- **Surveyor agent version:** dfir-surveyor / discipline_v4_loaded
- **UTC timestamp:** 2026-04-26 14:08:11 UTC

## Tools run

- `PECmd` -> `dotnet /opt/zimmermantools/PECmd.dll -d ./exports/registry/Prefetch --csv ./analysis/windows-artifacts/prefetch/` -> exit 0 -> `./analysis/windows-artifacts/prefetch/PECmd_Output.csv`
- `AmcacheParser` -> `dotnet /opt/zimmermantools/AmcacheParser.dll -f ./exports/registry/Amcache.hve --csv ./analysis/windows-artifacts/` -> exit 0 -> `./analysis/windows-artifacts/Amcache_AssociatedFileEntries.csv`
- `RECmd` -> `dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn Kroll_Batch.reb -d ./exports/registry/ --csv ./analysis/windows-artifacts/hives/` -> exit 0 -> `./analysis/windows-artifacts/hives/RECmd_Batch_Kroll_Output.csv`
- `EvtxECmd` -> `dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f ./exports/evtx/Security.evtx --inc 4624,4625,4672 --maps ./EvtxMaps --csv ./analysis/windows-artifacts/evtx/` -> exit 0 -> `./analysis/windows-artifacts/evtx/Security_4624_4625_4672.csv`
- `RBCmd` -> `dotnet /opt/zimmermantools/RBCmd.dll -d ./exports/recyclebin --csv ./analysis/windows-artifacts/recyclebin/` -> exit 0 -> `./analysis/windows-artifacts/recyclebin/RBCmd_Output.csv`
- `SBECmd` -> `dotnet /opt/zimmermantools/SBECmd.dll -d ./exports/registry/users --csv ./analysis/windows-artifacts/` -> exit 0 -> `./analysis/windows-artifacts/SBECmd_BagMRU.csv`

## Findings of interest

- Prefetch shows `JANE-WIN10-DESKTOP\Downloads\update_helper.exe` first run 2026-04-18 12:03:14 UTC, eight runs total over 18 minutes; binary not in Amcache by SHA-1 — strongly suggests rapid execute-then-delete (`./analysis/windows-artifacts/prefetch/PECmd_Output.csv#L412`). Lead: `L-EV01-windows-artifacts-01`
- RECmd Run-key entry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterTask` was created 2026-04-18 12:03:09 UTC and points at `C:\Users\jane\AppData\Roaming\updater.exe` — present in registry, absent on disk per Amcache (`./analysis/windows-artifacts/hives/RECmd_Batch_Kroll_Output.csv#L88`). Lead: `L-EV01-windows-artifacts-02`
- Security.evtx has six 4625 (failed-logon) records for `administrator` from `WORKGROUP\WIN-VENDOR-LT` between 2026-04-18 11:58–12:01 UTC, then a successful 4624 type 3 from the same workstation at 12:02:47 UTC (`./analysis/windows-artifacts/evtx/Security_4624_4625_4672.csv#L23-L29`). Lead: `L-EV01-windows-artifacts-03`
- RBCmd shows two `$I` entries deleted 2026-04-18 12:21 UTC under SID `S-1-5-21-...-1001` originally pathed at `C:\Users\jane\Downloads\report_q1.zip` and `C:\Users\jane\Documents\customer_list.csv` — overlap with the failed-logon window (`./analysis/windows-artifacts/recyclebin/RBCmd_Output.csv#L4-L5`). Lead: `L-EV01-windows-artifacts-04`

## Lead summary table

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV01-windows-artifacts-01` | high | `update_helper.exe` ran 8x then was deleted; binary likely staged dropper | `MFTECmd $J` filter on `update_helper.exe` for create+delete window | ~3 min |
| `L-EV01-windows-artifacts-02` | high | Run-key persistence pointing at deleted binary indicates intended re-execution after reboot | `RECmd --kn Run` on every NTUSER.DAT + cross-ref binary path; pull from MFT slack via `MFTECmd --rs` | ~4 min |
| `L-EV01-windows-artifacts-03` | high | Failed-logon burst followed by success suggests successful credential brute / password spray against `administrator` | `EvtxECmd Security --inc 4625,4624 --sd 2026-04-18T11:55Z --ed 2026-04-18T12:05Z` for full source-IP/auth-package context | ~30 s |
| `L-EV01-windows-artifacts-04` | med  | `customer_list.csv` deletion at 12:21 UTC is exfiltration cleanup, not user housekeeping | `MFTECmd $MFT --rs` for slack copy; SrumECmd network bytes for `update_helper.exe` window | ~6 min |

## Negative results

- AppCompatCache (Shimcache) `RECmd --bn AppCompatCache_Map.reb`: `update_helper.exe` not present (likely Win10/11 Shimcache, which excludes execution metadata) — no separate cache line.
- WMI permanent subscriptions (`EvtxECmd WMI-Activity --inc 5860,5861`): no events; WMI persistence not in play.
- TerminalServices RDP logon (`Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational --inc 1149`): zero records; the successful 4624 was network logon, not interactive RDP.
- Scheduled tasks XML scan of `Windows\System32\Tasks\`: no tasks created or modified inside the 11:55–12:25 UTC window.

## Open questions

- Two scheduled-task-history events (TaskScheduler 200/201) at 12:04 UTC reference task name `\Microsoft\Windows\WindowsUpdate\Scheduled Start` — looks legitimate but timestamp coincides with the persistence write; correlation should test whether the legitimate task's launch was abused as a parent process.
- The Amcache delta between Prefetch (8 runs) and Amcache (zero hash entry) might indicate Amcache parsing was incomplete; correlator should check whether the disk image had `Amcache.hve` truncated mid-write.
