# Process Anomaly Indicators — Reference

Use this table after Step-1 cross-source enumeration (`psxview`) and Step-2
parent-child sanity (`pstree`) flag a candidate. These are the patterns that
distinguish "ordinary Windows weirdness" from "attacker activity."

| Anomaly | What to Look For |
|---------|-----------------|
| Wrong binary path | `svchost.exe` not in `System32\`; `lsass.exe` anywhere but `System32\` |
| Wrong parent | `svchost.exe` parent ≠ `services.exe`; `lsass.exe` parent ≠ `wininit.exe` |
| `taskhostw.exe` sibling | Process launched as a scheduled task |
| `conhost.exe` child | Console I/O attached — hands-on-keyboard attacker |
| LOLBin with suspicious args | `cmd.exe`, `powershell.exe`, `net.exe`, `wmic.exe`, `mshta.exe`, `certutil.exe` |
| Orphaned process | PPID not present in process list — see `pslist_orphans.csv` |
| Very short-lived processes | Exited in < 5 seconds — atomic actions or AV termination |
| Missing image path | No on-disk backing file (DLL injection / reflective loading) |
| Unsigned kernel modules | In `modscan` but absent from `modules` — see `modscan_only.csv` |
| High privilege context | `SeDebugPrivilege` or `SeTcbPrivilege` in unexpected process |
| RWX VAD without file backing | Classic shellcode injection indicator from `malfind` |
| Cross-process handles | Process / Thread handles to OTHER processes — see `handles_<PID>_process.csv` / `_thread.csv` (`CreateRemoteThread` / injection trace) |
