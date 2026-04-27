# Velociraptor (Enterprise Endpoint Hunting) — Reference

Velociraptor is deployed on Windows endpoints in the environment under investigation.
Connect to the Velociraptor web console to run hunts across live or collected endpoints.
**It is NOT a local binary on the SIFT workstation.**

## Key Concepts
- **Artifact:** A named collection/query (e.g., `Windows.System.Pslist`)
- **Hunt:** Deploy an artifact across multiple endpoints simultaneously
- **VQL:** Velociraptor Query Language (SQL-like syntax for live system queries)

## Common Artifacts for Threat Hunting

| Artifact | Purpose |
|----------|---------|
| `Windows.System.Pslist` | Process listing |
| `Windows.Sysinternals.Autoruns` | Persistence / ASEPs |
| `Windows.Network.Netstat` | Active network connections |
| `Windows.System.TaskScheduler` | Scheduled tasks |
| `Windows.Forensics.Prefetch` | Execution evidence |
| `Windows.Forensics.Lnk` | Recent files / LNK files |
| `Windows.Forensics.SRUM` | SRUM resource usage |
| `Windows.Forensics.MFT` | MFT parsing |
| `Windows.EventLogs.EvtxHunter` | Search event logs by keyword |
| `Windows.Detection.Yara.Process` | YARA scan of process memory |
| `Windows.Detection.Yara.File` | YARA scan of files on disk |
| `Windows.Detection.Yara.NTFS` | YARA scan via raw NTFS access |

## Deploy a YARA Hunt (VQL reference)
```vql
SELECT * FROM Artifact.Windows.Detection.Yara.Process(
    YaraRule='''
rule ExampleRule {
  strings: $s = "indicator_string" nocase
  condition: $s
}
''')
```

## VQL — Quick Triage Queries

```vql
-- Find processes with no parent
SELECT Name, Pid, Ppid, Exe
FROM pslist()
WHERE NOT Ppid IN (SELECT Pid FROM pslist())

-- Find network connections to non-private IPs
SELECT Pid, FamilyString, RemoteAddr, RemotePort, Status
FROM netstat()
WHERE NOT RemoteAddr =~ "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)"

-- Hunt for scheduled tasks with suspicious paths
SELECT Name, Command, Arguments
FROM scheduledtasks()
WHERE Command =~ "(temp|appdata|\\\\users\\\\)" OR
      Arguments =~ "(powershell|cmd|wscript|mshta)"
```
