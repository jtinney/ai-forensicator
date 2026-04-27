# Skill: Unguided Forensic Triage Protocol

The orchestrator's entrypoint when the case has no specific lead — "tell me what
happened on this host." When the case *does* have a specific question, jump
straight to the matching domain skill via the **Goal → Tool routing** table
below.

## Operating philosophy

- **Best tool for the question, not the most data.** A targeted EvtxECmd `--inc`
  pass with the right Event IDs beats a 12-hour Plaso super-timeline you will
  never read. A 5-minute `psscan + cmdline` pivot beats a 90-minute
  `windows.memmap --dump` you cannot triage.
- **Cheapest signal first.** Burn cycles on artifacts that produce a yes/no
  answer fast (Prefetch, Amcache, Run keys). Reserve expensive passes
  (full-image Plaso, full memory dump, recursive YARA) for after triage points
  you somewhere.
- **Iterate.** Triage → wide → deep → pivot → repeat. Every finding spawns the
  next question. Stop when the case question is answered, not when you run out
  of artifacts.
- **Coverage discipline.** Every pivot writes a `findings.md` entry and a
  `forensic_audit.log` line. If you cannot point to the entry that justifies
  the next action, the previous action wasn't finished.

---

## Phase 0 — Preflight & scaffold (always, ~5 min)

Every case in this project lives under `./cases/<CASE_ID>/`. Create that
workspace and `cd` into it first; every `./evidence/`, `./analysis/`,
`./exports/`, `./reports/` path below is relative to it.

```bash
mkdir -p "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>/evidence"
cd "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>"
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/preflight.sh" \
    | tee ./analysis/preflight.md
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/case-init.sh" <CASE_ID>
```

Read the preflight summary. **Tier the toolbox before touching evidence:**

| Tool group | If GREEN | If RED/MISSING |
|---|---|---|
| Sleuth Kit + libewf | Use `fls`/`icat` against the E01 directly | Stop — install `sleuthkit libewf libewf-tools` (GIFT PPA) before continuing |
| EZ Tools + dotnet | Tier 1 — preferred for every Windows artifact below | Drop to Tier 2 (regipy/python-evtx) or Tier 3 (`.claude/skills/dfir-bootstrap/parsers/`) |
| Plaso | Use for super-timeline / cross-artifact merge | Use targeted EvtxECmd + RECmd + mactime instead |
| Volatility 3 | Use if a memory image is in scope | Skip the memory phase; flag it in `00_intake.md` |
| YARA | Use for IOC sweeps once you have indicators | Skip; record as a follow-up |

Record the chosen tier per domain in `./reports/00_intake.md` so the rest of
the workflow doesn't re-derive it.

---

## Phase 1 — Triage (cheap, high-signal, ~15–45 min)

Goal: find an anomaly worth chasing. Run these in order; **stop and pivot the
moment one returns a hit worth investigating**. Do not finish every step
mechanically before pivoting.

| # | Question | Best tool | Output target |
|---|---|---|---|
| 1 | What is this host? (OS build, install date, last boot, timezone, hostname) | RECmd against `SYSTEM` + `SOFTWARE` (Tier 1) or `hive_strings.py` (Tier 3) | `./analysis/windows-artifacts/findings.md` header |
| 2 | What recently *executed*? (top 50 by time) | PECmd on `Windows\Prefetch\` → sort `LastRun` desc | `./reports/prefetch_top50.csv` |
| 3 | What was *recently installed* or first-seen? | AmcacheParser → sort `FirstRunTime` desc | `./reports/amcache_recent.csv` |
| 4 | Who logged in interactively / over the network in the last 14 days? | EvtxECmd `Security.evtx --inc 4624,4625,4672,4648 --sd <window>` | `./analysis/windows-artifacts/evtx/logons.csv` |
| 5 | Was Defender disabled / log cleared / shadow copies removed? | EvtxECmd `--inc 1102,104,1116,5001 --maps <maps>` over `Security` + `System` + `Defender` channels | `./analysis/windows-artifacts/evtx/tamper.csv` |
| 6 | What persistence exists right now? | RECmd Kroll batch (Run/RunOnce/Services) + `Windows\System32\Tasks\` listing | `./analysis/windows-artifacts/persistence.csv` |
| 7 | (If memory image available) What was running at capture? | `vol windows.psscan` + `vol windows.netscan` | `./analysis/memory/{psscan,netscan}.txt` |

Anomaly examples that should immediately pivot to Phase 3:

- Prefetch entry for `cmd.exe`, `powershell.exe`, `rundll32.exe`, `mshta.exe`,
  `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe` running from `\Users\`,
  `\Temp\`, `\AppData\`, `\ProgramData\` → **execution via LOLBin**
- Amcache first-seen binary inside an admin window → **fresh implant**
- 4624 LogonType 3/10 from a non-corporate IP → **remote access**
- 4624 Type 9 (NewCredentials) → **runas / pass-the-hash indicator**
- 1102 Security log cleared / 104 System log cleared → **counter-forensics**
- New service, scheduled task, or Run key created in last 30 days → **persistence**
- Defender 5001 (real-time protection disabled) → **AV tampering**

If Phase 1 returns nothing actionable → Phase 2.

---

## Phase 2 — Wide pass (hours, build coverage)

Run when triage came up clean and the case still demands an answer. Spend the
budget here in this order, stopping if any pass surfaces a lead.

1. **Targeted Plaso** — `--parsers winevtx,winreg,prefetch,amcache,recycle_bin_*,mft`
   over the incident window only. Avoid `win10` full preset on the first pass.
2. **Filesystem timeline** — `fls -r -m / <image>.E01 > bodyfile` →
   `mactime -y -z UTC` filtered to the incident window.
3. **All Security + PowerShell + Sysmon EVTX → CSV** with EvtxECmd `-d` against
   the exported `winevt\Logs\` directory.
4. **Memory enumeration** (if image present): `psscan`, `pstree`, `cmdline`,
   `netscan`, `malfind`, `svcscan` — write each to `./analysis/memory/`.
5. **Browser history** (if user-system): `SQLECmd -d ./exports/browser/` for
   Chrome/Edge/Firefox profile dirs.
6. **YARA sweep** of `./exports/files/` once you have at least one IOC family
   (hash, mutex, string, named pipe).

Each pass writes a `findings.md` entry even if it produced "no hits" —
"absence" is also a finding.

---

## Phase 3 — Deep dive (focused, narrow scope)

Use the goal-driven routing tables below. Pick the *question*, then the tool,
not the other way around.

### Execution evidence — "Did `<binary>` run on this host? When?"

| Priority | Tool | Why |
|---|---|---|
| 1 | **PECmd** (Prefetch) | Confirms execution + last 8 run times + DLLs/files referenced. Disabled on Server, but otherwise authoritative. |
| 2 | **AmcacheParser** | Confirms execution + SHA-1 + first-run time. Survives binary deletion. |
| 3 | **AppCompatCacheParser** (Shimcache) | Confirms file *existed*; Win8+ does NOT confirm execution. Use as corroboration only. |
| 4 | **RECmd** → `BAM\State\UserSettings\<SID>` | Last execution per user (Win10 ≤ 1809). |
| 5 | **SrumECmd** | Per-app network bytes + CPU time + duration. Confirms execution AND C2 volumes. |
| 6 | **RECmd** → `UserAssist` | GUI-launched programs only (Explorer double-click). |
| 7 | **JLECmd / LECmd** | Recent file opens, even if target deleted. |

**Rule:** never claim execution from Shimcache alone on Win8+.

### Logon / authentication — "Who accessed this host? How?"

| Priority | Tool / source | Why |
|---|---|---|
| 1 | EvtxECmd `Security --inc 4624,4625,4634,4647,4672,4648,4776,4768,4769` | Authoritative logon record. LogonType is the differentiator. |
| 2 | EvtxECmd `TerminalServices-RemoteConnectionManager%4Operational --inc 1149` | Source IP for RDP — Security 4624 only has the workstation name. |
| 3 | EvtxECmd `TerminalServices-LocalSessionManager%4Operational --inc 21,22,23,24,25` | Session connect/disconnect/reconnect timeline. |
| 4 | RECmd → `SAM` hive | Local accounts, last logon, password hash age. |
| 5 | RECmd → `SYSTEM\...\Lsa\` | Cached creds count, restricted admin mode. |

LogonType cheat:
| Type | Meaning | What to chase |
|---|---|---|
| 2 | Interactive (console) | Physical access or KVM |
| 3 | Network (SMB/file share) | Source workstation, share accessed |
| 4 | Batch (scheduled task) | The task XML in `\Windows\System32\Tasks\` |
| 5 | Service | Service binary path |
| 7 | Unlock (workstation unlocked) | Often pairs with prior 4800/4801 |
| 8 | NetworkCleartext | NTLM v1 / weak auth — investigate |
| 9 | NewCredentials (runas /netonly) | **Pass-the-hash / pass-the-ticket signature** |
| 10 | RemoteInteractive (RDP) | Pair with 1149 source IP |
| 11 | CachedInteractive | Used cached creds — host was offline-from-DC |

### USB / removable media — "What devices touched this host?"

| Priority | Source | Why |
|---|---|---|
| 1 | RECmd → `SYSTEM\CurrentControlSet\Enum\USBSTOR` | Vendor + product + serial + first/last connect |
| 2 | RECmd → `SYSTEM\MountedDevices` | Drive-letter ↔ volume GUID mapping |
| 3 | RECmd → `NTUSER.DAT\...\Explorer\MountPoints2` | Per-user mount evidence |
| 4 | `Windows\inf\setupapi.dev.log` | Driver install timestamp (first plug-in time) |
| 5 | EvtxECmd `Security --inc 6416` | Plug-and-play device announcement (audit policy must be on) |
| 6 | LECmd over `Recent\` | LNK files referencing removed drive letters |

### File deletion — "Was `<file>` deleted? When? By whom?"

| Priority | Tool | Why |
|---|---|---|
| 1 | RBCmd over `\$Recycle.Bin\<SID>\$I*` | If recycled: original path + size + deletion UTC + which SID |
| 2 | MFTECmd `$J` (UsnJrnl) | Every create/delete/rename — survives recycle-bin emptying |
| 3 | MFTECmd `$MFT --rs` | Slack-recovered MFT entries — names of deleted files no longer in `$J` |
| 4 | `bulk_extractor` / `photorec` over unallocated | Carve content if MFT entry overwritten |

### Persistence — "How does the attacker stay resident?"

Sweep all of these — persistence is rarely in one location:

| Source | Coverage |
|---|---|
| RECmd Kroll batch | Run/RunOnce, Image File Execution Options, AppInit_DLLs, AppCertDlls, Winlogon, Userinit, ScreenSaver |
| `Windows\System32\Tasks\` (XML) + Task Scheduler EVTX (106/200/201) | Scheduled tasks |
| RECmd → `SYSTEM\...\Services` | New services since baseline |
| EvtxECmd `System --inc 7045` | Service installs |
| Sysmon ID 12/13/14 (if Sysmon present) | Registry persistence in real time |
| EvtxECmd `WMI-Activity --inc 5860,5861` | WMI event subscriptions (fileless) |
| Autorunsc CSV (if collected live) | Comprehensive ASEP enumeration |

### Network — "What did this host talk to?"

| Priority | Tool | Why |
|---|---|---|
| 1 | `vol windows.netscan` | Memory: closed + active + listening sockets at capture |
| 2 | EvtxECmd Sysmon `--inc 3` | Per-connection process attribution (if Sysmon installed) |
| 3 | EvtxECmd `DNS-Client/Operational --inc 3008` | DNS queries (if turned on) |
| 4 | SRUM `SrumECmd` | Per-app bytes sent/received with timestamps |
| 5 | Browser history via SQLECmd | User-driven HTTP/HTTPS |
| 6 | `bulk_extractor -e net -e url -e domain -e email` over image | Carved indicators in slack/unallocated |

### Network — "What was on the wire?"

| Question | Best tool | Why |
|---|---|---|
| Capture metadata (time range, count, drops, link layer) | `capinfos <pcap>` | Cheapest possible read; sets the time window for everything else |
| Top talkers by bytes | `tshark -q -z conv,ip -r <pcap>` | One command; sortable; no Zeek dependency |
| DNS queries (what was looked up) | `tshark -r <pcap> -Y dns -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.a` | Fastest L7 visibility; works even when SNI is the only L7 field for HTTPS |
| TLS SNI / JA3 (what was contacted over HTTPS) | `tshark -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja3` | The only L7-adjacent signal inside encrypted traffic |
| HTTP request URIs / Host / UA | `tshark -Y http.request -T fields -e http.host -e http.request.uri -e http.user_agent` | Full L7 for cleartext HTTP |
| Structured cross-protocol logs | `zeek -C -r <pcap>` then `zeek-cut` | Produces conn.log / dns.log / http.log / ssl.log / files.log in one pass |
| Signature-based IDS sweep | `suricata -r <pcap> -k none -l ./analysis/network/suricata/` | ET Open + custom rules; eve.json is the triage source |
| Beaconing / C2 detection | `python3 .claude/skills/network-forensics/parsers/conn_beacon.py ./analysis/network/zeek/conn.log` | Stdlib jitter check; ranks low-jitter, high-count flows |
| File extraction (HTTP / SMB / SMTP / FTP) | `tshark --export-objects http,./exports/network/http_objects/` | One protocol per flag; preserves filenames where present |
| Single TCP stream as raw bytes | `tshark -Y "tcp.stream eq <N>" -w stream-<N>.pcap` | Cheapest way to isolate one conversation |
| Fallback when tshark/Zeek/Suricata absent | `python3 .claude/skills/network-forensics/parsers/{pcap_summary,zeek_triage,suricata_eve}.py` | Stdlib triage parsers — top-talkers, DNS qnames, alerts |

**Rule:** never claim a host beaconed to C2 from `tshark`/Zeek alone — confirm
with JA3/SNI fingerprint match AND host-side process attribution (Sysmon ID 3
or memory `windows.netscan`).

### Memory triage — "What was alive at capture?"

| Question | Plugin |
|---|---|
| What processes (incl. hidden/exited)? | `windows.psscan` (compare to `pslist` for hidden) |
| Parent-child anomalies? | `windows.pstree` |
| Command lines / args? | `windows.cmdline` |
| Network at capture? | `windows.netscan` |
| Injected code? | `windows.malfind` (then `--dump`) |
| Loaded drivers? | `windows.modules` vs `windows.modscan` (delta = hidden) |
| Services? | `windows.svcscan` |
| Recent registry writes? | `windows.registry.printkey` for Run/Services |

---

## Phase 4 — Pivot wide

Every finding has a follow-on. Don't stop at the first hit.

| If you found … | Pivot to … | Skill |
|---|---|---|
| A suspicious binary path | (a) hash for VT/YARA, (b) `Prefetch`+`Amcache` for execution, (c) `$J` for create time, (d) parent in `pstree` | `windows-artifacts` + `memory-analysis` + `sleuthkit` |
| A suspicious logon (4624/4648) | (a) source IP geolocation, (b) other 4624s from same IP, (c) RDP 1149 / SMB 5145, (d) what executed within 5 min after | `windows-artifacts` + `plaso-timeline --slice` |
| A persistence entry | (a) creator account, (b) creation time vs first execution, (c) service binary hash + YARA, (d) related new files in same window, (e) Sigma `service_install` rules across the host's EVTX | `windows-artifacts` + `yara-hunting` + `sigma-hunting` |
| Suspicious EVTX event ID / pattern (4624 anomaly, 4688 LOLBin, 7045 service install, 5145 share access) | (a) Sigma rule pack against the EVTX corpus, (b) cross-host sweep with same rule, (c) parent-process pivot, (d) source-WorkstationName pivot | `sigma-hunting` + `windows-artifacts` |
| Defender disabled / log cleared | (a) who/when (4720, 1102, 4719), (b) what executed *immediately after*, (c) is the policy still tampered now? | `windows-artifacts` |
| Suspicious memory region (malfind) | (a) dump it, (b) strings + YARA, (c) parent process + cmdline, (d) on-disk backing file (or absence) | `memory-analysis` + `yara-hunting` |
| A deleted user file | (a) `$I` for original path/SID, (b) `$J` for the delete event, (c) carve `$R` if present, (d) what process did it (Sysmon 23, prefetch around delete time) | `sleuthkit` + `windows-artifacts` |
| C2-looking outbound | (a) process attribution (Sysmon 3 / netscan), (b) DNS resolution, (c) prior 4624 / parent of process, (d) SRUM bytes total, (e) pcap if available — JA3/SNI + cadence | `windows-artifacts` + `memory-analysis` + `network-forensics` |
| Beaconing candidate (low jitter, repeated outbound) | (a) confirm via tshark cadence, (b) JA3 + SNI for the flow, (c) host process attribution (Sysmon 3 / memory netscan), (d) timeline-slice host activity at the same intervals | `network-forensics` + `memory-analysis` + `plaso-timeline` |
| Suspicious DNS qname in pcap | (a) DNS-Client EVTX 3008 on host, (b) memory DNS cache, (c) browser history if userland, (d) YARA the qname literal across disk + memory | `network-forensics` + `windows-artifacts` + `memory-analysis` + `yara-hunting` |
| File carved from pcap (HTTP / SMB / SMTP / FTP) | (a) hash + YARA, (b) cross-reference to host filesystem (was it written?), (c) `$J` for create time, (d) Prefetch/Amcache for execution | `yara-hunting` + `sleuthkit` + `windows-artifacts` |
| Suricata alert hit | (a) confirm payload bytes match signature with `tshark -Y` on the flow, (b) extract any L7 indicators (URL, host, UA), (c) build YARA, (d) sweep host evidence | `network-forensics` + `yara-hunting` + `windows-artifacts` |
| USB device connected | (a) what was copied (LNK files, $J, RecentDocs, JumpLists), (b) RDP file copy 1149, (c) browser uploads in same window | `windows-artifacts` + `plaso-timeline` |

---

## Common incident-type checklists

When the case prompt names an incident type, jump straight to the matching
checklist. These are tuned for high-yield artifacts only.

### Suspected ransomware
1. Mass file modification window (`$J` create/rename rate spike)
2. Ransom note name (filescan + filesystem search)
3. `vssadmin delete shadows` / `wbadmin delete catalog` (Security 4688 / PowerShell 4104 / cmdline plugin)
4. Defender disable (5001), log clear (1102/104)
5. Likely entry vector: RDP 1149 + 4624 Type 10, or phishing (browser history + email artifacts)
6. Lateral spread: 4624 Type 3 from this host *outbound*, SMB 5145

### Suspected credential theft
1. lsass access — Sysmon 10 (target=lsass), 4663 with handle to lsass
2. comsvcs.dll usage — Prefetch, cmdline, 4688
3. Mimikatz / lsadump artifacts via YARA
4. NTDS.dit copy attempts (`vssadmin create shadow` then file copy)
5. SAM/SYSTEM hive copy attempts (Security 4663 on hive paths)
6. New 4624 Type 9 (NewCredentials) — pth/ptt indicator
7. Kerberoasting — 4769 with RC4 ticket encryption

### Suspected lateral movement (this host as source)
1. 4648 (explicit creds) outbound — destination + target user
2. Sysmon 1 + cmdline for PsExec / wmic / Invoke-Command / SchTasks /S
3. Prefetch for `psexec.exe`, `wmic.exe`, `winrs.exe`, `paexec`, `ntdsutil`
4. RDP 1024 / outbound 3389 — TerminalServices-Client%4Operational

### Suspected lateral movement (this host as target)
1. 4624 Type 3 (network) and Type 10 (RDP) inbound — source IP/workstation
2. New 7045 service install in same window (PsExec signature: `PSEXESVC`)
3. New scheduled task (4698) created remotely
4. Files created in `ADMIN$` / `C$` / IPC paths via `$J`

### Suspected data exfil
1. SRUM — top apps by bytes sent over incident window
2. Browser history — large file uploads (Drive, Dropbox, anonfiles, transfer.sh)
3. RDP 1149 + clipboard / drive redirection events
4. USB plug-in events + LNK files referencing removed letters
5. `$J` for read-then-modify of sensitive paths (HR, finance, IP)

### Suspected insider threat
1. UserAssist + RecentDocs + JumpLists for the suspect SID
2. Browser history during off-hours
3. USB activity for that user (USBSTOR + MountPoints2 under their NTUSER)
4. File copies to USB / cloud (`$J` + browser + SRUM)
5. Recycle Bin contents for the user (`$I` files under their SID)
6. Email artifacts (Outlook OST/PST, webmail browser cache)

---

## Stop conditions

Stop the loop when **any** of these is true:

- The case question is answered (you can write a one-paragraph narrative with
  artifact citations)
- Every actionable lead has been chased to a definitive yes/no/unknown
- You hit the limit of available evidence (e.g., no memory image, log roll-over)
  — document the gap in `./reports/00_intake.md`

Do **not** stop because you ran out of artifacts to look at. Forensic coverage
is finite; the question is whether you answered the question.

---

## Output discipline (mirrors every other skill)

- Each phase's actions go to `./analysis/forensic_audit.log` via
  `bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next>"`
- Each pivot writes a finding to `./analysis/<domain>/findings.md`
- Headline changes update `./reports/00_intake.md`
- Final narrative goes to `./reports/<NN>_<topic>.md`

If a phase produced no `findings.md` entries, that phase isn't done — backfill
before moving on, even if the entry is "Phase 1 triage complete; no anomalies
in items 1–6, see audit log."
