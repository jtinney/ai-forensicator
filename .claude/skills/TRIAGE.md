# Skill: Unguided Forensic Triage Protocol

<role>
Single-context unguided triage. Use this entrypoint when ONE evidence item
has no specific lead and the operator drives the full triage → wide → deep
→ pivot loop in one Claude context. Distinct from the `dfir-triage` agent
(Phase 1 entrypoint inside ORCHESTRATE.md). When the case has a specific
question, jump straight to the matching domain skill via `CLAUDE.md`'s
Goal → Tool routing.
</role>

<inputs>
- `CASE_ID` — case identifier.
- One evidence item under `./cases/<CASE_ID>/evidence/`.
- Operator's prompt (open-ended; no pre-existing lead).
</inputs>

<rules-binding>
Binds DISCIPLINE §A (audit-log integrity), §B (headline revalidation), §F
(hypothesis-first / cheapest-disconfirmation-first), §G (scope closure), §H
(lead surface), §I (no lead un-worked), §J (intake completeness), §K
(ATT&CK tagging), §L (multi-evidence path encoding), §P-pcap, §P-diskimage,
§P-priority, §P-yara, §P-sigma. Every audit-log write goes through `audit.sh`. Every
pivot emits the marker `discipline_v4_loaded` in its action context.
</rules-binding>

## Operating philosophy

- **Best tool for the question, not the most data.** A targeted EvtxECmd `--inc` pass with the right Event IDs beats a 12-hour Plaso super-timeline no one reads. A 5-minute `psscan + cmdline` pivot beats a 90-minute `windows.memmap --dump` no one will triage.
- **Cheapest signal first.** Prefetch / Amcache / Run keys produce yes/no fast. Reserve full-image Plaso, full memory dump, recursive YARA for AFTER triage points somewhere.
- **Iterate.** Triage → wide → deep → pivot → repeat. Stop when the case question is answered, not when artifacts run out.
- **Coverage discipline.** Every pivot writes a `findings.md` entry and a `forensic_audit.log` line via `audit.sh`. When no entry justifies the next action, the previous action was not finished.

<protocol>

<step n="0" name="preflight-and-scaffold" budget="~5 min">
The case lives under `./cases/<CASE_ID>/`. Create the workspace and `cd` into
it; every `./evidence/`, `./analysis/`, `./exports/`, `./reports/` path
below is relative to it.

```bash
mkdir -p "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>/evidence"
cd "${CLAUDE_PROJECT_DIR}/cases/<CASE_ID>"
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/preflight.sh" \
    | tee ./analysis/preflight.md
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/case-init.sh" <CASE_ID>
```

Tier the toolbox per `preflight.md` BEFORE touching evidence: Sleuth Kit +
libewf, EZ Tools + dotnet, Plaso, Volatility 3, YARA. Record chosen tier
per domain in `./reports/00_intake.md`. Tool-substitution and BLOCKED-lead
rules live in DISCIPLINE §P-priority.
</step>

<step n="1" name="triage" budget="~15-45 min">
Goal: find an anomaly worth chasing. Run cheap-pass entry points; **STOP
and pivot the moment one returns a hit worth investigating** — do NOT
finish every step mechanically before pivoting.

Per-domain cheap-pass entry points (cheap-pass tables themselves live in
the domain skill):
- **Windows host** (Prefetch, Amcache, Security 4624/4625/4672/4648, log-tamper 1102/104/1116/5001, persistence Run/RunOnce/Services/Tasks) → `.claude/skills/windows-artifacts/SKILL.md` § Cheap-pass.
- **Memory** (`vol windows.psscan`, `vol windows.netscan`) → `.claude/skills/memory-analysis/SKILL.md` § Cheap-pass.
- **Filesystem / disk image** (RECmd hive headers, `fls -r -m /`) → `.claude/skills/sleuthkit/SKILL.md` § Cheap-pass.
- **PCAP / network** (`capinfos`, `tshark -q -z conv,ip`, DNS qnames, TLS SNI/JA3) → `.claude/skills/network-forensics/SKILL.md` § Cheap-pass.
- **Timeline slice** (Plaso `--parsers winevtx,winreg,prefetch,amcache,...` over the incident window only) → `.claude/skills/plaso-timeline/SKILL.md`.
- **YARA / Sigma** — held until an IOC family or rule pack is identified → `.claude/skills/yara-hunting/SKILL.md`, `.claude/skills/sigma-hunting/SKILL.md`.

Anomaly examples that immediately escalate to step 3:
- LOLBin (`cmd.exe`, `powershell.exe`, `rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`) running from `\Users\` / `\Temp\` / `\AppData\` / `\ProgramData\` — execution via LOLBin.
- Amcache first-seen binary inside admin window — fresh implant.
- 4624 LogonType 3/10 from non-corporate IP — remote access.
- 4624 Type 9 (NewCredentials) — runas / pass-the-hash indicator.
- 1102 / 104 log clear — counter-forensics.
- New service / scheduled task / Run key in last 30 days — persistence.
- Defender 5001 (real-time protection disabled) — AV tampering.

When step 1 returns nothing actionable → step 2.
</step>

<step n="2" name="wide-pass" budget="hours; build coverage">
Run when triage came up clean and the case still demands an answer. Order;
STOP the moment any pass surfaces a lead.

1. **Targeted Plaso** — `--parsers winevtx,winreg,prefetch,amcache,recycle_bin_*,mft` over the incident window only. Avoid `win10` full preset on first pass.
2. **Filesystem timeline** — `fls -r -m / <image>.E01 > bodyfile` → `mactime -y -z UTC` filtered to the window.
3. **Security + PowerShell + Sysmon EVTX → CSV** with EvtxECmd `-d` against exported `winevt\Logs\`.
4. **Memory enumeration** (when image present): `psscan`, `pstree`, `cmdline`, `netscan`, `malfind`, `svcscan` to `./analysis/memory/`.
5. **Browser history** (user-system): `SQLECmd -d ./exports/browser/` for Chrome/Edge/Firefox profile dirs.
6. **YARA sweep** of `./exports/files/` once an IOC family exists (hash, mutex, string, named pipe).

Each pass writes a `findings.md` entry even on "no hits" — absence is also a finding (§G).
</step>

<step n="3" name="deep-dive" budget="focused; narrow scope">
Pick the *question*, then the tool. Goal-driven routing tables for each
question class live in the domain skill files — do NOT duplicate them here.

- "Did `<binary>` run on this host? When?" → `windows-artifacts/SKILL.md` § Execution evidence. Authoritative rule: NEVER claim execution from Shimcache alone on Win8+.
- "Who accessed this host? How?" → `windows-artifacts/SKILL.md` § Logon / authentication (LogonType cheat sheet included).
- "What devices touched this host?" → `windows-artifacts/SKILL.md` § USB / removable media.
- "Was `<file>` deleted? When? By whom?" → `sleuthkit/SKILL.md` § File deletion (and `windows-artifacts` § Recycle Bin / `$J`).
- "How does the attacker stay resident?" → `windows-artifacts/SKILL.md` § Persistence.
- "What did this host talk to?" → `network-forensics/SKILL.md` § Host-attributed network.
- "What was on the wire?" → `network-forensics/SKILL.md` § PCAP triage. Authoritative rule: NEVER claim a host beaconed to C2 from `tshark`/Zeek alone — confirm with JA3/SNI fingerprint match AND host-side process attribution (Sysmon ID 3 or memory `windows.netscan`).
- "What was alive at capture?" → `memory-analysis/SKILL.md` § Triage plugins.

Deep-dive terminates when the question has a yes/no/unknown answer with artifact citations. Then step 4.
</step>

<step n="4" name="pivot-wide">
Every finding has a follow-on. Do NOT stop at the first hit. Pivot
catalogues live in the domain SKILL.md files; each pivot row names the
target skill. Examples: a suspicious binary path pivots to hash + YARA +
Prefetch/Amcache + `$J` + memory parent; a 4624/4648 anomaly pivots to
source-IP geo, RDP 1149, SMB 5145, execution within 5 min after; a
beaconing candidate pivots to JA3 + SNI + Sysmon 3 + timeline slice.
Re-read the domain pivot tables per pivot rather than memorising.

Each pivot writes a finding to `./analysis/<domain>/findings.md` and an
audit row via `audit.sh`. Headline changes update `./reports/00_intake.md`
per §B.
</step>

<step n="5" name="incident-type-checklists">
When the operator's prompt names an incident type, jump to the matching checklist (high-yield artifacts only):

- **Ransomware** — mass-modify `$J` window, ransom-note name, `vssadmin`/`wbadmin` shadow delete, Defender disable + log clear, entry vector (RDP 1149 + 4624 Type 10 / phishing), lateral 4624 Type 3 outbound + SMB 5145.
- **Credential theft** — lsass access (Sysmon 10, 4663), `comsvcs.dll` (Prefetch/cmdline/4688), Mimikatz/lsadump YARA, NTDS.dit copy via shadow, SAM/SYSTEM hive copy (4663), 4624 Type 9, 4769 RC4 Kerberoasting.
- **Lateral (this host as source)** — 4648 outbound, Sysmon 1 + cmdline for PsExec/wmic/Invoke-Command/SchTasks, Prefetch for `psexec.exe`/`wmic.exe`/`winrs.exe`/`paexec`/`ntdsutil`, RDP outbound 1024/3389.
- **Lateral (this host as target)** — inbound 4624 Type 3 and Type 10, new 7045 service (PsExec `PSEXESVC`), 4698 remote scheduled task, files in `ADMIN$`/`C$`/IPC via `$J`.
- **Data exfil** — SRUM top apps by bytes-sent in window, browser history for upload sites, RDP 1149 + clipboard/drive redirection, USB plug-in + LNK, `$J` read-then-modify of sensitive paths.
- **Insider threat** — UserAssist + RecentDocs + JumpLists for suspect SID, off-hours browser history, USBSTOR + MountPoints2 under that NTUSER, copies to USB/cloud (`$J` + browser + SRUM), Recycle Bin under SID, Outlook OST/PST + webmail cache.
</step>

<step n="6" name="stop-conditions">
Stop the loop when ANY of these is true:
- The case question is answered (a one-paragraph narrative with artifact citations is writeable).
- Every actionable lead has been chased to a definitive yes/no/unknown.
- The limit of available evidence has been reached (no memory image, log roll-over, etc.) — document the gap in `./reports/00_intake.md`.

Do NOT stop because artifacts ran out. Forensic coverage is finite; the
question is whether the question got answered.
</step>

</protocol>

<outputs>
- Pivot actions go to `./analysis/forensic_audit.log` via `bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next>"` (§A.1 — NEVER `>>` directly).
- Each pivot writes a finding to `./analysis/<domain>/findings.md`.
- Headline changes update `./reports/00_intake.md` (§B).
- Final narrative → `./reports/<NN>_<topic>.md`.
- Lead IDs in single-context triage use `L-TRIAGE-NN` (zero-padded, counter-scoped to this session) — distinct from the orchestrated prefixes in ORCHESTRATE.md so a later orchestrator pickup never collides.

When a phase produced no `findings.md` entries, that phase is NOT done — backfill before advancing, even when the entry is "Phase 1 triage complete; no anomalies in items 1–6, see audit log."
</outputs>

<example>
Operator: "Tell me what happened on `host-DC01`. Disk image + memory dump under `./evidence/`."

Step 0 — preflight + case-init; EZ Tools Tier 1, Volatility 3 + Plaso present.

Step 1 — Prefetch top 50 surfaces `powershell.exe` from `C:\Users\Public\Downloads\` at 2026-04-30 02:14 UTC. STOP triage; pivot.

Step 3 — Execution: Amcache first-run 02:14 SHA-1 match, 4688 cmdline corroborates. Lead `L-TRIAGE-01`: "PowerShell from non-standard path at admin window."

Step 4 — Pivot: pstree parent `wmiprvse.exe` (remote WMI); 4624 Type 3 from 192.0.2.55 (off-corp); persistence sweep returns 7045 service `WindowsHelp` at 02:16; YARA on the service binary returns Cobalt Strike beacon family. Findings cascade; one-paragraph narrative + citations in `./reports/01_cobalt_strike_intrusion.md`.

Step 6 — Question answered. Stop.
</example>
