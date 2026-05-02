# Skill: Threat Hunting & IOC Sweeps (YARA / Velociraptor)

<protocol>
  <rule>Rules live at <code>/opt/yara-rules/</code>. See DISCIPLINE.md §P-yara.</rule>
  <rule>Tool order is the <code>yara-hunting</code> entry of DISCIPLINE.md §P-priority. Surveyor runs <code>yara -r /opt/yara-rules/ &lt;target&gt;</code>.</rule>
  <rule>Hits go to <code>./exports/yara_hits/</code>. Summaries to <code>./analysis/yara/</code>.</rule>
  <rule>Do not author, cache, or vendor rules inside the project workspace. Operator maintains <code>/opt/yara-rules/</code> via the SIFT install script.</rule>
</protocol>

## Use this skill when
- You have *at least one* concrete indicator (hash, mutex, named pipe, unique
  string, distinctive code pattern, registry path) and want to sweep the rest
  of the evidence for siblings
- A binary recovered from disk, memory, or carving needs malware-family
  attribution
- A finding from another skill (memory `malfind` hit, `bstrings` regex hit,
  $J-deleted file, suspicious LNK target) needs to be lifted to a reusable
  rule for cross-evidence sweep

**Don't reach for YARA when** you have no indicators yet — it's a *confirm and
expand* tool, not a discovery tool. Don't sweep the entire image with the
full ruleset on day 1; the false-positive triage will eat the case.

## Tool selection — pick by question

| Question | Best invocation | Why |
|---|---|---|
| Is this one file malicious? | `yara -s /opt/yara-rules/ <file>` | `-s` shows matched offsets — validates the rule fired on the right bytes |
| Sweep extracted files for an IOC family | `yara -r -s -p 4 /opt/yara-rules/ ./exports/files/` | `-p` parallelizes; `-s` keeps you honest |
| Sweep a memory image | `yara /opt/yara-rules/ /path/to/memory.img` | Hits include strings injected into RWX VADs that may not exist on disk |
| Sweep VAD regions of one process (no dump) | `vol windows.vadyarascan --pid <PID> --yara-rules /opt/yara-rules/<scope>/<rule>.yar` | Cheaper than `memmap --dump` then YARA |
| Sweep VAD regions of every process | `vol windows.vadyarascan --yara-rules /opt/yara-rules/<scope>/<rule>.yar` | One-shot wide scan |
| Repeated scans of large corpus | `yarac /opt/yara-rules/<scope>/<rule>.yar ./analysis/yara/<scope>.compiled` then `yara -C ./analysis/yara/<scope>.compiled <target>` | Avoids re-parsing rule source each run |
| Sweep just unallocated space | `blkls -A <image>.E01 > unalloc.raw` then `yara /opt/yara-rules/ unalloc.raw` | Carved indicators in slack |
| Tag-scoped sweep (narrow) | `yara -r -t <tag> /opt/yara-rules/ <target>` | Apply only the rules carrying TAG |
| Validate scope of a rule before sweeping | `yara -r -n /opt/yara-rules/<scope>/ /usr/bin/` | `-n` shows non-matches — confirms you're not catching the universe |

**Order conditions cheap → expensive in every rule:**
`uint16(0) == 0x5A4D` → `filesize < N` → `pe.is_pe` → string match → `math.entropy(...)`.
YARA short-circuits left-to-right; getting this wrong is the #1 cause of slow
sweeps.

## Overview
Use this skill for IOC sweeps, malware identification, and threat hunting.
YARA 4.1.0 runs locally on SIFT Linux for scanning files and memory images.
Velociraptor is an endpoint agent — hunts are deployed via its web console,
not run directly from the SIFT command line.

## Analysis Discipline

`./analysis/` is not just a bucket for raw tool output. Keep both a terse audit trail and
human-written findings as you work.

- `./analysis/forensic_audit.log` — the action that triggers the entry must append its own UTC
  line describing that exact action, the tool or artifact reviewed, the result, and why it
  matters.
- `./analysis/yara/findings.md` — append short notes with the artifact reviewed, finding,
  interpretation, and next pivot.
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

## Tool Reference

| Tool | Location | Platform |
|------|----------|----------|
| `yara` | `/usr/local/bin/yara` (v4.1.0) | SIFT Linux — local file/memory scanning |
| `yarac` | `/usr/local/bin/yarac` | SIFT Linux — rule compiler |
| Velociraptor | Enterprise endpoint deployment | Web console — not a local SIFT binary |

---

## YARA Rule Structure

```yara
rule RuleName
{
    meta:
        description = "Detects X"
        author      = "Analyst Name"
        date        = "YYYY-MM-DD"
        hash        = "SHA256 of reference sample"
        reference   = "Case number or source"

    strings:
        // Hex patterns (use ?? for wildcard bytes)
        $mz     = { 4D 5A }
        $hex1   = { 48 8B ?? 48 89 ?? ?? 48 8B ?? }   // wildcarded opcodes

        // String patterns
        $str1   = "suspicious_string" nocase
        $str2   = "another_string"    wide ascii        // scan both encodings
        $str3   = "C:\\Windows\\Temp\\" wide nocase

        // Regex
        $re1    = /net\s+use\s+[A-Z]:\s+\\\\/
        $re2    = /[A-Za-z0-9+\/]{40,}={0,2}/          // base64 blob

    condition:
        uint16(0) == 0x5A4D and   // MZ header
        filesize < 5MB and
        any of them
}
```

---

## YARA Module Imports

### PE Module (Windows Executables)

```yara
import "pe"

rule Suspicious_PE
{
    meta:
        description = "PE with high section entropy and no exports"

    condition:
        pe.is_pe and
        pe.number_of_sections > 3 and
        pe.number_of_exports == 0 and
        // Check for packed/encrypted section (entropy > 7.0)
        for any section in pe.sections : (
            section.name != ".rsrc" and
            math.entropy(section.raw_offset, section.raw_size) > 7.0
        )
}
```

**Useful PE module fields:**
| Field | Description |
|-------|-------------|
| `pe.is_pe` | True if valid PE header |
| `pe.imphash()` | Import hash (pivots to related malware families) |
| `pe.number_of_imports` | Import count |
| `pe.number_of_exports` | Export count |
| `pe.number_of_sections` | Section count |
| `pe.timestamp` | Compile timestamp (can be forged) |
| `pe.imports("kernel32.dll", "VirtualAlloc")` | Specific import check |
| `pe.exports("DllEntryPoint")` | Specific export check |
| `pe.sections[i].name` | Section name (`.text`, `.data`, etc.) |
| `pe.sections[i].characteristics` | Section permissions flags |
| `pe.version_info["CompanyName"]` | Version info strings |

### Math Module (Entropy Detection)

```yara
import "math"

rule High_Entropy_File
{
    meta:
        description = "File with high overall entropy — likely packed or encrypted"

    condition:
        math.entropy(0, filesize) > 7.2
}

rule High_Entropy_Section_PE
{
    meta:
        description = "PE with a high-entropy section (packed/obfuscated)"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            math.entropy(pe.sections[i].raw_offset, pe.sections[i].raw_size) > 7.0
        )
}
```

### Hash Module (Hash-Based IOC Matching)

```yara
import "hash"

rule Known_Bad_Hash
{
    meta:
        description = "Match by MD5 hash of known malware sample"

    condition:
        // hash.md5(offset, size) — use 0, filesize for whole file
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" or
        hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

## YARA Scanning

### Scan a Single File
```bash
yara -r /opt/yara-rules/ /path/to/file
```

### Scan a Directory Recursively
```bash
yara -r /opt/yara-rules/ /mnt/windows_mount/Windows/System32/
```

### Scan a Memory Image
```bash
yara -r /opt/yara-rules/ /path/to/memory.img
```

### Scan Exported Files from Evidence
```bash
yara -r /opt/yara-rules/ ./exports/files/
```

### Scan with Match Detail (Show Matching Strings)
```bash
yara -r -s /opt/yara-rules/ ./exports/files/ 2>/dev/null | tee ./exports/yara_hits/yara-EV01.txt
```

### Scan with Metadata Output
```bash
yara -r -m /opt/yara-rules/ /mnt/windows_mount/ 2>/dev/null
```

### Useful Flags
| Flag | Description |
|------|-------------|
| `-r` | Recursive directory scan |
| `-s` | Print matching strings (with offset) |
| `-m` | Print rule metadata |
| `-e` / `--print-namespace` | Print rule namespace in output |
| `-n` | Print non-matching rules (invert — for testing) |
| `-f` | Fast scan mode (first match only per rule) |
| `-p N` | Use N threads for parallel scanning |
| `--timeout N` | Skip file after N seconds |
| `-t TAG` / `--tag=TAG` | Only apply rules tagged with TAG |
| `--scan-list` | Input is a text file listing paths to scan (one per line) |
| `-N` / `--no-follow-symlinks` | Do not follow symlinks (prevents loops in recursive scans) |
| `--max-rules=NUMBER` | Abort scan after NUMBER rules match |
| `-x <module>=<file>` | Load external module |
| `-d <var>=<val>` | Define external variable |

---

## Rule Compilation (Repeated Large-Scale Scanning)

```bash
# Compile rules to binary for faster re-use (avoids re-parsing .yar each run).
# Source rules read from /opt/yara-rules/; compiled output is a per-case
# byte artifact tracked in analysis/yara/.
yarac /opt/yara-rules/<scope>/<rule>.yar ./analysis/yara/<scope>.compiled

# Scan using compiled rules
yara -C ./analysis/yara/<scope>.compiled /target/path/
```

---

## Performance Best Practices

**Condition ordering matters — YARA evaluates left to right and short-circuits:**
```yara
condition:
    // Put cheap, specific checks FIRST to eliminate non-matches early
    uint16(0) == 0x5A4D and    // 1. Fast: 2-byte read at offset 0
    filesize < 10MB and         // 2. Fast: metadata check
    pe.is_pe and                // 3. Medium: PE structure validation
    $str1 and                   // 4. Medium: string match
    math.entropy(...) > 7.0    // 5. Expensive: full entropy scan — LAST
```

**Other tips:**
- Use `filesize < X` as the first condition to skip large files when hunting small malware
- Use `pe.is_pe` to scope rules to PE files only instead of scanning everything
- Compile rules once with `yarac` before scanning large directories
- Use `-f` (fast mode) for initial triage; rescan hits with `-s` for details
- Use `-p 4` or more threads on multi-core SIFT for directory scans

---

## Rule enumeration gate (run BEFORE any scan)

Before any `yara` invocation, enumerate the rule corpus at `/opt/yara-rules/`
so the audit trail records exactly what was available at scan time. If the
directory is missing or empty, preflight reports `yara-hunting: RED/YELLOW`;
the surveyor BLOCKS its lead per §P-priority with
`suggested-fix=install-package; tool-needed=/opt/yara-rules`.

```bash
mkdir -p ./analysis/yara

{
    echo "# YARA rule enumeration — $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo "## corpus root: /opt/yara-rules/"
    if [[ -d /opt/yara-rules ]]; then
        find /opt/yara-rules -type f \( -name '*.yar' -o -name '*.yara' \) \
            | sort
        echo
        echo "rule files: $(find /opt/yara-rules -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l)"
    else
        echo "(missing — preflight RED)"
    fi
} > ./analysis/yara/rules-enumerated.txt

# Validate the rule library before scanning. Errors here mean the rule set
# itself is broken; refuse to scan with a broken library.
bash .claude/skills/yara-hunting/validate-rules.sh \
    > ./analysis/yara/validate-rules.txt 2>&1 \
    || echo "WARN: validate-rules.sh reported errors — see analysis/yara/validate-rules.txt"

bash .claude/skills/dfir-bootstrap/audit.sh \
    "yara-rule-enumeration /opt/yara-rules/" \
    "enumerated $(wc -l < ./analysis/yara/rules-enumerated.txt) lines — see analysis/yara/rules-enumerated.txt" \
    "scope per evidence question; compile via yarac for repeat scans"
```

`rules-enumerated.txt` is in the baseline-artifact contract for this skill
(see § "Required baseline artifacts" below). Skipping the gate causes
`baseline-check.sh yara` to flag a missing artifact and the orchestrator
to emit `L-BASELINE-yara-NN`.

---

## IOC Sweep Workflow

1. **Build IOC list** from confirmed findings (file hashes, strings, IPs, domains, paths, mutex names)
2. **Author rules** targeting each IOC family in `/opt/yara-rules/<scope>/` (operator action — out-of-band)
3. **Test rules for false positives** against `/usr/bin/` or another known-clean target first
4. **Scan mounted evidence** — `yara -r -s /opt/yara-rules/ /mnt/windows_mount/`
5. **Scan memory image** — `yara -r /opt/yara-rules/ /path/to/memory.img`
6. **Scan extracted files** — `yara -r /opt/yara-rules/ ./exports/files/`
7. **Cross-reference hits** with filesystem timeline and process artifacts
8. **Export findings** to `./exports/yara_hits/yara-EV<NN>.txt`

### False Positive Testing

```bash
# Test rules against a known-clean directory before sweeping evidence
yara -r /opt/yara-rules/<scope>/ /usr/bin/ 2>/dev/null

# Use -n to see which rules did NOT match (verify scope coverage)
yara -r -n /opt/yara-rules/<scope>/ /path/to/sample/

# Test a single rule in isolation
yara -r /opt/yara-rules/<scope>/<single_rule>.yar /path/to/target/
```

---

## Rule library layout

```
/opt/yara-rules/                   ← canonical rule corpus (operator-maintained, populated by SIFT install)
└── <scope>/<rule>.yar             ← operator-organized subdirs (by tactic, family, or source)
```

**Per-case output (follows the layer model in DISCIPLINE.md Rule A):**
```
./analysis/yara/                         ← per-case scan summaries + compiled rulesets (layer 3)
./analysis/yara/<scope>.compiled         ← yarac-compiled binary (per-case build of /opt/yara-rules/)
./analysis/yara/yara-hits-EV01.txt       ← scan hit summary
./analysis/yara/rules-enumerated.txt     ← required baseline (see § gate)
./exports/yara_hits/yara-EV01.txt        ← scan hit byte extract (layer 4)
./exports/yara_hits/EV01/                ← per-rule byte trees (multi-evidence)
./reports/                               ← finalized IOC sweep reports
```

Multi-evidence cases follow Rule L: hit summaries are `yara-hits-EV02.txt`
sibling files; byte-extract subdirs are `exports/yara_hits/EV01/`,
`exports/yara_hits/EV02/`.

---

## Rule conventions

See `reference/rule-conventions.md` for the full convention: required and
recommended `meta` keys, tag vocabulary (Scope / Format / Stage / Severity /
Family), naming, performance contract (cheap→expensive condition ordering),
false-positive contract. The operator enforces these at the `/opt/yara-rules/`
boundary; `validate-rules.sh` runs against `/opt/yara-rules/` to confirm.

---

## Rule validation (`validate-rules.sh`)

Default target is `/opt/yara-rules/`.

```bash
# Validate every rule under /opt/yara-rules/
bash .claude/skills/yara-hunting/validate-rules.sh

# Validate a specific path (e.g. a subset of /opt/yara-rules/)
bash .claude/skills/yara-hunting/validate-rules.sh /opt/yara-rules/malware/

# Strict mode — also requires `reference` and `mitre`
bash .claude/skills/yara-hunting/validate-rules.sh --strict

# Strict + FP-test against /usr/bin
bash .claude/skills/yara-hunting/validate-rules.sh --strict --fp-test
```

The script:

1. Runs `yarac` on each file (full syntax + semantic check).
2. Parses every `rule X { meta: ... }` block and verifies the required keys
   are present, `date` matches `YYYY-MM-DD`, `severity` and `scope` use
   allowed values.
3. With `--fp-test`, scans every rule against goodware directories and
   warns on rules that hit more than `FP_THRESHOLD` (default 5) files.

Exit 0 on clean, 1 on errors, 2 on bad invocation.

---

## Required baseline artifacts

This block is parsed by `.claude/skills/dfir-bootstrap/baseline-check.sh yara`.
Missing artifacts produce a high-priority `L-BASELINE-yara-NN` lead that runs
first in the next investigator wave.

<!-- baseline-artifacts:start -->
required: analysis/yara/rules-enumerated.txt
required: analysis/yara/validate-rules.txt
optional: analysis/yara/<scope>.compiled
optional: analysis/yara/yara-hits-EV01.txt
optional: analysis/yara/survey-EV01.md
optional: exports/yara_hits/yara-EV01.txt
<!-- baseline-artifacts:end -->

---

## Pivots — what to do with what you found here

| Found here | Pivot to | Skill |
|---|---|---|
| Hit on a file in `./exports/files/` | (a) Prefetch / Amcache for execution evidence of that filename, (b) `$J` for create time + parent process if Sysmon present, (c) USBSTOR if path is removable media | `windows-artifacts` + `sleuthkit` |
| Hit in process VAD (`vadyarascan` / image-wide) | (a) `cmdline --pid`, (b) `dlllist --pid`, (c) on-disk binary at process image path → hash + Prefetch, (d) network attribution (`netscan`) | `memory-analysis` + `windows-artifacts` |
| Hit on memory image with no matching process | `windows.malfind` to find which RWX VAD; dump it; carve PE if applicable | `memory-analysis` |
| Hit in unallocated / carved blob | `photorec` to recover surrounding container; check `$J` slack for original filename | `sleuthkit` |
| Hit confirms malware family | (a) extract family-specific IOCs (mutex, named pipe, C2 domain) into new rules, (b) sweep memory + disk + EVTX strings with the new rules, (c) DNS cache + browser history + SRUM for outbound to family C2 | this skill + `memory-analysis` + `windows-artifacts` |
| New high-FP rule | Run `-n` against `/usr/bin/`, `/Windows/System32/`; tighten conditions before sweeping evidence again | this skill |

---

## Velociraptor (Enterprise Endpoint Hunting)

See `reference/velociraptor.md` for the Velociraptor cross-reference:
key concepts (Artifact / Hunt / VQL), the common artifacts table for
threat hunting, the YARA-hunt VQL template, and triage VQL queries
(orphan processes, non-private remotes, suspicious scheduled tasks).
**Velociraptor is NOT a local SIFT binary** — connect to the web console.
