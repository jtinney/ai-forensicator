# Skill: Threat Hunting & IOC Sweeps (YARA / Velociraptor)

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
ProjectHoneynet ruleset on day 1; the false-positive triage will eat the case.

## Tool selection — pick by question

| Question | Best invocation | Why |
|---|---|---|
| Is this one file malicious? | `yara -s rules.yar <file>` | `-s` shows matched offsets — needed to validate the rule actually fired on the right bytes |
| Sweep extracted files for an IOC family | `yara -r -s -p 4 rules.yar ./exports/files/` | `-p` parallelizes; `-s` keeps you honest |
| Sweep a memory image | `yara rules.yar /path/to/memory.img` | Hits include strings injected into RWX VADs that may not exist on disk |
| Sweep VAD regions of one process (no dump) | `vol windows.vadyarascan --pid <PID> --yara-rules rules.yar` | Cheaper than `memmap --dump` then YARA |
| Sweep VAD regions of every process | `vol windows.vadyarascan --yara-rules rules.yar` | One-shot wide scan |
| Repeated scans of large corpus | `yarac rules.yar compiled.rules` then `yara -C compiled.rules <target>` | Avoids re-parsing rule source each run |
| Sweep just unallocated space | `blkls -A <image>.E01 > unalloc.raw` then `yara rules.yar unalloc.raw` | Carved indicators in slack |
| Hash-based IOC match | rule with `import "hash"` and `hash.sha256(0, filesize) == "..."` | When you have the hash and want the path |
| Validate scope of a rule before sweeping | `yara -r -n rules.yar /usr/bin/` | `-n` shows non-matches — confirms you're not catching the universe |

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
yara /path/to/rules.yar /path/to/file
```

### Scan a Directory Recursively
```bash
yara -r /path/to/rules.yar /mnt/windows_mount/Windows/System32/
```

### Scan a Memory Image
```bash
yara /path/to/rules.yar /path/to/memory.img
```

### Scan Exported Files from Evidence
```bash
yara -r /path/to/rules.yar ./exports/files/
```

### Scan with Match Detail (Show Matching Strings)
```bash
yara -r -s /path/to/rules.yar ./exports/files/ 2>/dev/null | tee ./exports/yara_hits/hits.txt
```

### Scan with Metadata Output
```bash
yara -r -m /path/to/rules.yar /mnt/windows_mount/ 2>/dev/null
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
# Compile rules to binary for faster re-use (avoids re-parsing .yar each run)
yarac rules.yar compiled.rules

# Scan using compiled rules
yara -C compiled.rules /target/path/
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

Before any `yara` invocation, enumerate the rule library and record what
is available. An in-memory mental model of the rule set leaves the audit
trail unable to prove which rules fired and which did not — record the
enumeration on disk so a future examiner can reconstruct the scan.

```bash
mkdir -p ./analysis/yara

{
    echo "# YARA rule enumeration — $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo

    for ns in local vendor quarantine legacy; do
        nsdir=".claude/skills/yara-hunting/rules/$ns"
        echo "## namespace: $ns"
        if [[ -d "$nsdir" ]]; then
            ls -la "$nsdir"
            find "$nsdir" \( -name '*.yar' -o -name '*.yara' -o -name '*.rules' \) \
                -printf '\n=== %p ===\n' \
                -exec head -25 {} \;
        else
            echo "(directory missing)"
        fi
        echo
    done

    echo "## case-local rules under ./analysis/yara/"
    if compgen -G './analysis/yara/*.yar' >/dev/null \
       || compgen -G './analysis/yara/*.yara' >/dev/null; then
        ls -la ./analysis/yara/*.yar ./analysis/yara/*.yara 2>/dev/null
    else
        echo "(none)"
    fi

    echo
    echo "## vendor manifest"
    if [[ -f .claude/skills/yara-hunting/rules/vendor/vendor-manifest.json ]]; then
        cat .claude/skills/yara-hunting/rules/vendor/vendor-manifest.json
    else
        echo "(no vendored sets pulled — see vendor-rules.sh)"
    fi
} > ./analysis/yara/rules-enumerated.txt

# Validate the rule library before scanning. Errors here mean the rule set
# itself is broken; refuse to scan with a broken library.
bash .claude/skills/yara-hunting/validate-rules.sh \
    .claude/skills/yara-hunting/rules/local/ \
    ./analysis/yara/ \
    > ./analysis/yara/validate-rules.txt 2>&1 \
    || echo "WARN: validate-rules.sh reported errors — see analysis/yara/validate-rules.txt"

bash .claude/skills/dfir-bootstrap/audit.sh \
    "yara-rule-enumeration" \
    "enumerated local/vendor/quarantine/legacy + case-local rules — see analysis/yara/rules-enumerated.txt" \
    "select namespaces in scope; compile via yarac before scan"
```

**Namespace discipline.** Default scans should load
`rules/local/` (always reusable). Vendored sets under `rules/vendor/<source>/`
are loaded explicitly. `rules/quarantine/` and `rules/legacy/` are NEVER
loaded by default. Case-local rules under `./analysis/yara/` are scoped to
the current evidence set only.

If `rules/local/` is empty AND no case-local rules exist AND no vendor sets
have been pulled, the scan is a discipline failure — STOP and pull a vendor
set (`vendor-rules.sh`) or request rules from the case lead rather than
running yara with no signatures.

**Compile once, scan many.** For corpora over ~1 GB:

```bash
yarac ./analysis/yara/rules-EV01.yar ./analysis/yara/rules-EV01.compiled
yara -C ./analysis/yara/rules-EV01.compiled <target>     # uses compiled
```

`rules-enumerated.txt` is in the baseline-artifact contract for this skill
(see § "Required baseline artifacts" below). Skipping the gate causes
`baseline-check.sh yara` to flag a missing artifact and the orchestrator
to emit `L-BASELINE-yara-NN`.

---

## IOC Sweep Workflow

1. **Build IOC list** from confirmed findings (file hashes, strings, IPs, domains, paths, mutex names)
2. **Write YARA rules** targeting each IOC type — one rule per indicator family
3. **Test rules for false positives** against a clean image or known-good file set first
4. **Scan mounted evidence** — `yara -r -s <rules> /mnt/windows_mount/`
5. **Scan memory image** — `yara <rules> /path/to/memory.img`
6. **Scan extracted files** — `yara -r <rules> ./exports/files/`
7. **Cross-reference hits** with filesystem timeline and process artifacts
8. **Export findings** to `./exports/yara_hits/ioc_sweep_<CASE_ID>_<date>.txt`

### False Positive Testing

```bash
# Test rules against a known-clean directory before sweeping evidence
yara -r rules.yar /usr/bin/ 2>/dev/null

# Use -n to see which rules did NOT match (verify scope coverage)
yara -r -n rules.yar /path/to/sample/

# Test a single rule in isolation
yara -r /path/to/single_rule.yar /path/to/target/
```

---

## Rule library layout

The skill rule library is namespace-partitioned so that every scan can be
scoped intentionally and the audit trail records exactly which namespaces
fired:

```
.claude/skills/yara-hunting/rules/
├── local/        — project-vetted, in-house rules (tracked in git)
├── vendor/       — third-party upstream sets, populated by vendor-rules.sh
│                   (gitignored by default — license terms vary, operator
│                    must `git add -f` to commit a vendored set)
├── quarantine/   — rules disabled for FP / scope problems (tracked in git
│                   as historical record, never loaded into scans)
└── legacy/       — historical case-specific rules retained for chain of
                    custody. NOT included in default sweeps.
```

**Per-case output (follows the canonical layer model in
`.claude/skills/dfir-discipline/DISCIPLINE.md` "Layer model" subsection):**
```
./analysis/yara/                         ← per-case rules + scan summaries (layer 3)
./analysis/yara/rules-EV01.yar           ← case-local rules (one per evidence)
./analysis/yara/rules-EV01.compiled      ← yarac-compiled binary
./analysis/yara/yara-hits-EV01.txt       ← scan hit summaries
./analysis/yara/rules-enumerated.txt     ← required baseline (see § gate)
./exports/yara_hits/                     ← byte extracts of files that matched (layer 4)
./reports/                               ← finalized IOC sweep reports
```

Multi-evidence cases append the EVID per Rule L: hit summaries
`yara-hits-EV02.txt` are sibling files; byte-extract subdirs are
`exports/yara_hits/EV01/`, `exports/yara_hits/EV02/`.

A scan that loads `rules/local/` + `rules/vendor/<source>/` is **reusable**.
A scan that loads `rules/legacy/` is **not** — those files contain
case-tied indicators (filenames, hostnames, hashes) that would generate
false positives outside the originating case.

---

## Rule conventions (mandatory for `rules/local/`)

See `reference/rule-conventions.md` for the full convention: required and
recommended `meta` keys, tag vocabulary (Scope / Format / Stage / Severity /
Family), naming convention by provenance, the performance contract
(cheap→expensive condition ordering), and the false-positive contract.
`validate-rules.sh` enforces the required keys and runs `yarac` for syntax.

---

## Rule validation (`validate-rules.sh`)

Run before committing any change to `rules/local/` and as part of the
case-bootstrap rule-enumeration gate (see below):

```bash
# Validate every rule in rules/local/
bash .claude/skills/yara-hunting/validate-rules.sh

# Validate case-local rules
bash .claude/skills/yara-hunting/validate-rules.sh ./analysis/yara/

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

## Vendoring upstream rule sets (`vendor-rules.sh`)

See `reference/vendor-sources.md` for the full vendoring workflow:
`vendor-rules.sh` invocations (default / `--with elastic` / `--verify-only` /
`--list` / `--clean`), the reputable-upstream-sources table (yara-forge,
signature-base, Elastic, ReversingLabs, Volexity/Mandiant, CISA), the
`vendor-manifest.json` integrity model, and tag-based scoping for vendored
sets at scan time.

---

## Required baseline artifacts

This block is parsed by `.claude/skills/dfir-bootstrap/baseline-check.sh yara`.
Missing artifacts produce a high-priority `L-BASELINE-yara-NN` lead that runs
first in the next investigator wave.

<!-- baseline-artifacts:start -->
required: analysis/yara/rules-enumerated.txt
required: analysis/yara/validate-rules.txt
optional: analysis/yara/rules-EV01.yar
optional: analysis/yara/rules-EV01.compiled
optional: analysis/yara/yara-hits-EV01.txt
optional: analysis/yara/survey-EV01.md
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
