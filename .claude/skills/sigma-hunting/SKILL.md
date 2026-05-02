# Skill: Sigma / EVTX Hunting (Chainsaw + Hayabusa)

<protocol>
  <rule>Rules + mappings live at <code>/opt/sigma-rules/</code>. See DISCIPLINE.md §P-sigma.</rule>
  <rule>Tool order is the <code>sigma-hunting</code> entry of DISCIPLINE.md §P-priority. Surveyor runs <code>chainsaw hunt --sigma /opt/sigma-rules/sigma --mapping /opt/sigma-rules/mappings/sigma-event-logs-all.yml --csv -o ./analysis/sigma/&lt;EVID&gt;/ &lt;evtx_dir&gt;</code>.</rule>
  <rule>Hits go to <code>./analysis/sigma/&lt;EVID&gt;/</code> (CSVs). Matched-event byte extracts go to <code>./exports/sigma_hits/&lt;EVID&gt;/&lt;rule_id&gt;/</code>.</rule>
  <rule>Do not author, cache, or vendor rules inside the project workspace. Operator maintains <code>/opt/sigma-rules/</code> via the SIFT install script.</rule>
  <rule>EVTX corpus on a disk image is read from the partition mount at <code>./working/mounts/&lt;EV&gt;/p&lt;M&gt;/Windows/System32/winevt/Logs/</code> per DISCIPLINE.md §P-diskimage. Do NOT extract via <code>icat</code> first when the mount is available.</rule>
</protocol>

## Use this skill when

- You have a corpus of Windows `.evtx` files (host-collected event logs,
  exported from a triage bundle, or extracted from `Windows/System32/winevt/Logs/`)
- A finding from another skill (memory `pslist` anomaly, Prefetch hit,
  YARA match on a binary path) needs cross-correlation against EVTX
  signal — Sigma rules express that signal portably across hosts
- You want signature-based event-log triage instead of grep-by-EID

**Don't reach for Sigma when** the question is bytes-on-disk or
bytes-in-memory — that's YARA territory. Sigma is a log-event language;
it operates on parsed EVTX records, not file/memory contents. Conversely,
do not try to express a Windows event-log condition with a YARA rule —
the abstraction is wrong.

## Tool selection — pick by question

| Question | Best invocation | Why |
|---|---|---|
| Run Sigma rules against a directory of EVTX | `chainsaw hunt <evtx_dir> -s <sigma_rules> --mapping <mapping.yml> --csv -o <out>` | Sigma needs a field-mapping file to translate to EVTX field names; Chainsaw bundles a curated mapping |
| Run Chainsaw's bundled hunting rules (no Sigma) | `chainsaw hunt <evtx_dir> -r <chainsaw_rules> --csv -o <out>` | Chainsaw rules are richer than Sigma (aggregations, on-disk groupings); use when you want Chainsaw's curated detections |
| Search EVTX for a literal IOC string (no rule) | `chainsaw search <evtx_dir> -s "<term>" --tau "<EID>"` | Faster than building a one-shot Sigma rule for a single string |
| Wide-coverage EVTX timeline + Sigma in one pass | `hayabusa csv-timeline -d <evtx_dir> -o timeline.csv` | Hayabusa bundles a pre-mapped Sigma + Hayabusa-specific rule set, optimized for triage |
| Validate one Sigma rule before running | `chainsaw lint <sigma.yml>` | Catches schema errors before a long hunt |
| Convert one Sigma rule for Splunk / Elastic / etc | `sigma convert -t splunk <sigma.yml>` | When the host org runs another SIEM and you want to ship the rule there |
| Repeated runs of large EVTX corpus | Pre-filter with `evtx_dump` → grep relevant EIDs → run Chainsaw on subset | Filter cheap before invoking Sigma matchers |

## Overview

Sigma is the portable detection-rule language for SIEMs. `Chainsaw`
(WithSecure Labs, Rust) and `Hayabusa` (Yamato Security, Rust) both
consume Sigma rules and apply them to local EVTX files — neither is a
SIEM, both are forensic triage tools. They overlap in capability but
differ in opinion:

- **Chainsaw** — explicit `hunt` / `search` / `dump` / `lint` subcommands,
  Sigma + its own richer rule format (with aggregations), CSV / JSON / JSONL
  output, designed to be scripted into pipelines
- **Hayabusa** — single-command timelines, ships a curated rule pack
  optimized for IR triage, opinionated severity model (`crit`/`high`/`med`/
  `low`/`info`), strong default output

Use Chainsaw when you want fine-grained control over which rules run
against which logs and want machine-readable per-hit output. Use
Hayabusa when you want a fast triage timeline of "everything interesting
in this evtx set". Both are fine; the project default below is Chainsaw
for orchestrator integration (its CSV output maps cleanly into the
findings format).

## Analysis Discipline

`./analysis/sigma/` is not just a bucket for raw tool output. Keep a terse
audit trail and human-written findings as you work.

- `./analysis/forensic_audit.log` — append a UTC line after every distinct
  action (`chainsaw hunt`, `sigma rule promote`, `hayabusa csv-timeline`).
- `./analysis/sigma/findings.md` — append short notes per pivot: rule that
  fired, evidence path + line/EID, interpretation, next pivot.
- `./reports/00_intake.md` or the active case report — update when a
  finding changes the case narrative.

Use this format for audit entries: `<UTC timestamp> | <action> |
<finding/result> | <next step>`.

---

## Tool reference

| Tool | Location | Platform |
|------|----------|----------|
| `chainsaw` | install from `https://github.com/WithSecureLabs/chainsaw/releases` (Rust binary, no deps) | SIFT Linux |
| `hayabusa` | install from `https://github.com/Yamato-Security/hayabusa/releases` (Rust binary) | SIFT Linux |
| `evtx_dump` | apt: `evtx-tools` (or `cargo install evtx`) | SIFT Linux — raw EVTX → JSONL |
| `python3-evtx` | apt: `python3-evtx` | SIFT Linux — Python EVTX parser (fallback) |

Both Chainsaw and Hayabusa are statically linked Rust binaries — drop the
release binary in `/usr/local/bin/` and it works. They are NOT preinstalled
on a default SIFT image — verify with `bash .claude/skills/dfir-bootstrap/preflight.sh`
before invoking.

---

## Rule library layout

```
/opt/sigma-rules/                  ← canonical rule corpus (operator-maintained, populated by SIFT install)
├── sigma/                         ← Sigma .yml rules (SigmaHQ + project-authored)
├── chainsaw/                      ← Chainsaw bundled rules (richer than Sigma — aggregations, on-disk groupings)
├── hayabusa/                      ← Hayabusa rule packs
└── mappings/                      ← Chainsaw field-mapping YAMLs (sigma → EVTX field names)
                                       e.g. sigma-event-logs-all.yml, sigma-event-logs-windows.yml, chainsaw.yml
```

**Per-case output routing.** Sigma hunting produces two classes of output;
they go to different layers per the canonical layer model documented in
`.claude/skills/dfir-discipline/DISCIPLINE.md` ("Layer model" subsection
under Rule A). Bytes-as-analytic-unit go to `./exports/`; summaries-of-
bytes-elsewhere go to `./analysis/`.

**Summaries → `./analysis/sigma/`** (layer 3 — tool reports). Recomputable
from the source EVTX corpus by re-running Chainsaw / Hayabusa. NOT
fingerprinted (the source of truth is `./evidence/`):

```
./analysis/sigma/                          ← per-case scan output (layer 3)
./analysis/sigma/EV01/                     ← chainsaw CSV output (one CSV per rule that fired + Hits.csv)
./analysis/sigma/EV01/Hits.jsonl           ← chainsaw --jsonl summary (when used)
./analysis/sigma/hayabusa-timeline-EV01.csv ← hayabusa csv-timeline output
./analysis/sigma/survey-EV01.md            ← surveyor write-up per evidence item
./analysis/sigma/findings.md               ← consolidated investigator findings
./analysis/sigma/rules-enumerated.txt      ← required baseline (see § gate)
```

**Matched-event byte extracts → `./exports/sigma_hits/<EVID>/<rule_id>/`**
(layer 4 — derived artifacts). The actual EVTX record dumps a Chainsaw or
Hayabusa rule surfaced — distinct analytic units that downstream skills
(YARA, disassembly, registry pivot) chain conclusions on. Fingerprinted by
`audit-exports.sh` into `analysis/exports-manifest.md`. Per Rule L's
directory-tree exception (`.claude/skills/dfir-discipline/DISCIPLINE.md`):

```
./exports/sigma_hits/<EVID>/<rule_id>/event-<record_id>.jsonl
./exports/sigma_hits/EV01/proc_creation_win_powershell_encoded_invocation/event-12345.jsonl
./exports/sigma_hits/EV01/file_event_win_susp_office_doc_drop/event-67890.jsonl
./exports/sigma_hits/EV02/proc_creation_win_powershell_encoded_invocation/event-22001.jsonl
```

`<EVID>` is the manifest evidence id (`EV01`, `EV02`, …) the surveyor /
investigator agent prose receives at dispatch — see Phase 1 (`dfir-triage`)
output. `<rule_id>` is the rule's filename minus the `.yml` extension so
the matched-record corpus is self-describing without a sidecar map.

Chainsaw and Hayabusa themselves emit only summary CSVs/JSONL — neither
tool dumps matched-event bytes natively. Byte extracts are produced by
post-processing the summary's `record_id` + `channel` columns through
`evtx_dump` (see Hunting workflow § 6 below).

---

## Rule conventions

Every rule under `/opt/sigma-rules/sigma/` MUST conform to this convention.
The linter (`validate-rules.sh`, see below) defaults to that path; it
enforces required keys and runs `chainsaw lint` to confirm syntax. Rule
authoring and curation happen out-of-band — the operator maintains
`/opt/sigma-rules/` via the SIFT install script.

### Required Sigma keys

| Key | Value | Notes |
|---|---|---|
| `title`       | string                              | One-line, present-tense ("Detects PowerShell encoded command") |
| `id`          | UUID v4                             | Generate with `uuidgen` — must be globally unique |
| `description` | string                              | What the rule fires on (the technical condition), not why it matters |
| `author`      | string                              | Person or project ("ai-forensicator project library") |
| `date`        | `YYYY/MM/DD`                        | Sigma convention uses slashes (NOT dashes) — bump when rule body changes |
| `level`       | `informational` \| `low` \| `medium` \| `high` \| `critical` | Operator's confidence the hit is malicious |
| `logsource`   | structured (see Sigma spec)          | At minimum `product:` or `service:` and either `category:` or `definition:` |
| `detection`   | structured                          | Selection blocks + `condition:` |

### Recommended Sigma keys

| Key | Value |
|---|---|
| `references`     | List of URLs / CVE IDs / paper links |
| `tags`           | List, prefer ATT&CK form: `attack.command_and_control`, `attack.t1059.001` |
| `falsepositives` | List of plausible benign sources |
| `status`         | `experimental` \| `test` \| `stable` \| `deprecated` \| `unsupported` |
| `modified`       | `YYYY/MM/DD` of last meaningful body change |
| `fields`         | Useful EVTX fields to surface alongside the hit |

### Naming convention

- `title` should be specific enough to search for. Avoid generic titles
  like "Suspicious Process" — name the technique.
- File names follow `<area>.yml` (e.g. `win-process-creation.yml`,
  `win-network-connection.yml`, `win-account-mgmt.yml`). One file may
  contain multiple `---`-separated rules.

### Tag vocabulary

Mirror Sigma's official tag namespace:

| Category | Tags |
|---|---|
| ATT&CK Tactic    | `attack.initial_access`, `attack.execution`, `attack.persistence`, `attack.privilege_escalation`, `attack.defense_evasion`, `attack.credential_access`, `attack.discovery`, `attack.lateral_movement`, `attack.collection`, `attack.command_and_control`, `attack.exfiltration`, `attack.impact` |
| ATT&CK Technique | `attack.t1059.001` (PowerShell), `attack.t1003.001` (LSASS dump), etc. |
| CAR              | `car.2013-05-002` |
| CVE              | `cve.2021-44228` |
| Project-local    | `project.<name>` for in-house tags (e.g. `project.dfir-orchestrator`) |

---

## Rule validation (`validate-rules.sh`)

Default target is `/opt/sigma-rules/sigma/`.

```bash
# Lint every rule under /opt/sigma-rules/sigma/
bash .claude/skills/sigma-hunting/validate-rules.sh

# Lint a specific subset
bash .claude/skills/sigma-hunting/validate-rules.sh /opt/sigma-rules/sigma/rules-threat-hunting/

# Strict mode — also requires `references` and `tags`
bash .claude/skills/sigma-hunting/validate-rules.sh --strict
```

The script:

1. Runs `chainsaw lint` (full Sigma schema check) on each `.yml`.
2. Parses each rule's frontmatter and verifies the required keys, `id` is a
   well-formed UUID, `date` matches `YYYY/MM/DD`, `level` is in the
   allowed set.
3. With `--strict`, also requires `references` and `tags`.

Exit 0 on clean, 1 on errors, 2 on bad invocation.

---

## Mapping files (Chainsaw)

Chainsaw needs a field-mapping file to translate Sigma's generic field
names (`Image`, `CommandLine`, `User`) to the EVTX-specific schema.
Mappings live alongside the rules at `/opt/sigma-rules/mappings/`:

- `sigma-event-logs-all.yml` — broadest coverage; default
- `sigma-event-logs-windows.yml` — Windows-specific
- `chainsaw.yml` — for Chainsaw's own rule format

---

## Rule enumeration gate (run BEFORE any scan)

Before any `chainsaw hunt` or `hayabusa` invocation, enumerate the rule
corpus at `/opt/sigma-rules/` so the audit trail records exactly what was
available at scan time. If the directory is missing or empty, preflight
reports `sigma-hunting: RED/YELLOW`; the surveyor BLOCKS its lead per
§P-priority with `suggested-fix=install-package; tool-needed=/opt/sigma-rules`.

```bash
mkdir -p ./analysis/sigma

{
    echo "# Sigma rule enumeration — $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo "## corpus root: /opt/sigma-rules/"
    if [[ -d /opt/sigma-rules ]]; then
        for sub in sigma chainsaw hayabusa mappings; do
            echo
            echo "### /opt/sigma-rules/${sub}/"
            if [[ -d "/opt/sigma-rules/${sub}" ]]; then
                find "/opt/sigma-rules/${sub}" -type f \( -name '*.yml' -o -name '*.yaml' \) | wc -l \
                    | xargs -I{} echo "  rule/mapping files: {}"
            else
                echo "(missing)"
            fi
        done
    else
        echo "(missing — preflight RED)"
    fi
} > ./analysis/sigma/rules-enumerated.txt

bash .claude/skills/sigma-hunting/validate-rules.sh \
    > ./analysis/sigma/validate-rules.txt 2>&1 \
    || echo "WARN: validate-rules.sh reported errors — see analysis/sigma/validate-rules.txt"

bash .claude/skills/dfir-bootstrap/audit.sh \
    "sigma-rule-enumeration /opt/sigma-rules/" \
    "enumerated $(wc -l < ./analysis/sigma/rules-enumerated.txt) lines — see analysis/sigma/rules-enumerated.txt" \
    "pick rule scope + mapping; chainsaw hunt"
```

---

## Hunting workflow

### 1. Pre-filter EVTX (cheap)

```bash
# Get a quick sense of what's in the corpus
for evtx in /path/to/evtx/*.evtx; do
    evtx_dump --no-confirm-overwrite -o jsonl "$evtx" \
        > "./analysis/sigma/jsonl/$(basename "$evtx").jsonl"
done

# Counts per channel (pick what's worth running rules against)
for f in ./analysis/sigma/jsonl/*.jsonl; do
    printf "%-60s %d\n" "$(basename "$f")" "$(wc -l <"$f")"
done | sort -k2 -nr
```

### 2. Run Sigma rules with Chainsaw

`<EVID>` below is the manifest evidence id (`EV01`, `EV02`, …) the agent
receives at dispatch. Substitute the concrete value when invoking. The
`--csv` summary writes to `./analysis/sigma/` (layer 3); matched-event
byte extracts are produced as a separate post-processing step (§ 6) and
land under `./exports/sigma_hits/<EVID>/<rule_id>/` (layer 4).

```bash
chainsaw hunt /path/to/evtx \
    -s /opt/sigma-rules/sigma/ \
    --mapping /opt/sigma-rules/mappings/sigma-event-logs-all.yml \
    --csv \
    -o ./analysis/sigma/EV01/
```

Chainsaw writes one CSV per Sigma rule that produced any hit, plus a
`Hits.csv` summary. Each hit has columns: `timestamp`, `detections`,
`channel`, `event_id`, `record_id`, plus the rule-defined `fields`. The
`record_id` + `channel` pair is the join key for the byte-extract step
in § 6.

### 3. Run Chainsaw's bundled hunting rules

These are richer than Sigma (aggregation, on-disk groupings) and tuned
for incident response:

```bash
chainsaw hunt /path/to/evtx \
    -r /opt/sigma-rules/chainsaw/ \
    --csv \
    -o ./analysis/sigma/EV01-chainsaw/
```

### 4. Hayabusa one-shot triage timeline

When you want everything-at-once instead of a guided hunt:

```bash
hayabusa csv-timeline \
    -d /path/to/evtx \
    -o ./analysis/sigma/hayabusa-timeline-EV01.csv \
    --UTC \
    --no-summary
```

Hayabusa output columns: `Timestamp`, `Computer`, `Channel`, `Level`,
`EventID`, `RuleTitle`, `Details`, `RecordID`, `RuleAuthor`, `RuleModifiedDate`,
`Status`, `RuleID`. Filter by `Level=crit` for the first triage pass. The
`RecordID` + `Channel` pair feeds the byte-extract step in § 6.

### 5. Pivot from hit → host artifact

Every Sigma hit cites `record_id` and `channel`. To re-read the underlying
event from the original EVTX in-place (no extract written):

```bash
# Inspect the exact record by ID without producing a derived artifact
evtx_dump -t 1 -o jsonl /path/to/Security.evtx \
    | jq 'select(.Event.System.EventRecordID == 12345)'
```

### 6. Extract matched-event bytes → `./exports/sigma_hits/<EVID>/<rule_id>/`

When a Sigma / Hayabusa hit becomes a chainable analytic unit (YARA target,
correlator join key, downstream report citation), promote the underlying
EVTX record to layer 4 so it gets fingerprinted by `audit-exports.sh` and
survives chain-of-custody. Use the rule's filename (less the `.yml`
extension) as `<rule_id>` so the directory is self-describing. Per Rule L
(directory-tree exception, see DISCIPLINE.md):

```bash
EVID=EV01
rule_id="proc_creation_win_powershell_encoded_invocation"
record_id=12345                                             # from Hits.csv / hayabusa-timeline.csv
channel="Microsoft-Windows-Sysmon%4Operational"             # from Hits.csv / hayabusa-timeline.csv
src_evtx="/path/to/${channel}.evtx"

mkdir -p "./exports/sigma_hits/${EVID}/${rule_id}/"

# Write the JSON dump of the single matched record. The byte sequence —
# this JSON dump — is the analytic unit a downstream investigator pivots on.
evtx_dump -t 1 -o jsonl "$src_evtx" \
    | jq -c --argjson rid "$record_id" \
        'select(.Event.System.EventRecordID == $rid)' \
    > "./exports/sigma_hits/${EVID}/${rule_id}/event-${record_id}.jsonl"

# Audit row links the source EVTX to the export so chain-of-custody is intact.
bash .claude/skills/dfir-bootstrap/audit.sh \
    "sigma-hit byte-extract" \
    "extracted ${rule_id} record ${record_id} from ${EVID} channel ${channel}" \
    "audit-exports.sh PostToolUse hook fingerprints into exports-manifest.md"
```

`audit-exports.sh` walks `./exports/` depth-unbounded, so each new
`event-<record_id>.jsonl` lands in `analysis/exports-manifest.md` with a
`first-seen` row. Per-rule subdirs collate every match for that detection
under one path, and per-EVID parents keep the multi-host corpus organized
without filename collisions across hosts (Rule L worked example).

---

## Required baseline artifacts

This block is parsed by `.claude/skills/dfir-bootstrap/baseline-check.sh sigma`.
Missing artifacts produce a high-priority `L-BASELINE-sigma-NN` lead that
runs first in the next investigator wave.

<!-- baseline-artifacts:start -->
required: analysis/sigma/rules-enumerated.txt
required: analysis/sigma/validate-rules.txt
optional: analysis/sigma/EV01/Hits.csv
optional: analysis/sigma/hayabusa-timeline-EV01.csv
optional: analysis/sigma/survey-EV01.md
optional: exports/sigma_hits/EV01/
<!-- baseline-artifacts:end -->

---

## Pivots — what to do with what you found here

| Found here | Pivot to | Skill |
|---|---|---|
| Sigma hit on a process-creation event | (a) parent process chain in same EVTX, (b) Prefetch/Amcache for the executable, (c) `$J` for create time + parent on disk, (d) YARA the executable hash | `windows-artifacts` + `sleuthkit` + `yara-hunting` |
| Sigma hit on a network-connection event | (a) DNS-Client / Sysmon EID-22 in same window, (b) pcap capture if available, (c) host file system for the process image path | `network-forensics` + `windows-artifacts` |
| Sigma hit on auth / account-management EID | (a) other login/logoff in same session, (b) NTUSER.DAT for the account, (c) Logon-Type / WorkstationName context for movement direction | `windows-artifacts` |
| Sigma hit confirms malware family | (a) extract IOCs (mutex, named pipe, C2 domain) into YARA rules, (b) sweep memory + disk + EVTX strings, (c) DNS cache + browser history + SRUM for outbound | `yara-hunting` + `windows-artifacts` + `memory-analysis` |
| New high-FP rule | Run `chainsaw lint`; tighten `condition:` and `selection:` blocks; FP-test against a clean EVTX corpus before re-running | this skill |

---

## Velociraptor cross-reference

Velociraptor's `Windows.EventLogs.EvtxHunter` artifact accepts Sigma rules
directly via the `Rules` parameter. Promoting a `/opt/sigma-rules/sigma/`
rule into a Velociraptor hunt is a copy-paste — keep `references:`
pointing back at the source so the chain is auditable.
