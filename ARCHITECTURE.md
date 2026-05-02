# ARCHITECTURE.md

Single source of truth for "where things live" in this project.

<directory-map>

```
ai-forensicator/                     project root
├── CLAUDE.md                        operator preferences + case-start protocol + tool routing
├── ARCHITECTURE.md                  this file
├── README.md                        project overview
├── VALIDATION.md                    human-reviewer protocol for verifying case output
├── .claude/
│   ├── agents/                      six phase agents (dfir-{triage,surveyor,investigator,correlator,reporter,qa}.md)
│   ├── commands/                    /case slash command
│   ├── settings.json                permissions + audit hooks
│   ├── skills/
│   │   ├── ORCHESTRATE.md           phase-based dispatch
│   │   ├── TRIAGE.md                single-context unguided protocol
│   │   ├── dfir-bootstrap/          preflight, case-init, audit hooks, fallback parsers
│   │   ├── dfir-discipline/         DISCIPLINE.md rules + survey template
│   │   ├── exec-briefing/           stakeholder-summary writing rules
│   │   ├── memory-analysis/         Volatility 3 + Memory Baseliner
│   │   ├── network-forensics/       Zeek + tshark inventory
│   │   ├── plaso-timeline/          Plaso super-timelines
│   │   ├── sigma-hunting/           Chainsaw + Hayabusa
│   │   ├── sleuthkit/               TSK, carving, MFT
│   │   ├── windows-artifacts/       EZ Tools, EVTX, registry, Prefetch
│   │   └── yara-hunting/            YARA scans (rules at /opt/yara-rules/)
│   └── reference/                   SANS docs cache
├── cases/                           one subdirectory per case
│   ├── case-xxxx/                   blank template — clone for new cases
│   └── <CASE_ID>/                   case workspace (five layers below)
└── examples/                        worked example case (NIST CFREDS)
```
</directory-map>

<case-workspace>
Every case at `./cases/<CASE_ID>/` has five top-level folders. Each layer has a distinct mutability and integrity contract.

| n | path           | purpose                                              | mutability                    |
|---|----------------|------------------------------------------------------|-------------------------------|
| 1 | `evidence/`    | originals; `chmod a-w` after intake                  | read-only                     |
| 2 | `working/`     | bundle expansions, E01 conversions, decompressions   | read-only by convention       |
| 3 | `analysis/`    | tool reports (CSV / JSON / `findings.md` / `survey-EVnn.md`) | mutable, recomputable |
| 4 | `exports/`     | derived bytes (carved files, hives, pcap slices, memdumps) | write-once               |
| 5 | `reports/`     | final deliverables (`final.md`, `stakeholder-summary.md`, `qa-review.md`, `00_intake.md`) | mutable |
</case-workspace>

<concept-locations>
Where each shared concept is canonically defined.

| concept                       | canonical file                                           |
|-------------------------------|----------------------------------------------------------|
| audit-log row format          | `.claude/skills/dfir-discipline/DISCIPLINE.md` `<audit-log-format>` |
| marker self-attestation       | `.claude/skills/dfir-discipline/DISCIPLINE.md` `<marker-self-attestation>` |
| five-layer model              | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule A — Layer model + this file |
| hypothesis-first              | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule F |
| scope-closure                 | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule G |
| lead surface exhaustion       | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule H |
| headline / table revalidation | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule B |
| lead terminal-status invariant| `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule I |
| MITRE ATT&CK tagging          | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule K |
| intake completeness           | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule J |
| multi-evidence path encoding  | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule L |
| PCAP processing (Zeek-only)   | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule P-pcap |
| disk-image format (E01)       | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule P-diskimage |
| new-tool prohibition / BLOCKED leads | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule P-tools |
| YARA rules location           | `.claude/skills/dfir-discipline/DISCIPLINE.md` Rule P-yara |
| tool inventory (per-host)     | `./analysis/preflight.md` (output of `preflight.sh`) |
| reference-style convention    | `CLAUDE.md` `<reference-style>` |
| lead-ID prefixes              | `.claude/skills/ORCHESTRATE.md` Lead ID conventions table |
| case-close gates              | `CLAUDE.md` Case-close gates table |
| survey output skeleton        | `.claude/skills/dfir-discipline/templates/survey-template.md` |
</concept-locations>

<naming>
| kind                   | pattern                                  | example                          |
|------------------------|------------------------------------------|----------------------------------|
| evidence ID            | `EV<NN>` (zero-padded)                   | `EV01`, `EV12`                   |
| bundle member ID       | `<EV>-M<NNN>`                            | `EV01-M042`                      |
| surveyor lead          | `L-<EV>-<DOMAIN>-<NN>`                   | `L-EV01-memory-01`               |
| investigator escalation| `L-<EV>-<DOMAIN>-e<NN>`                  | `L-EV01-memory-e01`              |
| correlator gap         | `L-CORR-<NN>`                            | `L-CORR-03`                      |
| correlator re-extract  | `L-EXTRACT-RE-<NN>` (sequential mode)    | `L-EXTRACT-RE-01`                |
| disk-pressure block    | `L-EXTRACT-DISK-<NN>`                    | `L-EXTRACT-DISK-01`              |
| audit-row prefix       | `[discipline]`, `[correlation]`, `[disk]`, `[qa-redispatch]` | as documented |
| derived-byte filename  | `<artifact>-<EV>.<ext>`                  | `dns-EV01.pcap`                  |
| derived-byte tree      | `exports/<domain>/<EV>/<artifact-tree>/` | `exports/registry/EV01/SOFTWARE/`|
</naming>
