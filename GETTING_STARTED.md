# Getting started

A 10-minute walkthrough from cloned repo to a closed case. Read
`README.md` for the project ideology, `ARCHITECTURE.md` for the
directory map, and `CLAUDE.md` for the operator contract.

## Prerequisites

| Requirement | Why |
|-------------|-----|
| SANS SIFT Workstation (Ubuntu, x86-64) | Every domain skill expects SIFT-installed tooling (TSK, Plaso, Volatility 3, Zeek, Suricata, Chainsaw, Hayabusa, EZ Tools). |
| Claude Code CLI | The orchestrator runs as Claude Code subagents and slash commands. |
| `sudo` access | `install-tools.sh` invokes `apt`; `case-init.sh` uses `chmod a-w` on evidence; disk-image mounting uses `qemu-nbd` + `ewfmount`. |
| ~10 GB free disk per case | Bundle expansion, mounted disks, exports, and Plaso storage grow fast. |

## 1. Clone the project

```bash
git clone https://github.com/jtinney/ai-forensicator ~/Desktop/ai-forensicator
cd ~/Desktop/ai-forensicator
```

The project root holds the harness (`.claude/`), the case container
(`cases/`), and the worked example pointer (`examples/`). Every case
lives at `./cases/<CASE_ID>/`; the project root is never an active
case workspace.

## 2. Inventory the SIFT instance

```bash
mkdir -p ./analysis    # preflight writes here when run from project root
bash .claude/skills/dfir-bootstrap/preflight.sh | tee ./analysis/preflight.md
```

Preflight is the authoritative tool inventory for this host. Read the
`SKILL_STATUS:` lines at the bottom — they drive which domain skills
the orchestrator routes to. A `RED` skill means evidence in that
domain produces BLOCKED leads until the missing tool is installed.

## 3. Install missing tools

```bash
sudo bash .claude/skills/dfir-bootstrap/install-tools.sh --check   # dry inventory
sudo bash .claude/skills/dfir-bootstrap/install-tools.sh           # install gaps
bash  .claude/skills/dfir-bootstrap/preflight.sh | tee ./analysis/preflight.md
```

`install-tools.sh` covers apt packages, EZ Tools at
`/opt/zimmermantools/`, Chainsaw, Hayabusa, `evtx_dump`, and the
Suricata ET Open ruleset sync. ET Open sync failures are a hard fail
— Suricata without rules silently runs an empty IDS pass.

## 4. Stage the YARA and Sigma rule corpora

The DFIR discipline rules pin both corpora to fixed `/opt/` paths
(`§P-yara`, `§P-sigma`). Agents read from these paths and never
vendor rules into the workspace.

```bash
sudo mkdir -p /opt/yara-rules /opt/sigma-rules/{sigma,chainsaw,hayabusa,mappings}
sudo chown -R "$USER":"$USER" /opt/yara-rules /opt/sigma-rules

# YARA — Yara-Rules/rules covers the common malware signatures
git clone https://github.com/Yara-Rules/rules.git /opt/yara-rules/yara-rules-community

# Sigma — upstream rules + Chainsaw + Hayabusa mappings
git clone https://github.com/SigmaHQ/sigma.git              /opt/sigma-rules/sigma
git clone https://github.com/WithSecureLabs/chainsaw.git    /opt/sigma-rules/chainsaw
git clone https://github.com/Yamato-Security/hayabusa-rules /opt/sigma-rules/hayabusa
```

Maintain these out-of-band — re-pull them when the upstream corpora
move. Agents do not author or cache rules; the workspace stores only
hits (`./exports/yara_hits/`, `./analysis/sigma/`).

## 5. Create a case workspace

```bash
CASE_ID=case01
mkdir -p ./cases/$CASE_ID/evidence
cp /path/to/evidence.E01 ./cases/$CASE_ID/evidence/
```

`./cases/case-xxxx/` is the blank template — clone or rename it for
new cases. Drop every artifact for the case under `./evidence/`.
Bundles (`.zip`, `.tar.gz`, `.7z`) expand into `./working/<basename>/`
during case-init; raw/E01/VMDK/VHD images mount read-only into
`./working/mounts/<EV>/` via `qemu-nbd` + `ewfmount`.

## 6. Launch the orchestrator

From the project root, inside Claude Code:

```
/case case01
```

The slash command `cd`s into `./cases/case01/`, runs `case-init.sh`,
gates on `manifest-check.sh`, then dispatches the six phase agents:

| Phase | Agent | Job |
|-------|-------|-----|
| 1 Triage | `dfir-triage` | Hash evidence, lock `./evidence/` read-only, write `manifest.md`, run intake interview if chain-of-custody fields are blank. |
| 2 Survey | `dfir-surveyor` | Cheap-signal sweeps per (evidence × domain). Emits leads to `./analysis/leads.md`. |
| 3 Investigate | `dfir-investigator` | One lead per invocation, parallel waves of up to 4. Writes `./analysis/<domain>/findings.md`. |
| 4 Correlate | `dfir-correlator` | Cross-domain reasoning across timestamps, users, hosts, hashes, IPs. Writes `./analysis/correlation.md`. |
| 5 Report | `dfir-reporter` | Writes `./reports/final.md` and `./reports/stakeholder-summary.md`. |
| 6 QA | `dfir-qa` | Verifies numerical claims, enforces lead-status invariants, applies fixes, writes `./reports/qa-review.md`. |

The intake interview is the one place the orchestrator pauses for
operator input. Every other phase runs autonomously — when blocked,
the agent picks the most reasonable path and notes it.

## 7. Resume a case

`/case case01` is idempotent. A second invocation reads the workspace
state and starts at the lowest-remaining phase:

| State | Resumes at |
|-------|-----------|
| `analysis/manifest.md` missing | Phase 1 |
| `analysis/leads.md` missing | Phase 2 |
| Any lead `in-progress` | Reset to `open`, re-enter Phase 3 |
| `analysis/correlation.md` missing | Phase 4 |
| `reports/final.md` missing | Phase 5 |
| `reports/qa-review.md` missing | Phase 6 |

Append-only chain-of-custody files (`leads.md`, `findings.md`,
`correlation.md`, `forensic_audit.log`) are never truncated on
resume.

## 8. Read the output

```bash
less ./cases/case01/reports/stakeholder-summary.md   # business-decision briefing
less ./cases/case01/reports/final.md                 # technical case report
less ./cases/case01/reports/qa-review.md             # QA verdict
less ./cases/case01/analysis/correlation.md          # cross-domain reasoning
cat  ./cases/case01/analysis/leads.md                # leads queue
cat  ./cases/case01/analysis/forensic_audit.log      # full chain of custody
ls   ./cases/case01/analysis/*/findings.md           # per-domain findings
```

A case is CLOSED when all five gates pass: intake fields populated,
every lead in terminal status, per-domain baseline artifacts present,
QA pass produced, final + stakeholder reports present.

## 9. Validate before sign-off

`VALIDATION.md` is the human-reviewer protocol. Run it on every case
before signing off — provenance & integrity gates, reasoning trail,
numerical reconciliation, headline-assertion checks, cross-document
consistency, negative-space review. The orchestrator is a triage
and acceleration aid; final interpretation and reporting belong to
the human investigator.

## 10. Calibrate against the worked example

```bash
gh release download sample-data-v1 --repo jtinney/ai-forensicator \
    --pattern 'CFREDS-Sample.zip' --dir ./examples/
unzip ./examples/CFREDS-Sample.zip -d ./cases/
less ./cases/case10/reports/final.md
```

The bundle is a complete six-phase run against the public NIST CFREDS
DFIR_AB image. Every check in `VALIDATION.md` has been verified
against it — use it as the "what good looks like" baseline when
reviewing a live case.

## Single-evidence shortcut

When the case is one evidence item with a narrow question ("did user
X run cmd.exe on host Y at 14:00 UTC?"), phasing is overhead. Route
directly to a domain skill via the table in `CLAUDE.md`, or load
`@.claude/skills/TRIAGE.md` for unguided single-context work.

## Where things live

| Need | Path |
|------|------|
| Operator contract | `CLAUDE.md` |
| Directory map + concept index | `ARCHITECTURE.md` |
| Reviewer validation protocol | `VALIDATION.md` |
| Discipline rules (canonical) | `.claude/skills/dfir-discipline/DISCIPLINE.md` |
| Phase dispatch | `.claude/skills/ORCHESTRATE.md` |
| Bootstrap scripts | `.claude/skills/dfir-bootstrap/` |
| Domain skills | `.claude/skills/{sleuthkit,plaso-timeline,memory-analysis,windows-artifacts,network-forensics,yara-hunting,sigma-hunting}/` |
| Phase agents | `.claude/agents/dfir-{triage,surveyor,investigator,correlator,reporter,qa}.md` |
| `/case` slash command | `.claude/commands/case.md` |
