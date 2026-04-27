# Worked example case

A complete, signed-off case run end-to-end with this orchestrator,
published as a reference for what the project produces. Browse it to see
what a real `cases/<CASE_ID>/` workspace looks like after all six phases
(triage → survey → investigate → correlate → report → QA) have run.

## Attribution — this is not original work

The underlying disk image is **public reference data published by NIST**,
redistributed here for convenience. Cite the original source in any
derived report.

| Layer | Origin | Source URL |
|-------|--------|-----------|
| Disk image (`evidence/2020JimmyWilson.E01`) | NIST CFREDS — Forensic Image Test Image (DFIR_AB) | <https://cfreds.nist.gov/all/DFIR_AB/ForensicsImageTestimage> |
| Analysis, findings, correlation, reports | Output of this project's six-phase orchestrator running against the NIST image | this repository (`.claude/agents/`, `.claude/skills/`) |

NIST CFREDS data is published by the U.S. National Institute of
Standards and Technology and is in the public domain.

## Distribution

The bundle is ~327 MB — too large for git. It is attached to the
GitHub Release [`sample-data-v1`](https://github.com/jtinney/ai-forensicator/releases/tag/sample-data-v1),
and `examples/*.zip` / `*.tar*` / `*.7z` files are gitignored so a local
copy can sit here without bloating commits.

```bash
gh release download sample-data-v1 \
    --repo jtinney/ai-forensicator \
    --pattern 'CFREDS-JimmyWilson.zip' \
    --dir ./examples/
```

If you only want the original NIST disk image (no project analysis),
download it directly from CFREDS:

```bash
curl -L -o /tmp/2020JimmyWilson.E01 \
    "https://cfreds.nist.gov/all/DFIR_AB/ForensicsImageTestimage"
```

## What's inside

```
case10/
├── evidence/
│   └── 2020JimmyWilson.E01           # NIST CFREDS disk image (309 MB)
├── analysis/
│   ├── forensic_audit.log            # full chain-of-custody trail
│   ├── manifest.md                   # evidence sha256 + bundle members
│   ├── exports-manifest.md           # sha256 of every extracted artifact
│   ├── leads.md                      # surveyor + investigator + correlator leads queue
│   ├── correlation.md                # Phase 4 cross-domain reasoning
│   ├── preflight.md                  # tool inventory at case start
│   └── filesystem/, memory/, network/, sigma/, timeline/, windows-artifacts/, yara/
│       └── findings.md, survey-*.md  # per-domain investigator output
├── exports/                          # extracted analytic units
│   ├── files/, carved/, hives/, mft/, prefetch/, evtx/, recyclebin/,
│   ├── lnk/, amcache/, shimcache/, network/, timeline/,
│   └── yara_hits/, sigma_hits/
└── reports/
    ├── 00_intake.md                  # Phase 1 chain-of-custody intake
    ├── final.md                      # Phase 5 technical case report
    ├── stakeholder-summary.md        # Phase 5 non-technical briefing
    └── qa-review.md                  # Phase 6 QA verdict + corrections
```

(The bundle also includes an inner `.claude/` snapshot of the toolset
used at the time of the run and a `.git/` of the case history. Both are
optional context — delete them if you re-run the case under your own
toolset.)

## How to explore

```bash
# 1. Download and unpack into the project's cases/ directory.
gh release download sample-data-v1 --repo jtinney/ai-forensicator \
    --pattern 'CFREDS-JimmyWilson.zip' --dir ./examples/
unzip ./examples/CFREDS-JimmyWilson.zip -d ./cases/

# 2. Read the headline outputs first.
less ./cases/case10/reports/stakeholder-summary.md   # business-decision briefing
less ./cases/case10/reports/final.md                 # technical case report
less ./cases/case10/reports/qa-review.md             # QA verdict + corrections
less ./cases/case10/analysis/correlation.md          # cross-domain reasoning

# 3. Inspect the chain of custody.
cat ./cases/case10/analysis/forensic_audit.log       # every action, append-only
cat ./cases/case10/analysis/manifest.md              # evidence sha256
cat ./cases/case10/analysis/exports-manifest.md      # extracted artifacts sha256

# 4. Look at the leads queue and per-domain findings.
cat ./cases/case10/analysis/leads.md
ls  ./cases/case10/analysis/*/findings.md
```

If you want to re-run the case under the current toolset, delete the
inner `.claude/` and `.git/`, then `/case case10` from the project
root — the orchestrator's resume protocol will start at the
lowest-remaining phase.
