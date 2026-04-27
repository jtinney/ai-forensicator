# Blank case template

This directory is the starting point for a new case. To use it:

1. **Pick a case ID.** Free-form (e.g. `INC-2026-042`, `2020JimmyWilson`).
2. **Clone or rename this directory** to match:
   ```bash
   cp -r cases/case-xxxx cases/<CASE_ID>
   ```
3. **Drop evidence** into `cases/<CASE_ID>/evidence/`. The directory becomes
   read-only at the filesystem level once `case-init.sh` runs (chain-of-
   custody enforcement).
4. **Launch orchestration** from the project root:
   ```
   /case <CASE_ID>
   ```
   The slash command `cd`s into `./cases/<CASE_ID>/` and runs the six-phase
   pipeline (triage -> survey -> investigate -> correlate -> report -> QA).

That's the whole workflow. The orchestrator handles preflight, case-init,
intake interview, evidence hashing, scaffolding (`./analysis/`, `./exports/`,
`./reports/`), and the chain-of-custody audit log.

For the manual path (no slash command), see the **Case start** section in
the project root `README.md`.

## What lives here once a case is active

| Path | Owner | Notes |
|------|-------|-------|
| `evidence/` | original artifacts | read-only after case-init; sha256 in `analysis/manifest.md` |
| `analysis/` | tool output, findings, audit log | per-domain subdirs (`network/`, `memory/`, ...) |
| `exports/` | extracted analytic units | carved files, reassembled streams; sha256 in `analysis/exports-manifest.md` |
| `reports/` | human-readable narrative | `00_intake.md`, `final.md`, `stakeholder-summary.md`, `qa-review.md` |

This template directory itself stays empty in git. Per-case `analysis/`,
`exports/`, `reports/` are gitignored; only the case dir and its `evidence/`
placeholder are tracked.
