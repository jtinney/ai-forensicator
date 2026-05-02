# VALIDATION.md — reviewing and verifying ai-forensicator output

A methodical protocol for a trained DFIR analyst to validate a case
produced by this orchestrator. **AI orchestration is a triage and
acceleration aid; the validation, interpretation, and final reporting
of analysis are the responsibility of the human investigator.** This
document is the inverse of the orchestrator: it tells the human how to
read what the machine wrote and either trust it, correct it, or reject
it.

> See `DISCLAIMER.md` (when added) and the upstream Protocol SIFT
> framing — this tooling is **not validated for forensic soundness or
> evidentiary reliability** and is **not admissible in court** without
> independent validation, documentation review, and peer scrutiny
> consistent with established forensic standards. The phases below are
> the minimum review pass; courtroom-quality validation is a larger
> exercise on top.

The reference example for "here is what a passing case looks like" is
the worked case bundle in the `sample-data-v1` GitHub Release
(`cases/case10/` after extraction — see `examples/README.md`). Every
command in this document has been verified against that case.

---

## What "validation" means here

Three distinct things, often conflated:

| Term | Question it answers | Who can answer it |
|------|--------------------|-------------------|
| **Provenance / integrity** | Is the analyzed bytes the same as the bytes received? Is every action accounted for? | This document — anyone with the case directory can verify. |
| **Reproducibility** | If I re-run the named tool with the named flags, do I get the same number? | This document — analyst with the same toolset. |
| **Forensic soundness** | Would a court accept this as evidence? | Requires formal validation, peer review, and process documentation **outside the scope of this tooling**. |

The protocol below establishes the first two. The third remains the
investigator's professional responsibility.

---

## Before you start

You need:

- The case directory (`cases/<CASE_ID>/`) including `evidence/`,
  `analysis/`, `exports/`, `reports/`.
- The same tool versions that were used to produce the case (compare
  `analysis/preflight.md` against your current `preflight.sh` output).
- Read access to the original evidence (the E01, .pcap, .mem, etc.).
- Time. Plan ~30 min for a small case (one evidence item, <10 leads),
  ~2 hours for a multi-evidence case with full cross-domain
  correlation.

You do **not** need to re-run forensic tools to perform this
validation. The audit log + structured artifacts on disk are the
substrate; you re-grep, re-count, and re-hash, not re-analyze.

---

## Phase A — Provenance & integrity gates

These checks must pass before any finding can be trusted.
A failure here invalidates everything downstream.

### A1. Evidence integrity

The original evidence's sha256 was recorded at intake. Re-hash now and
confirm it matches.

```bash
cd ./cases/<CASE_ID>

# What was recorded?
grep -E '^\| EV[0-9]+ ' analysis/manifest.md \
    | awk -F'|' '{print $7, $4}'    # column 6 = sha256, column 3 = filename

# Re-derive each (one row per top-level evidence item):
sha256sum evidence/*
```

**Pass:** every recorded sha256 matches the live re-hash. **Fail:** any
mismatch is a chain-of-custody break — stop the validation, flag the
case as compromised, do not proceed.

For bundle members (e.g., a zip expanded under
`working/`), the manifest carries one `bundle-member` row
per file. Spot-check at least 5 random members:

```bash
shuf -n 5 <(grep -E '^\| EV[0-9]+-M[0-9]+ ' analysis/manifest.md) \
    | awk -F'|' '{print $7, $4}'
# Re-hash each named file under working/
```

### A2. Audit-log integrity

The audit log is append-only and hook-protected, but a thorough
reviewer verifies independently. Run the offline checker:

```bash
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/audit-retrofit.sh" \
    analysis/forensic_audit.log
less analysis/audit-integrity.md
```

**Pass:** verdict line reads *"No structural integrity violations
detected."* **Fail-investigate:** any of these in the report —

- ISO-8601 `T...Z` timestamps (audit.sh emits `YYYY-MM-DD HH:MM:SS UTC`;
  the wrong format means a direct write that bypassed audit.sh)
- Same-second clusters ≥ 4 rows (multiple actions stamped at the same
  second — possible synthetic batch)
- Non-monotonic backwards jumps > 60 s (a row dated before its
  predecessor — possible backdating)
- Unparseable rows

For each integrity violation, locate the corresponding row, read the
action it claims to describe, and decide whether to (a) accept (e.g.,
hook double-fire is benign noise) or (b) downgrade related findings.
Rule of thumb: if the suspect rows fall in the audit window of an
investigator that produced a load-bearing finding, downgrade that
finding's confidence by one grade until you can re-derive it.

### A3. Discipline self-attestation

Every phase agent appends `discipline_v1_loaded` to its first audit
entry. Confirm every phase that ran left its marker:

```bash
grep -c discipline_v1_loaded analysis/forensic_audit.log
grep    discipline_v1_loaded analysis/forensic_audit.log \
    | awk -F'|' '{print $2}' | sort -u
```

**Pass:** at minimum one marker per agent invocation that ran
(triage, surveyor × N, investigator × N, correlator, reporter, qa).
**Fail-investigate:** missing marker for an agent whose findings
appear in the report — that agent skipped its discipline preamble and
its work warrants a closer read.

### A4. Exports integrity

Extracted analytic units (carved files, reassembled streams, dumped
processes) are hashed at write time by the `audit-exports.sh`
PostToolUse hook. Verify a sample didn't mutate.

```bash
# Pick 3 extracted files at random and re-hash them.
shuf -n 3 <(grep -E '^\| \./exports/' analysis/exports-manifest.md \
            | awk -F'|' '{print $2, $4}')
# Re-derive each.
```

Look at every `MUTATED` row in `exports-manifest.md` and decide:
benign re-derivation (e.g., a tool re-ran and produced the same logical
artifact under the same path) vs. real chain-of-custody concern.

### A5. Intake completeness

Chain-of-custody fields are not optional.

```bash
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/intake-check.sh"
```

**Pass:** exit 0 with `intake-check: PASS — all required fields
populated`. **Fail:** the case was signed off without a complete
intake — the gates were bypassed. Treat the case as draft until
intake is filled in.

---

## Phase B — Reasoning-trail gates

These checks confirm the orchestrator's discipline contracts held.

### B1. Lead terminal-status invariant

```bash
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/leads-check.sh"
```

**Pass:** every lead is `confirmed`, `refuted`, or in a documented
non-blocking state (`open` low priority with notes; `blocked` with
external-dependency notes). **Fail:** in-progress rows mean an
investigator died mid-run; escalated parents with terminal children
mean the parent's hypothesis was answered through the child but the
parent never transitioned. Both warrant either re-dispatching the
lead or transitioning the parent before trusting the report.

### B2. Per-domain baseline artifacts

For every domain that produced findings, verify the surveyor created
the structural baseline artifacts the skill contract requires:

```bash
for d in filesystem timeline windows-artifacts memory network yara sigma; do
    if [[ -f "analysis/${d}/findings.md" ]]; then
        echo "=== ${d} ==="
        bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/baseline-check.sh" "${d}"
    fi
done
```

**Pass:** every domain returns `"missing":[]`. **Fail:** any missing
required-tier-1 artifact means the surveyor skipped a baseline; later
investigator findings in that domain may be operating on incomplete
structural context. Consider the affected domain's findings
provisional until the gap is filled.

### B3. Lead → findings correspondence

Every lead with a terminal status should have a findings entry that
cites it.

```bash
# Confirmed/refuted lead IDs:
awk -F'|' '/^\| L-/ && ($7 ~ /confirmed|refuted/) {print $2}' \
    analysis/leads.md | tr -d ' '

# Findings entries should reference each:
for lid in $(awk -F'|' '/^\| L-/ && ($7 ~ /confirmed|refuted/) {print $2}' \
             analysis/leads.md | tr -d ' '); do
    hits=$(grep -rl -- "${lid}" analysis/*/findings.md 2>/dev/null)
    [[ -z "$hits" ]] && echo "ORPHAN LEAD: ${lid}"
done
```

**Pass:** every confirmed/refuted lead has at least one findings
entry that names it. **Fail:** orphan leads mean the lead's status
was set without a documented investigation — the assertion has no
audit trail.

### B4. Findings → authoritative-artifact correspondence

Every findings entry should cite an artifact path under
`analysis/`, `exports/`, or `evidence/`. Spot check 3 random entries
and verify:

```bash
grep -h '^- \*\*Artifacts reviewed:' analysis/*/findings.md | shuf -n 3
# For each cited path, confirm:
#   - it exists
#   - the line/row referenced actually says what the finding claims it says
```

**Pass:** every cited artifact exists and the cited content matches
the claim. **Fail:** dangling pointers or content that doesn't say
what the finding claims it says are the highest-severity validation
failures — the AI fabricated or misread evidence. Every finding from
that investigator now needs independent re-derivation.

---

## Phase C — Numerical reconciliation

Take every load-bearing number in the case (counts, byte volumes,
timestamps, victim/host counts, hash values) and re-derive it from
the authoritative source.

### C1. Build the number list

```bash
# Pull every number-shaped substring from the headline reports.
grep -ohnE '\b[0-9][0-9,]{2,}\b|\b[0-9]+\s*(MB|GB|alerts|hosts|files|frames|requests|connections)\b' \
    reports/final.md reports/stakeholder-summary.md analysis/correlation.md \
    | sort -u
```

For each, identify (a) the authoritative source artifact and (b) the
re-derivation command. Examples:

| Claim shape | Authoritative source | Re-derive |
|-------------|---------------------|-----------|
| "N Suricata alerts" | `analysis/network/suricata/eve.json` | `jq -c 'select(.event_type=="alert")' eve.json \| wc -l` |
| "N unique destinations" | `analysis/network/zeek/conn.log` | `zeek-cut id.resp_h < conn.log \| sort -u \| wc -l` |
| "N timeline events in window X" | Plaso CSV under `analysis/timeline/` | `awk -F, '$1>="X-start" && $1<="X-end"' \| wc -l` |
| "sha256 = abc..." | the cited file under `evidence/` or `exports/` | `sha256sum <file>` |
| "first/last connection at T" | `analysis/network/zeek/conn.log` | `zeek-cut ts \| sort -n \| head/tail -1`, convert epoch |
| "N hosts compromised" | enumerated finding rows | manual count, cross-checked against `analysis/manifest.md` `EV` rows |

**Pass:** every cited number re-derives within rounding. **Fail:**
mismatches must be reconciled before the report is trustworthy. If
the QA agent already ran (`reports/qa-review.md` exists), check
whether QA caught the mismatch — but verify QA's correction
independently.

### C2. Per-actor / per-victim accounting

A common QA-stage failure mode is row-swap (counts on one actor's row
that actually belong to another). For every per-actor table in
`final.md` and `stakeholder-summary.md`:

```bash
# Sanity: do row counts in stakeholder-summary roll up to the per-actor
# numbers in final.md? Do the per-actor numbers in final.md sum from
# the per-finding entries in correlation.md?
```

**Pass:** roll-ups consistent in both directions (stakeholder roll-up
sums from final; final sums from correlation; correlation entries
trace to per-domain findings). **Fail:** any inconsistency requires
re-derivation from the authoritative substrate, not just averaging
the disagreeing values.

---

## Phase D — Headline-assertion validation

The `final.md` Executive Summary contains the headline assertions —
the things that, if wrong, would mislead a stakeholder. For each
headline assertion:

1. Locate the assertion sentence in `final.md`.
2. Trace it to the supporting findings entry/entries (each finding row
   should carry a per-row Confidence grade per the
   `exec-briefing` rubric).
3. Trace each supporting finding to the cited artifact path.
4. Open the artifact at the cited line/row and confirm the claim.
5. Check whether the assertion is also in `correlation.md` and
   `stakeholder-summary.md`. If the wording diverges between
   documents, decide whether the divergence changes meaning.

```bash
# Extract executive-summary assertions:
sed -n '/^## Executive [Ss]ummary/,/^## /p' reports/final.md | head -40

# Extract per-finding confidence grades:
grep -hE '\bConfidence\b' analysis/*/findings.md | sort -u
```

**Pass:** every headline assertion traces to a confirmed finding (not
"escalated", not "open") with a HIGH or MEDIUM confidence grade per
the per-row rubric, and the wording is consistent across `final.md`,
`stakeholder-summary.md`, and `correlation.md`. **Fail-downgrade:**
any headline backed only by LOW-confidence findings, or contradicted
between documents, must be reworded or removed.

### D1. Forbidden phrases (global confidence collapse)

The reporter is supposed to self-check this; verify independently.
A single global confidence claim ("Overall Confidence: HIGH")
collapses per-finding nuance and is forbidden.

```bash
grep -nE '^\s*\*?\*?(Overall )?Confidence\*?\*?\s*[:\-]\s*(HIGH|MEDIUM|LOW)\b' \
    reports/final.md reports/stakeholder-summary.md
```

**Pass:** every match sits inside a per-finding row or per-assertion
bullet. **Fail:** any standalone global confidence claim collapses
the per-finding evidence — rewrite as a posture line ("majority HIGH;
two MEDIUM on extrapolation") or remove.

### D2. Stakeholder-summary truth-test

`stakeholder-summary.md` is written for non-technical decision makers;
it must not introduce assertions absent from `final.md`.

```bash
# Pull noun phrases / claims from each; manually compare.
diff <(sed -n '/^## /,/^---$/p' reports/stakeholder-summary.md) \
     <(sed -n '/^## Executive/,/^## /p'      reports/final.md) | head -60
```

**Pass:** every stakeholder claim has a corresponding (and stronger,
artifact-cited) claim in `final.md`. **Fail:** a stakeholder-only
claim is the AI inventing — strike it.

---

## Phase E — Cross-document consistency

Reconcile the four headline documents pairwise:

| Pair | What to check |
|------|---------------|
| `correlation.md` ↔ `final.md` | Every entity / cluster / timeline event in `correlation.md` is reflected in `final.md`; the directionality is correlation → final, not the other way. |
| `final.md` ↔ `stakeholder-summary.md` | Every claim in stakeholder is a translation of a final.md claim; no new assertions. |
| `leads.md` ↔ `correlation.md` | Every confirmed lead is referenced (directly or via its domain finding) in correlation. Leads marked `escalated` should have a child lead and the parent should now be terminal. |
| `qa-review.md` ↔ everything | The QA agent's "Changes applied" section should be reflected in the current state of the docs. |

```bash
# Eyeball pass; also:
sed -n '/Changes applied:/,/Lead-status transitions:/p' reports/qa-review.md
# For each Edit listed, open the named file:line and confirm the
# corrective state matches the QA description.
```

---

## Phase F — Negative-space review

What's not in the case is often as important as what is.

| Question | Where to look | Why |
|----------|--------------|-----|
| Are there `RED` skills in `preflight.md` whose domain still produced findings? | `analysis/preflight.md` § Per-skill readiness vs. `analysis/<domain>/findings.md` presence | A RED skill that still produced output may have used a fallback parser; verify the fallback's coverage is acknowledged. |
| Are there evidence items in `manifest.md` with no surveyor coverage? | `manifest.md` rows vs. `analysis/<domain>/survey-EV*.md` files | Uncovered evidence is a coverage gap. |
| Are there `blocked` leads with real external dependencies still unresolved? | `leads.md` rows where `status=blocked` | These are honest gaps; surface to the user. |
| Are there `open` low-priority leads whose justification is weak? | `leads.md` notes column on low-priority opens | "Out of scope" is fine; "ran out of time" is a coverage gap. |

---

## Sign-off checklist

Validation is complete when **every box** below is checked.

```
PROVENANCE & INTEGRITY
[ ] A1  Evidence sha256 re-hash matches manifest for every EV row
[ ] A1  Bundle-member spot-check (5 random) matches manifest
[ ] A2  audit-retrofit.sh: no structural integrity violations
[ ] A3  Every phase agent left a discipline_v1_loaded marker
[ ] A4  Exports manifest spot-check: 3 random files match recorded sha
[ ] A5  intake-check.sh: PASS

REASONING TRAIL
[ ] B1  leads-check.sh: PASS
[ ] B2  baseline-check.sh: every domain that produced findings → missing=[]
[ ] B3  No orphan leads (every confirmed/refuted lead has a findings entry)
[ ] B4  3 random findings: cited artifacts exist and content matches claim

NUMERICAL & ASSERTION
[ ] C1  Every load-bearing number re-derives from its authoritative source
[ ] C2  Per-actor / per-victim roll-ups consistent in both directions
[ ] D   Every headline assertion traces to confirmed findings with HIGH/MED grades
[ ] D1  No standalone global confidence claims (per-finding only)
[ ] D2  Stakeholder summary introduces no assertions absent from final.md

CONSISTENCY & COVERAGE
[ ] E   correlation ↔ final ↔ stakeholder ↔ leads ↔ qa-review all reconcile
[ ] F   Negative-space review complete; gaps documented in 00_intake.md
```

If every box is checked, the case has passed independent validation
*as a triage product*. Forensic-soundness validation for evidentiary
use is a separate, larger exercise — see the upstream Protocol SIFT
disclaimers and your jurisdiction's standards.

---

## When validation fails

Do not silently fix. Do one of:

1. **Edit findings/correlation/final/stakeholder docs** to reflect the
   corrected state, citing the validation step that surfaced the
   issue. Treat this exactly like the Phase 6 QA agent's authority —
   reconciliation only, never new analysis. Append your edits to
   `forensic_audit.log` via `audit.sh` so the validation pass is
   itself part of the chain of custody.
2. **Re-dispatch a focused investigator wave** for a finding that
   fails Phase B4 or D — the AI's claim wasn't supported by the
   artifact it cited.
3. **Reject the case** if Phase A integrity gates fail. A
   chain-of-custody break is not a content issue; it invalidates
   everything downstream.

Record the validation-pass outcome at the bottom of
`reports/qa-review.md` (or in a new `reports/validation.md` if QA
already signed off): verdict, reviewer name, UTC timestamp, list of
checks that failed and what was done about each.

---

## Reference: the worked example

The `case10/` bundle in the GitHub Release `sample-data-v1` is a
complete pass through this validation protocol. Use it to calibrate
"what good looks like":

```bash
# Once extracted under cases/case10/ (see examples/README.md):
cd ./cases/case10

# A1 — the manifest has one EV01 row for the disk image. Re-hash it.
sha256sum evidence/2020JimmyWilson.E01

# A2 — run the offline audit checker.
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/audit-retrofit.sh" \
    analysis/forensic_audit.log

# A3 — discipline marker count.
grep -c discipline_v1_loaded analysis/forensic_audit.log

# B1 — leads invariant.
bash "${CLAUDE_PROJECT_DIR}/.claude/skills/dfir-bootstrap/leads-check.sh"

# Then read reports/qa-review.md to see what the QA agent already
# caught, and use that as the floor for your own pass.
```

If you find a check this protocol misses, the worked case fails it,
or a step is unclear — open an issue. Validation is the part of the
workflow that has to be right, and this document is the place to
sharpen it.
