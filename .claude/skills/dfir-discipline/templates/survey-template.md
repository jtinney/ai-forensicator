<!--
  ============================================================================
  Survey Template — `./analysis/<DOMAIN>/survey-EV<NN>.md`
  ============================================================================
  How to use:
    1. The dfir-surveyor agent instantiates this skeleton once per
       (evidence_id × domain) pair. Copy this file to
       `./analysis/<DOMAIN>/survey-EV<NN>.md` and fill in every field.
    2. The six headings below (Header / Tools run / Findings of interest /
       Lead summary table / Negative results / Open questions) are REQUIRED
       and must appear in this order. The lint script
       `.claude/skills/dfir-bootstrap/lint-survey.sh` enforces them.
    3. Replace every `<...>` placeholder. Do NOT ship a survey that still
       contains literal `<placeholder>` strings — the lint will fail.
    4. Keep the surveyor budget in mind: the survey reports the cheap-signal
       passes ONLY. Investigators consume the leads in Phase 3; do not
       deep-dive here.
    5. Lead IDs in this file MUST follow the canonical format
       `L-EV<NN>-<domain>-<MM>` (e.g. `L-EV01-network-01`,
       `L-EV02-windows-artifacts-03`). Domain segment is lowercase,
       hyphenated. The investigator escalation suffix `-eNN` is reserved
       for Phase-3 escalations and MUST NOT appear in a survey.
    6. Negative results matter. An explicit "we ran X and saw nothing"
       row tells the next investigator NOT to re-run that pass; without
       it, they will redo the work and waste budget.
    7. The HTML comments in this template are guidance for the surveyor.
       Leave them in place when the file is checked in, or strip them —
       the lint is comment-tolerant.
  ============================================================================
-->

# Header

<!--
  Required fields below. The lint script tests for the presence of each
  field name on its own line (case-sensitive). Use UTC timestamps in the
  format `YYYY-MM-DD HH:MM:SS UTC` so they sort lexicographically and
  match `audit.sh`'s wall-clock format.
-->

- **Case ID:** `<CASE_ID>`
- **Evidence ID:** `<EV_ID>`           <!-- e.g. EV01 -->
- **Evidence sha256:** `<sha256>`      <!-- copy from analysis/manifest.md -->
- **Domain:** `<domain>`               <!-- one of: filesystem, timeline, windows-artifacts, memory, network, yara, sigma -->
- **Surveyor agent version:** `dfir-surveyor / discipline_v2_loaded`
- **UTC timestamp:** `<YYYY-MM-DD HH:MM:SS UTC>`

## Tools run

<!--
  Bullet list of every tool invocation that produced output for this
  survey. Format:
    - `<tool>` -> `<exact invocation>` -> exit `<code>` -> `<output path>`
  Include the cheap-signal passes only (no full-image Plaso, no full
  memmap, no recursive YARA). One line per tool, even if the tool was
  re-run with different args (one line per invocation).
-->

- `<tool>` -> `<invocation>` -> exit `<code>` -> `<output path>`
- `<tool>` -> `<invocation>` -> exit `<code>` -> `<output path>`

## Findings of interest

<!--
  3-5 bullets, ONE LINE EACH. Each bullet is the surveyor's observation
  with a stub lead ID at the end so the lead summary table can reference
  it. Do not draw conclusions; the investigator phase confirms or
  refutes. Pin every claim to an artifact with a line-anchored pointer
  (`<file>#L<n>` or `<file>#L<n>-L<m>`).
-->

- Observation 1 with line-anchored pointer (`<file>#L<n>`). Lead: `L-EV<NN>-<domain>-01`
- Observation 2 with line-anchored pointer. Lead: `L-EV<NN>-<domain>-02`
- Observation 3 with line-anchored pointer. Lead: `L-EV<NN>-<domain>-03`

## Lead summary table

<!--
  Required columns: lead_id | priority | hypothesis | next-step query | est-cost
  Every row MUST use a canonical lead ID matching `L-EV<NN>-<domain>-<MM>`.
  Use `(no leads)` in a single data row if the survey produced none —
  but this is rare; if there are truly no leads, that itself is a
  finding worth raising as `open question`.
  est-cost = wall-clock estimate in seconds/minutes for the next-step
  query, used by the orchestrator for batching.
-->

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV<NN>-<domain>-01` | high | `<one-sentence hypothesis>` | `<concrete query / tool invocation>` | `<~Xs / ~Ymin>` |
| `L-EV<NN>-<domain>-02` | med  | `<one-sentence hypothesis>` | `<concrete query>` | `<estimate>` |

## Negative results

<!--
  Explicit "we ran X and found nothing" lines. The investigator phase
  reads this to avoid redoing the same pass. Format:
    - <pass / tool / question> -> <what was checked> -> no hits.
  If you have NOTHING to say here, write `- (none — every cheap-signal
  pass produced at least one hit)` so the lint sees a populated section.
-->

- `<pass / tool>` -> `<what was checked>` -> no hits in `<output path>`.
- `<pass / tool>` -> `<what was checked>` -> no hits in `<output path>`.

## Open questions

<!--
  Things you observed that fall outside the surveyor's scope but might
  matter to correlation later. Do NOT promote these to leads here — if
  they're worth chasing, the investigator or correlator will surface
  them as `-eNN` or `L-CORR-NN`. Format:
    - <observation>: <why it might matter>.
  If none, write `- (none)`.
-->

- `<observation>`: `<why it might matter for cross-domain correlation>`.
- `<observation>`: `<why it might matter>`.
