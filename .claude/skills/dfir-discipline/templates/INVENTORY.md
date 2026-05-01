# Templates & worked-examples inventory

The phase-based pipeline produces several recurring document types. Each
type benefits from a canonical template **and** a worked example that
demonstrates the expected shape. This inventory records which types are
covered, which are not, and the reasoning.

This file is informational — it does NOT enforce anything. The lint scripts
(`lint-survey.sh`, etc.) are the enforcement mechanism. Update this file
whenever a new output type is added or an existing one's structure shifts.

| Output type | Template file | Worked example | Lint script | Status | Notes |
|---|---|---|---|---|---|
| `survey-EV<NN>.md` (Phase 2) | `dfir-discipline/templates/survey-template.md` | `<domain>/reference/example-survey.md` (×7) | `dfir-bootstrap/lint-survey.sh` | **COVERED (issue #7)** | Six required sections; lint validates structure + canonical lead-ID format |
| `findings.md` entries (Phase 3) | inline in `agents/dfir-investigator.md` step 7 | not extracted | none | **PARTIAL** | 9-field template documented in agent; no standalone file or example. Acceptable today — template is short enough to live in agent prose; investigators don't read a separate file. Re-evaluate if format drift is observed in QA reviews |
| `correlation.md` (Phase 4) | inline in `agents/dfir-correlator.md` step 4 | not extracted | none | **PARTIAL** | Four required sections (Entities, Timeline, Narrative, Open questions) documented; no example. Single-author per case (one correlator, one wave) so structural variance is low. Re-evaluate if cross-case audit shows divergence |
| `qa-review.md` (Phase 6) | inline in `agents/dfir-qa.md` step 9 | not extracted | none | **PARTIAL** | Six required sections documented in agent prose. Single author, end-of-case file — same low-variance argument as `correlation.md` |
| `forensic_audit.log` rows | enforced by `dfir-bootstrap/audit.sh` | log itself is the example | `audit.sh` rejects malformed input | **COVERED (mechanical)** | `audit.sh` rejects vague action text and missing fields with exit 3; format is `<UTC> \| <action> \| <result> \| <next>` |
| `manifest.md`, `exports-manifest.md` | written by `case-init.sh` / `audit-exports.sh` | the seeded file is the example | hooks gate writes | **COVERED (mechanical)** | Direct edits denied by `settings.json`; only the bootstrap scripts can write |
| `00_intake.md` | seeded by `case-init.sh` from `intake-interview.sh` answers | seeded blank file | `intake-check.sh` validates field completeness | **COVERED** | Interview script is the template instantiator; `intake-check.sh` is the gate |
| `leads.md` rows | column schema in `ORCHESTRATE.md` § "Leads queue format" | example block in same section | `leads-check.sh` validates terminal status | **COVERED** | Schema documented; lint validates content invariants (terminal status, escalation chains) |

## Decision rationale for the PARTIAL rows

The three "PARTIAL" rows (`findings.md` entries, `correlation.md`,
`qa-review.md`) each have:

1. A documented structure inside the relevant agent prompt.
2. A single author per case (no parallel fan-out — survey was the
   exception, with N parallel surveyors all writing their own
   `survey-EV<NN>.md`).
3. No observed cross-case structural drift in production (case-12 only
   surfaced survey variance, not findings/correlation/qa variance).

Because of (2) and (3), the cost-benefit of extracting a standalone
template file is currently low — the agent prose carries the spec, and
a single author per case has a tight feedback loop (the QA reviewer
catches drift in the same wave). If a future case-audit surfaces
structural variance in any of these documents, promote the inline
spec to a `dfir-discipline/templates/<type>-template.md` file and
write a worked example under the relevant skill's `reference/` dir.

## Adding a new output type

When a future change introduces a new recurring document type:

1. Decide whether parallel fan-out applies (multiple agents writing
   instances). If yes, prioritize template + example + lint, like the
   surveyor flow.
2. If single-author and short, an inline-in-agent prose spec is fine —
   add a row to this inventory with status `PARTIAL` and a re-evaluation
   trigger.
3. If long-form or business-critical, write a template file under
   `dfir-discipline/templates/`, add a worked example under the relevant
   skill's `reference/` directory, and (if structural drift is plausible)
   a lint script under `dfir-bootstrap/`.
4. Update this inventory with the new row.
