# Skill: Executive Briefing (non-technical stakeholder report)

Produce a short, decision-focused companion to the technical `final.md`. The
audience is senior business decision-makers: legal, risk, executives, incident
commanders on the non-technical side. They do not need jargon explained —
they need to know what happened, what it means for the organisation, and
what they are being asked to decide.

## When to use

Run once per case, in Phase 5, **alongside** `final.md`. The technical report
is the source of truth; this briefing is a translation layer. Never invent
findings here that aren't in `final.md` / `correlation.md` / `findings.md`.

**Skip for** the technical analyst report (`final.md` is owned by
`dfir-reporter`) or per-domain findings (`./analysis/<domain>/findings.md` is
written by `dfir-investigator`).

## Output

Write `./reports/stakeholder-summary.md`. Target length: 1–2 pages. Never
longer than `final.md`.

## Required sections (in order)

1. **Bottom line** — 2–4 sentences. The single most important sentence first:
   how many systems are compromised, whether impact is quantifiable, what the
   main unknown is. No methodology. No preamble.
2. **Risk posture by system** — one-row-per-system table: system name,
   role/function, status (Compromised — high/medium confidence / Clean /
   Indeterminate), one-line business risk.
3. **Confirmed exposures** — one short paragraph per compromised system.
   Describe what the attacker can do, not how the artifact was detected.
4. **What we cannot answer with the evidence we have** — bullet list of the
   open questions that drive notification, legal, customer-impact, and
   regulatory decisions. Frame as business questions, not technical gaps.
5. **Decisions requested** — numbered list of concrete actions the business
   needs to approve or perform. Each should be actionable by a non-technical
   owner (isolate X, acquire Y, rotate Z, review log W).
6. **Context note** (optional) — one paragraph if the case has characteristics
   worth flagging to the reader that aren't obvious from the technical report
   (e.g. evidence looks like a lab/training set; evidence predates the
   engagement; scope is narrower than requested). Skip if nothing applies.
7. **Confidence summary** — two-column table. Separate assertions we can make
   with confidence from questions the current evidence cannot answer. Write
   "Not determinable from current evidence" explicitly rather than omitting
   or hedging.
8. **Pointer** — one-line reference to `./reports/final.md` for analysts.

## Voice

- **Direct and declarative.** "BATTLESTAR is compromised." Not "It appears
  that BATTLESTAR may have been compromised."
- **Business language, not forensic language.** "Unauthorised remote-access
  capability" not "WinVNC service with DemandStart persistence". "Hidden
  code running inside a trusted system process" not "DKOM-unlinked EPROCESS".
  Never name Volatility plugins, YARA rules, PID numbers, memory addresses,
  or file offsets.
- **No false balance.** If something is clean, say "clean" and move on — do
  not list the things you checked. If something is compromised, do not
  soften it with "potentially" or "appears to be" when the technical report
  is high-confidence.
- **Name what can't be answered.** Gaps that affect business decisions
  (data loss, attacker identity, dwell time, lateral movement) get stated
  as gaps, not hidden.
- **No teaching voice.** Don't explain what memory analysis is or why
  rootkits are bad. The reader either already knows or doesn't need to for
  the decision.

## Things to avoid

- Tool names (Volatility, YARA, Plaso, Sleuth Kit, bulk_extractor, Vol3).
- Technical identifiers (PIDs, VADs, offsets, GUIDs, SIDs, hashes).
- "Phase 1 / Phase 2" or any reference to the internal investigation process.
- Recounting refuted leads in detail. A single line acknowledging that
  false-positive triage happened is fine; a walkthrough is not.
- Passive-voice hedging ("it was determined that", "evidence suggests").
- Recommendations that aren't actionable ("improve security posture",
  "consider reviewing"). Use concrete verbs with a clear owner.

## Translation examples

| Technical finding | Stakeholder wording |
|---|---|
| DKOM-hidden svchost.exe PID 1732 with 4096 handles | Hidden code running under a system-service name, concealed from administrative tools |
| Process hollowing of wmiprvse.exe PID 4080 | A legitimate-looking Windows process has been replaced internally with attacker-controlled code |
| WinVNC 3.x installed as DemandStart service | Remote-control software installed as a permanent service, providing interactive access |
| 12+ RWX anonymous VadS regions in explorer.exe | The desktop process has been modified to carry additional attacker code |
| Vol3 `windows.netscan` NotImplementedError for XP SP2 | We cannot reconstruct network activity from the evidence available |
| No disk image provided | We do not have the underlying storage; data-loss questions cannot be answered |

## Return to orchestrator (≤80 words)

- Pointer to `./reports/stakeholder-summary.md`
- One-line characterisation of the posture (e.g. "2 of 3 systems confirmed
  compromised; data-loss indeterminate without disk evidence")
