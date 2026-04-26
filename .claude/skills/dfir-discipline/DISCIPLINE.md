# DFIR DISCIPLINE — mandatory rules for every phase agent

These four rules apply at every step of every phase agent (`dfir-triage`,
`dfir-surveyor`, `dfir-investigator`, `dfir-correlator`, `dfir-reporter`).
Each rule is bound to one or more specific failure modes observed in
production cases. The rule statement is normative; the **Why** and **How
to apply** lines are the operating context an agent uses to handle edge
cases.

A future audit of the case will grep for `discipline_v1_loaded` to confirm
each agent invocation acknowledged these rules — your first audit-log
entry of every invocation MUST include that marker in the `result` field.

---

## Rule A — Audit-log integrity AND extracted-artifact integrity

### A.1 — `forensic_audit.log` writes go through `audit.sh`

**Every entry to `./analysis/forensic_audit.log` must go through
`bash .claude/skills/dfir-bootstrap/audit.sh "<action>" "<result>" "<next>"`.
Direct `>>` / `tee -a` / `sed -i` / `cp` / `mv` / `python open()` writes
to the audit log are denied at the Claude Code harness level (PreToolUse
hook). Python writes that bypass the hook are caught after the fact by
the PostToolUse drift detector and recorded as `INTEGRITY-VIOLATION` rows.**

**Why:** `audit.sh` stamps the wall-clock UTC timestamp itself (`date -u
+%Y-%m-%d %H:%M:%S UTC`). Direct writes let an agent assert any
timestamp it likes — case7 contained 41 ISO-8601 `T...Z` synthetic
timestamps that fell outside the case's wall-clock window. A chain-of-
custody trail with author-asserted (vs. wall-clock) times will not
survive cross-examination.

**How to apply:**
- The first audit-log entry of every agent invocation MUST include
  `discipline_v1_loaded` somewhere in the `result` field. The orchestrator
  will grep for this marker.
- Never `echo "<UTC>" >> ./analysis/forensic_audit.log` or
  `tee -a ./analysis/forensic_audit.log`. The PreToolUse hook denies
  these patterns with exit code 2.
- Read access (cat / head / tail / grep / Read tool) is unaffected.
- If you find yourself wanting to "back-fill a sequence of audit entries
  with a synthetic timeline," stop. Each audit row is a wall-clock event;
  if you didn't run the action at the time the audit row claims, do not
  write the row at all.

### A.2 — Extracted artifacts under `./exports/` are sha256-tracked

**Every file written under `./exports/` is an *extracted artifact* — a
new analytic unit derived from the original evidence (carved from disk,
reassembled from a network capture, dumped from memory, exported via
`tshark --export-objects` / `tcpflow` / `bulk_extractor` / `photorec` /
`tsk_recover` / `vol windows.dumpfiles`, etc.). Its sha256 must be in
`./analysis/exports-manifest.md` with a `first-seen` row, so a future
examiner can verify they're looking at the same bytes that grounded a
conclusion.**

**Enforcement:** The PostToolUse hook (`audit-exports.sh`) sweeps
`./exports/` after every Bash/Write/Edit and appends rows for new files.
Mutated files (sha256 differs from the prior `first-seen` row) get a
`MUTATED` row — extracted artifacts should be immutable, and a mutation
row is itself a chain-of-custody concern that warrants investigation.

**Why a separate manifest:** `./analysis/manifest.md` tracks *original*
evidence (intake hashes of files in `./evidence/` and bundle members in
`./analysis/_extracted/`). `./analysis/exports-manifest.md` tracks
*derivative* evidence — the chain is layered (original → extracted →
conclusion). Conflating them would lose the layer.

**Distinction from `./analysis/`:**
- `./analysis/<domain>/*.csv`, `*.json`, `*.txt`, `*.md` — tool reports
  and summaries. Recomputable from the original evidence by re-running
  the tool. NOT hashed (no integrity ledger needed; source of truth is
  `./evidence/`).
- `./exports/**` — bytes carved/reassembled/dumped FROM the original
  evidence. NEW analytic units. Hashed (via `audit-exports.sh`).

**How to apply:**
- When you extract an artifact (any tool that writes to `./exports/`),
  the PostToolUse hook auto-hashes it. You don't need to hash manually.
- After a deliberate extraction, also write an `audit.sh` row that names
  the source artifact and the export destination, so chain-of-custody
  links extract-from to extract-to:
  `bash audit.sh "tshark --export-objects" "extracted 12 HTTP objects from EV01 stream 47" "yara sweep next"`
- Never write to `./analysis/manifest.md` or
  `./analysis/exports-manifest.md` directly — both are denied at the
  permission layer. Bundle expansion writes to `manifest.md` via case-init;
  exports are written by `audit-exports.sh`.
- A `MUTATED` row in `exports-manifest.md` means an extracted file was
  overwritten. Investigate why — a re-extraction with a different tool
  version may legitimately produce different bytes (and warrants a new
  row, not a mutation), or it may indicate a workflow bug or evidence
  tampering.

---

## Rule F — Hypothesis-first / cheapest-disconfirmation-first
**(binds: dfir-investigator)**

**Before any deep parse, write the hypothesis as one sentence and list
2–3 cheapest disconfirmation queries. Run the cheapest first. Reverse
engineering, disassembly, manual memory mapping, and >100K-frame scans
are allowed only after wire-level (`tshark -Y` follow / `tcpflow`),
artifact-level (`yara -i <rule> -s`), and structural-level (`zeek-cut`,
`jq` over `eve.json`) queries return a result that does NOT refute the
hypothesis.**

**Why:** Case7's L-EV01-yara-03-yara-e01 spent disassembly, 256-key XOR
brute-force, and 200K-frame post-exploit scan to refute the hypothesis
that a NOP-sled exploit produced a shell. The cheap disconfirmation —
"did the victim ever initiate an outbound connection or open a new
listener after the exploit timestamp?" — is a 30-second `tshark -Y`
query and would have refuted the lead immediately.

**How to apply:**
- The findings entry for the lead MUST start with the hypothesis as one
  sentence, then list the disconfirmation queries planned in cheapest-
  first order.
- "Cheap" = under 60 seconds wall-clock; "structural" = uses already-
  generated baseline artifacts (Zeek logs, Suricata eve.json, capinfos);
  "deep" = produces new derivative data (full Plaso run, full memmap
  dump, recursive YARA on the whole image, shellcode disassembly).
- If the cheap queries refute the hypothesis, mark `status=refuted` and
  STOP. Do not continue to deep queries to "make sure."
- If the cheap queries support but do not confirm, escalate as `-eNN`
  rather than running the deep query yourself — the deep query is a
  separate lead with its own pivot.

---

## Rule G — Scope closure discipline
**(binds: dfir-correlator)**

**Anomalies surfaced during correlation that, if resolved differently,
would change a headline assertion (cluster boundary, exploit success,
attribution, scope, kill-chain link) MUST become an `L-CORR-<NN>` lead at
priority `high`. They may NOT be moved to "Remaining unknowns / out of
scope." The test: if reversing the assumption flips a headline
assertion in the report, it is in scope.**

**Why:** Case7's correlator left the `dc19:c7f:2011:80::10:7777`
anomaly under "out of scope" even though it directly contradicted the
"address-agnostic spraying" characterization the report relies on.
Same with the "Cluster B = scoreboard" alternative hypothesis: the
report concluded "same team" without testing the strongest competing
hypothesis, which would invert the central attribution claim.

**How to apply:**
- Apply the test to every entry you're about to put under "out of
  scope" / "remaining unknowns": *if I assume the opposite resolution,
  does any headline change?* If yes → `L-CORR-<NN>` lead, priority
  `high`, status `open`. If no → it can go in OOS.
- Specific anti-patterns you must NOT do:
  - "Out of scope: total flag count" when the report claims a
    quantitative impact bound. The bound IS the headline; refining the
    count is in scope.
  - "Out of scope: alternative attribution" when the report attributes a
    cluster to a single team. Attribution is the headline; competing
    hypotheses are in scope.
  - "Out of scope: this anomaly does not fit our narrative." If your
    narrative requires the anomaly to not exist, the narrative is on
    trial — open the lead.

---

## Rule H — Exhaust the lead's surface
**(binds: dfir-investigator + dfir-correlator handoff)**

**A lead is "exhausted" only when its hypothesis is conclusively
confirmed/refuted AND every same-domain natural follow-up question is
either answered or escalated as an `-eNN` lead. The investigator's
findings entry MUST include an `**Adjacent surface checked:**` field
listing what same-domain follow-ups were considered. The correlator
must reject any "gap" that reads like missed Phase-3 surface and
escalate it back as a re-run lead, not absorb it as `L-CORR-*`.**

**Why:** Case7 wave-4 correlation surfaced six `L-CORR-*` leads, three
of which (`L-CORR-02` per-stream Meterpreter outcome enumeration,
`L-CORR-03` flag-harvester recovery, `L-CORR-06` parallel vs sequential
delivery) were squarely investigator-domain Phase-3 questions. The
investigators on the original leads answered the narrow hypothesis but
did not enumerate the obvious adjacent surface; the correlator paid for
that by running a second wave to fill the gap.

**How to apply:**
- Findings template gains a required field:
  ```
  **Adjacent surface checked:**
  - <Q1>: <answered / escalated as -eNN / out of domain>
  - <Q2>: <answered / escalated as -eNN / out of domain>
  ```
- "Same-domain natural follow-up" = the next question a working analyst
  would obviously ask given the artifact in front of them. For network:
  if you confirmed an exploit hit one host:port, the adjacent surface
  is the same exploit's reach across other host:port pairs in the same
  capture. For YARA: if you confirmed a rule fires in one PCAP, the
  adjacent surface is rule-fire timing/clustering across all PCAPs.
- The correlator: when constructing an `L-CORR-<NN>`, ask "should this
  have been a `-eNN`?" If yes, write the lead but flag it
  `re-investigator-surface=true` so the orchestrator knows the wave-3
  agents missed it.

---

## Rule B — Headline / table revalidation
**(binds: dfir-correlator wave-2+)**

**On any wave-2+ correlation pass, BEFORE rewriting the narrative, diff
every `L-CORR-<NN>` audit-log entry produced after wave-1 against the
headline tables in `correlation.md`. Any timestamp, attribution,
cluster boundary, or outcome the audit log corrected MUST be back-
ported into the tables (Cluster table, Unified Timeline, Cross-Finding
Matrix). Add an explicit "Wave-2 revalidation diff" subsection that
lists each amended cell and the audit-log line that justifies it.**

**Why:** Case7 audit log line 77 corrected Cluster C's exploit
timestamp from `11:37:21.734` to `11:40:41`; the L-CORR-04 wave-4
delta noted the correction in prose but did not back-port it into the
"Unified Attack Timeline" table at line 54 of `correlation.md`. The
final report uses the corrected `11:40:41`, but a reader who consults
`correlation.md` without scrolling to the delta gets the wrong time.
Headline tables are load-bearing; they cannot lag the audit trail.

**How to apply:**
- For every `L-CORR-<NN>` entry the audit log produced after the wave-1
  correlation timestamp, search the headline tables for the cells that
  match (timestamp, IP, host, hash, port). Rewrite the cell. Note the
  rewrite in the new "Wave-2 revalidation diff" subsection at the top of
  `correlation.md`, citing the audit-log line number.
- If a rewrite would break a downstream conclusion, that's a chain — the
  conclusion's narrative paragraph also needs an update, not just the
  table cell.
- Never delete the original cell silently; either rewrite in place
  (table is the canonical view) AND log the diff, or strike through and
  add a follow-up row. Either is auditable.

---

## Cross-rule notes

- The DISCIPLINE.md path is referenced from each agent's frontmatter as
  `MANDATORY` — the agent harness does not enforce reading; the marker
  `discipline_v1_loaded` is the self-attestation signal.
- The PreToolUse / PostToolUse hooks enforce Rule A mechanically. Rules
  F / G / H / B are agent-prompt-level discipline; they are caught after
  the fact by audit-log review and by the orchestrator's wave-2 logic.
- When in doubt about whether a borderline item is in scope (G) or
  whether the surface is exhausted (H), prefer the more conservative
  (in-scope / not-exhausted) choice. The cost of an extra lead is one
  investigator wave; the cost of a missed scope-flip is the case's
  conclusion.
