# DFIR DISCIPLINE — mandatory rules for every phase agent

These rules apply at every step of every phase agent (`dfir-triage`,
`dfir-surveyor`, `dfir-investigator`, `dfir-correlator`, `dfir-reporter`,
`dfir-qa`). Each rule is bound to one or more specific failure modes
observed in production cases. The rule statement is normative; the
**Why** and **How to apply** lines are the operating context an agent
uses to handle edge cases.

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

### Layer model — what lives where, and why each layer's ledger is distinct

The case workspace `./cases/<CASE_ID>/` has **five layers**, each with a
distinct mutability and integrity contract. Rule A.2 (below) is the
mechanical enforcement for Layer 4; the other layers' contracts are
documented here so an agent can answer "where does this file go?"
deterministically without consulting the project README.

| # | Layer | Path | Origin | Mutability | Integrity ledger | Hook |
|---|-------|------|--------|------------|------------------|------|
| 1 | Original evidence | `./evidence/` | Operator drop at intake | Read-only after intake (`chmod a-w` recursive) | `analysis/manifest.md` | Permission deny + filesystem lock |
| 2 | Bundle expansion | `./working/<bundle>/` | `case-init.sh` expanding archives at intake | Read-only by convention | `analysis/manifest.md` (`bundle-member` rows) | None — manifest-locked at write-once intake |
| 3 | Tool reports | `./analysis/<domain>/` | Surveyor + investigator output (CSVs, JSON, `findings.md`, `survey-EVnn.md`) | Mutable (recomputable) | None — by design | audit-log hooks only |
| 4 | Derived artifacts | `./exports/<domain>/...` | Carved bytes, exported hives, dumped memory regions, sliced pcaps, reassembled HTTP objects | Write-once; mutation = chain-of-custody concern | `analysis/exports-manifest.md` | `audit-exports.sh` PostToolUse, depth-unbounded |
| 5 | Reports | `./reports/` | Final deliverables (`final.md`, `stakeholder-summary.md`, `qa-review.md`, `00_intake.md`) | Mutable | None | None |

**Decision rule when an agent writes a file:** is the file's *byte
sequence* the analytic unit, or is the file a *summary* of bytes that
live elsewhere? Bytes go to `./exports/`. Summaries (CSV, JSON,
markdown) go to `./analysis/`. Layer 2 is the only place inside
`./analysis/` where bytes legitimately live, and only because they came
from layer 1 at intake (manifest-tracked as bundle members) and never
moved.

**Why layer 2 is NOT under `./exports/`:** bundle members are *original*
evidence — the bytes the operator delivered, just unpacked from a
container. They are tracked by `manifest.md` (the original-evidence
ledger), not `exports-manifest.md` (the derivative-artifact ledger).
Putting them under `./exports/` would double-track them, collapse the
layers, and make the path ambiguous about whether a file is operator-
supplied evidence or agent-derived artifact.

---

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
`./working/`). `./analysis/exports-manifest.md` tracks
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

**Why:** Case7's correlation pass surfaced six `L-CORR-*` leads, three
of which (`L-CORR-02` per-stream Meterpreter outcome enumeration,
`L-CORR-03` flag-harvester recovery, `L-CORR-06` parallel vs sequential
delivery) were squarely investigator-domain Phase-3 questions. The
investigators on the original leads answered the narrow hypothesis but
did not enumerate the obvious adjacent surface; the correlator paid for
that by triggering an additional Phase-3 investigation wave to fill the
gap.

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
  `re-investigator-surface=true` so the orchestrator knows the prior
  Phase-3 investigators missed it and routes it to a focused
  investigation wave rather than absorbing it as correlation work.

---

## Rule B — Headline / table revalidation
**(binds: dfir-correlator on every iteration after the first)**

**On any correlation pass where `./analysis/correlation.md` already
exists, BEFORE rewriting the narrative, diff every `L-CORR-<NN>`
audit-log entry produced since the prior correlation pass against the
headline tables in `correlation.md`. Any timestamp, attribution,
cluster boundary, or outcome the audit log corrected MUST be back-
ported into the tables (Cluster table, Unified Timeline, Cross-Finding
Matrix). Add an explicit "Since-last-correlation revalidation diff"
subsection that lists each amended cell and the audit-log line that
justifies it.**

**Why:** Case7 audit log line 77 corrected Cluster C's exploit
timestamp from `11:37:21.734` to `11:40:41`; the L-CORR-04 delta
noted the correction in prose but did not back-port it into the
"Unified Attack Timeline" table at line 54 of `correlation.md`. The
final report uses the corrected `11:40:41`, but a reader who consults
`correlation.md` without scrolling to the delta gets the wrong time.
Headline tables are load-bearing; they cannot lag the audit trail.

**How to apply:**
- The diff is keyed off the prior `correlation.md`'s contents and the
  audit log's timestamp ordering — the correlator does not need an
  iteration-counter argument from the orchestrator. If `correlation.md`
  is absent, this is the first pass and the rule does not apply.
- For every `L-CORR-<NN>` entry the audit log produced after the prior
  correlation pass's timestamp (read from
  `./analysis/correlation-history.md` or the file mtime of
  `correlation.md`), search the headline tables for the cells that
  match (timestamp, IP, host, hash, port). Rewrite the cell. Note the
  rewrite in the new "Since-last-correlation revalidation diff"
  subsection at the top of `correlation.md`, citing the audit-log line
  number.
- If a rewrite would break a downstream conclusion, that's a chain — the
  conclusion's narrative paragraph also needs an update, not just the
  table cell.
- Never delete the original cell silently; either rewrite in place
  (table is the canonical view) AND log the diff, or strike through and
  add a follow-up row. Either is auditable.

---

## Rule I — No lead goes un-worked
**(binds: dfir-investigator, dfir-correlator, dfir-qa)**

**Every lead in `./analysis/leads.md` must reach a terminal status before
case close. Acceptable terminal states are `confirmed` and `refuted`.
`escalated` is a transitional state — the parent must transition to
`confirmed` / `refuted` once its direct child is terminal. `open` is
acceptable only at `priority=low` AND with an explicit non-blocking
justification in the row's `notes` column. `blocked` is acceptable only
when `notes` documents a real external dependency. `in-progress` at case
close is always a discipline failure (the investigator died mid-run).**

**Why:** Case8 closed with four `escalated` parents whose children were
all terminal — the parents' own hypotheses had been answered through the
children, but the leads register kept claiming work was still in flight.
A reader scanning leads.md cannot tell whether the case is actually done
or whether some surface was abandoned. The QA pass caught this; the
discipline rule is here so future correlators / reporters / QA agents
catch it earlier.

**How to apply:**
- The orchestrator runs `bash .claude/skills/dfir-bootstrap/leads-check.sh`
  as a gate before Phases 4 (correlation), 5 (report), and 6 (QA). A
  nonzero exit forces a remediation pass.
- Investigators: when your -eNN child closes, always check whether the
  parent's hypothesis was answered. If yes, transition the parent in
  the same edit batch — don't leave the bookkeeping for a later phase.
- Correlator: if leads-check reports violations, return to the
  orchestrator with a blocker rather than pretending the leads queue
  is settled. Do not author a correlation matrix on top of an
  unresolved lead queue.
- QA agent: has authority to transition lingering parents. Cite the
  child's findings entry in the parent's `notes` field as
  justification. Reset stale `in-progress` rows to `open` for
  re-dispatch.

---

## Rule K — MITRE ATT&CK tagging on findings (optional, validated)
**(binds: dfir-surveyor, dfir-investigator, dfir-correlator, dfir-reporter, dfir-qa)**

**Findings entries MAY carry an optional `MITRE:` line that maps the
described adversary behavior to one or more enterprise ATT&CK technique IDs.
The line is OPTIONAL — its absence is not a discipline failure. If present,
every cited ID must (a) match the shape `T####` or `T####.###` and (b) be
present in the offline reference at
`.claude/skills/dfir-bootstrap/reference/mitre-attack.tsv`. The QA phase
validates this with `bash .claude/skills/dfir-bootstrap/mitre-validate.sh
<findings.md>`; the validator exits nonzero on malformed or unknown IDs.
Tagging is analyst-driven — never inferred by tooling.**

**Why:** Free-text descriptions of adversary behavior do not aggregate.
ATT&CK tags let the correlator roll up techniques across evidence items
("all findings of T1021.001 — RDP lateral movement") and let the reporter
produce a per-technique table and a tactics-only stakeholder summary.
Standardized vocabulary also helps SOC / threat-intel readers consume the
case without DFIR-specific phrasing.

**Line shape:** `MITRE:` followed by a comma-separated list of technique
IDs. Each ID may carry an inline tactic + name comment in parentheses. The
line is recognized in any of these markdown shapes — the validator
tolerates them all:

```
- **MITRE:** T1059.001 (Execution — PowerShell), T1027 (Defense Evasion — Obfuscated Files)
- MITRE: T1078, T1078.002
**MITRE:** T1021.001
```

**Worked example (a finding entry with the optional line):**

```
## 2026-04-25 14:12:33 UTC — L-EV01-windows-artifacts-03 — confirmed
- **Hypothesis:** the encoded PowerShell launched at logon staged the C2 dropper.
- **Cheapest disconfirmation queries (in order):** Prefetch hit (pass), Sysmon 1 (pass), Defender quarantine (pass)
- **MITRE:** T1059.001 (Execution — PowerShell), T1027 (Defense Evasion — Obfuscated Files)
- **Artifacts reviewed:** analysis/windows-artifacts/prefetch.csv#L88, analysis/sigma/timeline.csv#L1207
- **Finding:** powershell.exe -enc <b64> spawned by explorer.exe at logon, payload base64 of an HTTPS downloader.
- **Interpretation:** initial-access script staged the dropper minutes after first logon.
- **Confidence:** HIGH
- **Adjacent surface checked:**
    - Did the same parent spawn other encoded scripts?: answered (no)
    - Did the dropper's HTTPS host appear in DNS or Suricata?: escalated as L-EV01-network-e02
- **Next pivot:** L-EV01-network-e02
```

**How to apply:**
- Surveyor: when a survey-pass anomaly already maps obviously to a single
  technique (e.g. a Run-key persistence row → `T1547.001`), include the
  `MITRE:` line on the survey-stub finding. When the mapping is ambiguous,
  leave the line off and let the investigator tag it.
- Investigator: tag the findings entry once the hypothesis is resolved.
  If the mapping requires a sub-technique not present in the TSV, append
  the row to the TSV in the same edit batch — do NOT reach for a vague
  parent ID just to satisfy validation.
- Correlator: aggregate across every `findings.md`. Emit a per-tactic
  rollup section in `correlation.md` even if the section is empty (write
  "No MITRE tags present" rather than omitting the section).
- Reporter: render the technique table in `final.md` and a tactics-only
  bullet list in `stakeholder-summary.md`. Do NOT re-grep findings — use
  the data the correlator aggregated.
- QA: run `mitre-validate.sh` on every `analysis/<domain>/findings.md`.
  Apply Edit-in-place when a typo is fixable (`T1059001` → `T1059.001`,
  `t1078` → `T1078`); list as a finding-error in `qa-review.md` when the
  ID is genuinely unknown.

---

## Rule J — Intake completeness is a precondition
**(binds: dfir-triage, dfir-correlator, dfir-reporter, dfir-qa)**

**`reports/00_intake.md` must have every chain-of-custody field
populated before correlation, reporting, or QA runs. The triage agent
is responsible for completing intake at case open via the interactive
interview. If the harness has no TTY and the operator has not provided
intake values via env vars, triage MUST surface this as a blocker —
not silently proceed with blank fields.**

**Why:** Case8 closed with every chain-of-custody field blank in
`reports/00_intake.md` (Source, Acquired, Received, Evidence hash,
Integrity verification, Reported incident, Analyst priorities). The
underlying scaffolding accepted blank stubs as valid. Without intake,
a future examiner has no idea who authored the case, what they were
asked to find, or how the evidence was acquired — the report cannot
support a chain of custody. **This is the one place agent autonomy
yields to operator input.** The intake interview is exempt from the
"NEVER ask questions" operator preference.

**How to apply:**
- `bash .claude/skills/dfir-bootstrap/intake-check.sh` is a gate at
  Phases 4, 5, and 6. A nonzero exit means STOP and run the interview.
- The interview script (`intake-interview.sh`) reads from `/dev/tty`
  if available; non-TTY mode accepts `INTAKE_*` env vars or writes
  `./analysis/.intake-pending` for the orchestrator to surface.
- Use `n/a — <reason>` (not blank, not `TBD`, not `?`) when a field
  genuinely does not apply. The check rejects placeholders.

---

## Rule L — Multi-evidence path encoding
**(binds: dfir-surveyor, dfir-investigator, dfir-correlator)**

**When more than one evidence item writes into the same
`./exports/<domain>/` subdir, the path MUST encode the originating
evidence ID. Two patterns are allowed; pick by artifact shape, not by
preference.**

1. **Default — EV-suffix in filename.** Use `<artifact>-<EVID>.<ext>`.
   Examples:
   - `exports/network/slices/dns-EV01.pcap`,
     `exports/network/slices/dns-EV02.pcap`
   - `exports/files/cmd-EV01.exe`, `exports/files/cmd-EV02.exe`
   - `exports/yara_hits/ioc-sweep-EV01.txt`
   Keeps the per-domain export dir flat and grep-friendly:
   `find ./exports/network/slices -name 'dns-*.pcap'` produces the
   per-evidence list trivially.

2. **Required exception — directory-tree artifacts.** When the artifact
   is itself a directory (registry hive batch export, MFT + LogFile +
   UsnJrnl trio, `tsk_recover` recovery output, `bulk_extractor`
   per-extractor dirs, Sigma matched-event byte dumps), use
   `exports/<domain>/<EVID>/<artifact-tree>/`. Examples:
   - `exports/registry/EV01/{SOFTWARE,SYSTEM,SAM,SECURITY}` and
     `exports/registry/EV02/{SOFTWARE,SYSTEM,SAM}` as siblings
   - `exports/tsk_recover/EV01/`, `exports/tsk_recover/EV02/`
   - `exports/sigma_hits/EV01/<rule_id>/<event-N>.evtx` (Chainsaw /
     Hayabusa matched-event byte extracts — each rule gets a subdir,
     each match a separate EVTX record dump)
   Use this form when the tool itself emits a directory tree we don't
   control.

   **Worked example — Sigma matched-event byte extracts.** Sigma hunting
   is the canonical use case for this exception (see
   `.claude/skills/sigma-hunting/SKILL.md` § Hunting workflow step 6).
   `<rule_id>` is the rule's filename minus the `.yml` extension so the
   matched-record corpus is self-describing without a sidecar map; each
   `event-<record_id>.jsonl` is one EVTX record promoted to layer 4 so
   downstream skills (YARA, correlator joins, report citations) chain
   on a fingerprinted artifact:

   ```
   exports/sigma_hits/EV01/proc_creation_win_powershell_encoded_invocation/event-12345.jsonl
   exports/sigma_hits/EV01/file_event_win_susp_office_doc_drop/event-67890.jsonl
   exports/sigma_hits/EV02/proc_creation_win_powershell_encoded_invocation/event-22001.jsonl
   ```

   `case-init.sh` pre-scaffolds `./exports/sigma_hits/` (the empty parent
   dir) — per-EVID and per-rule subdirs are created lazily by the
   sigma-hunting workflow as matches are written. `audit-exports.sh`
   walks the tree depth-unbounded, so each `event-*.jsonl` lands in
   `analysis/exports-manifest.md` with a `first-seen` row regardless
   of its depth.

3. **Survey / findings (layer 3) keep the existing pattern.** Per-
   evidence survey stubs go to `analysis/<domain>/survey-EV01.md`,
   `survey-EV02.md`, … but `analysis/<domain>/findings.md` is
   **consolidated per domain across evidence items** — do NOT create
   per-evidence subdirs in `./analysis/<domain>/`.

**Why filename-encoding as default:** `audit-exports.sh` walks
`./exports/` depth-unbounded so either form gets fingerprinted.
Filename-encoding keeps related artifacts collated in one directory and
grep-friendly. The directory form is reserved for cases where the tool
itself emits a tree we don't control.

**How to apply:**
- Surveyor / investigator: when writing into `./exports/<domain>/`,
  always include the `EVID` in the path. If you cannot tell from the
  artifact alone which evidence item it came from, that is a chain-of-
  custody gap — fix the path encoding before writing.
- Correlator: when aggregating across evidence items, treat the EV-
  suffix (or per-EVID subdir) as the join key. A file in
  `./exports/<domain>/` without an `EVID` in its path is unattributed
  — flag it as a discipline failure rather than guessing.
- QA: `audit-exports.sh` does not enforce the suffix mechanically. The
  QA pass MUST grep `./exports/` for filename collisions across
  evidence items (`<artifact>.<ext>` instead of `<artifact>-<EVID>.<ext>`)
  in cases where `manifest.md` lists ≥2 evidence items, and Edit-fix
  the offending paths before sign-off.

---

## Cross-rule notes

- The DISCIPLINE.md path is referenced from each agent's frontmatter as
  `MANDATORY` — the agent harness does not enforce reading; the marker
  `discipline_v1_loaded` is the self-attestation signal.
- The PreToolUse / PostToolUse hooks enforce Rule A mechanically. Rules
  F / G / H / B are agent-prompt-level discipline; they are caught after
  the fact by audit-log review and by the orchestrator's correlation-
  loop convergence guard (Phase 4).
- Rules I and J are gate-enforced by `leads-check.sh` and
  `intake-check.sh`; the QA phase agent additionally has authority to
  apply remediation Edits in place.
- Rule K is QA-enforced by `mitre-validate.sh` against the offline TSV
  at `.claude/skills/dfir-bootstrap/reference/mitre-attack.tsv`. The
  rule is opt-in for the writer (the line is optional) but mandatory for
  the validator (if present, must validate). Extending the TSV is the
  expected response when a real technique is missing.
- Rule L (multi-evidence path encoding) is agent-prompt-level
  discipline at write time and QA-enforced at sign-off:
  `audit-exports.sh` fingerprints every file under `./exports/` but
  does not mechanically reject collision-prone names — the QA pass
  greps `./exports/` for un-suffixed artifacts when `manifest.md`
  records ≥2 evidence items and Edit-fixes the offending paths.
- **Manifest completeness (issue #12)** is gate-enforced by
  `manifest-check.sh`. The script runs in three places: (1) the
  `/case` slash-command after `case-init.sh`, refusing to dispatch
  agents when the manifest is broken; (2) the PreToolUse Bash hook,
  refusing reads against `./evidence/` or `./working/`
  when the manifest is broken; (3) the QA phase, which surfaces any
  remaining violations into `qa-review.md`. Bespoke hash files
  outside the canonical ledger (`analysis/archive_hashes.txt` and
  similar — case12's workaround pattern) trigger an
  `L-MANIFEST-BESPOKE-NN` BLOCKED lead requiring operator review;
  the file may carry forensic work that needs migration into
  `manifest.md`, not deletion.
- When in doubt about whether a borderline item is in scope (G) or
  whether the surface is exhausted (H), prefer the more conservative
  (in-scope / not-exhausted) choice. The cost of an extra lead is one
  investigator wave; the cost of a missed scope-flip is the case's
  conclusion.
