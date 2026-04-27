# YARA Rule Conventions — Reference

Every rule in `rules/local/` and every case-local rule under
`./analysis/yara/` MUST conform to this convention. The linter
(`validate-rules.sh`) enforces the required keys and runs `yarac` to confirm
syntax.

## Required `meta` keys

| Key | Value | Notes |
|---|---|---|
| `author`      | string                              | Person or project ("ai-forensicator project library") |
| `date`        | `YYYY-MM-DD`                        | Authoring date; bump when rule body changes |
| `description` | one-line string                     | What the rule fires on, not why it matters |
| `severity`    | `informational` \| `low` \| `medium` \| `high` \| `critical` | Operator's confidence the hit is malicious |
| `scope`       | `file` \| `memory` \| `both` \| `pcap_payload` \| `unallocated` | What the rule expects to scan |

## Recommended `meta` keys (required under `--strict`)

| Key | Value |
|---|---|
| `reference` | URL, CVE ID, paper, or in-house case ID. Vendored rules MUST set this to the upstream source URL + commit. |
| `mitre`     | Comma-separated ATT&CK technique IDs (e.g. `T1059.001,T1027`) |
| `family`    | Lowercase malware-family identifier (`emotet`, `cobaltstrike`) |
| `hash`      | SHA256 of a reference sample, when the rule was authored from one |
| `tlp`       | `clear` \| `green` \| `amber` \| `amber+strict` \| `red` |
| `license`   | SPDX ID, `DRL-1.1`, `EL-2.0`, or `Local` |
| `fp_tested` | `YYYY-MM-DD` of last FP test against goodware |
| `fp_target` | Path(s) used for the FP test (`/usr/bin`, `/Windows/System32`) |

## Tag vocabulary

YARA tags are how scans get scoped. Use them — `yara --tag=memory rules.yar`
runs only memory-scoped rules and skips disk-only ones. The accepted vocab:

| Category | Tags |
|---|---|
| Scope     | `file`, `memory`, `pcap_payload`, `unallocated` |
| Format    | `pe`, `elf`, `macho`, `script_ps1`, `script_vbs`, `script_js`, `script_cmd`, `office`, `archive` |
| Stage     | `loader`, `implant`, `persistence`, `credaccess`, `exfil`, `c2`, `recon`, `ransomware` |
| Severity  | `sev_critical`, `sev_high`, `sev_medium`, `sev_low`, `sev_info` |
| Family    | `family_<lowercase_name>` (e.g. `family_emotet`) |

A rule may have multiple tags from each category. Every rule SHOULD have at
least one `Scope` tag and one `Severity` tag.

## Naming convention

`<Provenance>_<Category>_<Variant>` — letters, digits, underscores only.

| Provenance prefix | Used for |
|---|---|
| `Local_`     | Rules under `rules/local/` |
| `Case<N>_`   | Case-local rules under `./analysis/yara/` (replace N with the case number) |
| `Sigbase_`   | Mirror of Neo23x0 signature-base (when promoted into local/) |
| `Yaraforge_` | Mirror of YARAHQ yara-forge |
| `Elastic_`   | Mirror of elastic/protections-artifacts |

Example: `Local_Emotet_Loader_v3`, `Case42_Lateral_PsExec_Beacon`.

## Performance contract

YARA short-circuits left-to-right. Order conditions cheap → expensive:

```
condition:
    uint16(0) == 0x5A4D and    // 1. Fast: 2-byte read at offset 0
    filesize < 10MB and         // 2. Fast: metadata
    pe.is_pe and                // 3. Medium: PE parser
    $str1 and                   // 4. Medium: string match
    math.entropy(...) > 7.0    // 5. Expensive: full entropy scan — LAST
```

- Strings ≥ 4 bytes (yara warns below)
- Regex must be bounded (anchored quantifier, `at` clause, or `filesize<X`)
- Don't `any of them` against rules whose only strings are short regexes

## False-positive contract

Rules in `rules/local/` SHOULD record an FP test. The validator's
`--fp-test` flag re-runs the test against `/usr/bin` (and
`/Windows/System32` if mounted) and warns when a rule fires on more than
`FP_THRESHOLD` (default 5) goodware files.

If a rule trips heavy goodware, move it to `rules/quarantine/` rather than
deleting it — keeping it on disk preserves the historical record and lets a
later analyst re-tighten it.
