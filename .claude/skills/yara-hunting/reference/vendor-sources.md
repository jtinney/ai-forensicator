# YARA Vendor Sources — Reference

The project does not ship third-party rule packs in git — license terms
vary and operators may need to make per-source decisions. Pull them on a
connected workstation, then transfer `rules/vendor/` to isolated SIFT
instances out-of-band.

```bash
# Default: yara-forge + signature-base, pinned refs
bash .claude/skills/yara-hunting/vendor-rules.sh

# Add Elastic protections-artifacts (Elastic License v2 — review terms)
bash .claude/skills/yara-hunting/vendor-rules.sh --with elastic

# Add ReversingLabs YARA rules (MIT)
bash .claude/skills/yara-hunting/vendor-rules.sh --with reversinglabs

# Verify on-disk archives match the manifest (run on the SIFT side)
bash .claude/skills/yara-hunting/vendor-rules.sh --verify-only

# List configured sources, refs, licenses
bash .claude/skills/yara-hunting/vendor-rules.sh --list

# Wipe the vendor dir
bash .claude/skills/yara-hunting/vendor-rules.sh --clean
```

The fetch writes `rules/vendor/vendor-manifest.json` — a deterministic
record of every archive pulled with source URL, ref, SHA256, license, and
pull timestamp. Re-running with `--verify-only` re-hashes and detects drift.

## Reputable upstream sources (in rough signal-to-noise order for DFIR)

| Source | License | Notes |
|---|---|---|
| **YARAHQ / yara-forge** | MIT (per-rule licenses preserved) | Aggregated, deduped, FP-tested superset of ~15 sources — best "single pull" |
| **Neo23x0 / signature-base** (Florian Roth) | DRL 1.1 | Broad APT/malware coverage, low FP, attribution required |
| **Elastic protections-artifacts** | Elastic License v2 | MITRE-tagged YARA + EQL — review redistribution restrictions |
| **ReversingLabs YARA rules** | MIT | Strong on packers, loaders, droppers |
| **Volexity / Mandiant / SentinelLabs** | Per-report | Narrow but high-confidence; vendor manually from threat reports |
| **CISA malware analysis advisories** | Public domain | Per-report rules linked from `cisa.gov/resources-tools/resources/malware-analysis-reports` |

Always promote a vendored rule into `rules/local/` (with the project meta
convention applied) when it becomes core to the project's hunting baseline.
Keep the upstream `rules/vendor/` copy unchanged — that preserves the
chain back to the source repo.

## Tag-based scoping with vendored rules

Vendored sets are typically large. Tag-based scoping is essential to
keep scan time manageable:

```bash
# Run only memory-scoped rules across local + vendor
yara --tag=memory \
    .claude/skills/yara-hunting/rules/local/ \
    .claude/skills/yara-hunting/rules/vendor/yara-forge/ \
    /path/to/memory.img

# Run only ransomware-tagged rules
yara --tag=ransomware ...
```

If an upstream set lacks the project's tag vocabulary (most do), the
operator can promote a curated subset into `rules/local/` with the
project convention applied — that's where the metadata convention pays
off across upstream.
