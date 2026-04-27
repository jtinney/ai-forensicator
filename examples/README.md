# Sample evidence

Public DFIR data sets used for demos, dry-runs, and skill validation.
Not consumed by the orchestrator — copy into a real case workspace before
analysis.

| File | Source | Use |
|------|--------|-----|
| `CFREDS-JimmyWilson.zip` | NIST CFREDS — Jimmy Wilson scenario | Disk image + collected artifacts; good end-to-end exercise for Phase 1-3 |

## How to use

```bash
# 1. Pick a case ID and stage the bundle in a new case workspace.
mkdir -p ./cases/CFREDS-JimmyWilson/evidence
cp ./examples/CFREDS-JimmyWilson.zip ./cases/CFREDS-JimmyWilson/evidence/

# 2. Launch orchestration. case-init.sh expands the bundle under
#    ./analysis/_extracted/ and hashes every member.
/case CFREDS-JimmyWilson
```

`*.zip`, `*.tar`, `*.tar.gz`, `*.7z` files in this directory are gitignored,
so large public bundles can sit here without bloating commits.
