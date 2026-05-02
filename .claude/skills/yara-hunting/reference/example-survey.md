<!--
  Example survey — yara domain (YARA / IOC sweeps).
  Synthetic case for reference only. Use as a model when instantiating
  `.claude/skills/dfir-discipline/templates/survey-template.md` for a
  real (evidence × yara) pair. This file lints clean against
  `.claude/skills/dfir-bootstrap/lint-survey.sh`.
-->

# Header

- **Case ID:** EXAMPLE-YARA-2026-06
- **Evidence ID:** EV01
- **Evidence sha256:** 70a8d3b9c5e4f211223344556677889900aabbccddeeff00112233445566778a
- **Domain:** yara
- **Surveyor agent version:** dfir-surveyor / discipline_v2_loaded
- **UTC timestamp:** 2026-04-26 15:02:14 UTC

## Tools run

- `yara (compiled vendor pack)` -> `yara -C .claude/skills/yara-hunting/rules/compiled.rules ./evidence/JANE-WIN10-DESKTOP.E01 -p 4 -r > ./analysis/yara/disk-vendor-hits.txt` -> exit 0 -> `./analysis/yara/disk-vendor-hits.txt`
- `yara (memory image)` -> `yara -C .claude/skills/yara-hunting/rules/compiled.rules ./evidence/JANE-WIN10-DESKTOP.mem > ./analysis/yara/mem-vendor-hits.txt` -> exit 0 -> `./analysis/yara/mem-vendor-hits.txt`
- `yara (recovered binaries)` -> `yara -s -p 4 .claude/skills/yara-hunting/rules/compiled.rules ./exports/recovered/ > ./analysis/yara/recovered-hits.txt` -> exit 0 -> `./analysis/yara/recovered-hits.txt`
- `yara (HTTP carve sweep)` -> `yara -s .claude/skills/yara-hunting/rules/cobalt_strike.yar ./exports/network/http_objects/` -> exit 0 -> `./analysis/yara/http-objects-hits.txt`
- `yarac (validate rule pack)` -> `yarac .claude/skills/yara-hunting/rules/local/cobalt_strike.yar /tmp/cs.compiled` -> exit 0 -> `/tmp/cs.compiled`

## Findings of interest

- Memory-image sweep returns 14 hits across 4 rules: `CS_BeaconStager_Stub` (3 offsets in one VAD region, PID 4488 inferred from cross-ref to vol3 malfind), `CS_Reflective_Loader_Hash`, `Mimikatz_Sekurlsa_Strings` (2 hits), and `Generic_RWX_PE_Header`. The `CS_*` cluster localizes inside the 0x1f3a0000000-area injected VAD that memory.malfind already flagged (`./analysis/yara/mem-vendor-hits.txt#L4-L17`). Lead: `L-EV01-yara-01`
- The recovered-binary sweep over `./exports/recovered/update_helper.exe` (sha256 `dd55ef...01ab`) hits `CS_BeaconStager_Stub` and `Generic_PowerShell_Downloader_Pattern`; both rules require ≥3 string matches to fire — this is a strong family attribution to Cobalt Strike (`./analysis/yara/recovered-hits.txt#L8-L12`). Lead: `L-EV01-yara-02`
- The HTTP-object sweep over the carved 4 MB POST body (`./exports/network/http_objects/upload`) fires `Generic_AES256_GCM_Header` and `Generic_PowerShell_Encoded_Block` — points at AES-encrypted PowerShell exfil, consistent with Cobalt Strike's default `Crypto::AES_256_CBC` profile (`./analysis/yara/http-objects-hits.txt#L4-L7`). Lead: `L-EV01-yara-03`
- The disk-image whole-image sweep returns 0 hits for the same `CS_*` family rules — the implant's on-disk footprint was deleted before capture; only the recovered-via-icat copy retains the bytes (`./analysis/yara/disk-vendor-hits.txt#L1-L4`). Lead: `L-EV01-yara-04`

## Lead summary table

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV01-yara-01` | high | The injected VAD in PID 4488 is Cobalt Strike Beacon; coupled with memory netscan + network-side beacon, attribution is high | `vol windows.vadyarascan --pid 4488 --yara-rules ./compiled.rules` for per-offset hit list; pivot offsets vs `windows.malfind --pid 4488 --dump` output | ~2 min |
| `L-EV01-yara-02` | high | `update_helper.exe` (recovered) is the staged stager for the in-memory beacon; same family same campaign | Promote disk-side IOCs from the binary: hash, PDB path, embedded C2 URL — append as a per-file YARA rule under `.claude/skills/yara-hunting/rules/local/` | ~5 min |
| `L-EV01-yara-03` | high | The 4 MB POST is an AES-encrypted exfil payload; matches Cobalt Strike's default AES exfil mode | Decrypt-attempt is out of scope for the surveyor; escalate to investigator with the AES hit offsets and request the carved-key pivot from memory dump | ~1 min |
| `L-EV01-yara-04` | med  | The on-disk implant binary was wiped before capture; only Recycle Bin and slack hold residual bytes | Re-run YARA against `blkls -A unalloc.raw` (unallocated only) to test whether implant bytes survive in slack independent of recovered-files path | ~4 min |

## Negative results

- `Mimikatz_Catalog` rule pack: 2 hits in memory (already noted under finding 1) but ZERO hits on disk — credential-access tooling was memory-only; no on-disk Mimikatz binary.
- Generic AV/EDR vendor hits: zero — rule families like `EICAR_Test_File`, `XMRig_Mining_Strings`, `WannaCry_Mutex` are absent. The campaign isn't piggy-backing on a public commodity tool.
- Browser extension YARA pack: zero hits in `\Users\jane\AppData\Local\Google\Chrome\User Data\Default\Extensions\` — no malicious browser-extension persistence.
- YARA performance metric: total wall clock for the 4-target sweep was 4 min 38 s on a compiled rule pack of 412 rules — within the surveyor budget; no need to narrow rule selection.

## Open questions

- The `Generic_RWX_PE_Header` rule fires on both injected VADs and on at least one legitimate process (`MsMpEng.exe` PID 1840, in Windows Defender's scratch buffer). Cross-reference required before reporting "RWX PE detected" as evidence — generic rules without a family match are noise.
- A single `Sysmon_Lookalike_String` hit on disk inside `\Users\jane\AppData\Local\Temp\readme.txt` could be a real installer document or could be a planted decoy. The text content is ~12 lines; should be read by hand before a Phase-3 lead is fired against it.
