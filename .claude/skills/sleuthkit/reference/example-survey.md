<!--
  Example survey — filesystem domain (Sleuth Kit).
  Synthetic case for reference only. Use as a model when instantiating
  `.claude/skills/dfir-discipline/templates/survey-template.md` for a
  real (evidence × filesystem) pair. This file lints clean against
  `.claude/skills/dfir-bootstrap/lint-survey.sh`.
-->

# Header

- **Case ID:** EXAMPLE-FS-2026-05
- **Evidence ID:** EV01
- **Evidence sha256:** 5b8c3e2a9f70a1b4c5d6e7f80991a2b3c4d5e6f7081929304a5b6c7d8e9f00ab
- **Domain:** filesystem
- **Surveyor agent version:** dfir-surveyor / discipline_v4_loaded
- **UTC timestamp:** 2026-04-26 14:43:21 UTC

## Tools run

- `mmls` -> `mmls ./evidence/JANE-WIN10-DESKTOP.E01` -> exit 0 -> `./analysis/filesystem/mmls.txt`
- `fsstat` -> `fsstat -o 264192 ./evidence/JANE-WIN10-DESKTOP.E01` -> exit 0 -> `./analysis/filesystem/fsstat-p2.txt`
- `img_stat` -> `img_stat ./evidence/JANE-WIN10-DESKTOP.E01` -> exit 0 -> `./analysis/filesystem/img_stat.txt`
- `fls (full listing)` -> `fls -r -p -o 264192 ./evidence/JANE-WIN10-DESKTOP.E01 > ./analysis/filesystem/fls-full.txt` -> exit 0 -> `./analysis/filesystem/fls-full.txt`
- `fls (deleted only)` -> `fls -r -p -o 264192 ./evidence/JANE-WIN10-DESKTOP.E01 | grep '^\*' > ./analysis/filesystem/fls-deleted.txt` -> exit 0 -> `./analysis/filesystem/fls-deleted.txt`
- `fls (bodyfile)` -> `fls -r -m / -o 264192 ./evidence/JANE-WIN10-DESKTOP.E01 > ./analysis/filesystem/bodyfile.txt` -> exit 0 -> `./analysis/filesystem/bodyfile.txt`
- `mactime (incident slice)` -> `mactime -y -z UTC -b ./analysis/filesystem/bodyfile.txt 2026-04-18T11:00:00..2026-04-18T14:00:00 > ./analysis/filesystem/mactime-incident.txt` -> exit 0 -> `./analysis/filesystem/mactime-incident.txt`

## Findings of interest

- `mmls` shows one NTFS partition at offset 264192 (sector 516, 512-byte sectors), size 119.4 GB; sector size 512 confirmed by `img_stat` — no 4K-sector trap (`./analysis/filesystem/mmls.txt#L4-L8`). Lead: `L-EV01-filesystem-01`
- `fls` deleted-entries pass surfaces 4 inodes inside the incident window: `91234-128-1` (`update_helper.exe`, deleted 2026-04-18 12:21:33 UTC), `91245-128-1` (`updater.exe`), `91261-128-3` (`report_q1.zip`), `91278-128-3` (`customer_list.csv`) — all in the same NTFS data run cluster, suggesting batch deletion (`./analysis/filesystem/fls-deleted.txt#L42-L45`). Lead: `L-EV01-filesystem-02`
- `mactime` incident slice confirms the 12:21 cluster: A=12:21:31, M=12:21:33 for all four deleted files. Earlier in the same window, `\Users\jane\Downloads\update_helper.exe` shows B=2026-04-18 12:02:58 (creation) — three minutes before the host-side execution evidence (`./analysis/filesystem/mactime-incident.txt#L88-L113`). Lead: `L-EV01-filesystem-03`
- `\Windows\System32\config\SYSTEM` last-written timestamp is 2026-04-18 12:03:09 UTC — exactly the moment Run-key persistence was written from the windows-artifacts side; provides cross-validation independent of registry parsing (`./analysis/filesystem/mactime-incident.txt#L42`). Lead: `L-EV01-filesystem-04`

## Lead summary table

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV01-filesystem-01` | low  | Partition layout is standard; no further action — informational | (none — informational) | ~0 s |
| `L-EV01-filesystem-02` | high | The four deletions are batch-recovery candidates via `icat` and the `$I/$R` Recycle Bin pair | `icat -o 264192 ./evidence/JANE-WIN10-DESKTOP.E01 91234 > ./exports/recovered/update_helper.exe` (repeat per inode); then `sha256sum` + YARA sweep | ~3 min |
| `L-EV01-filesystem-03` | high | The B(creation) of `update_helper.exe` at 12:02:58 places initial drop 16 s before run; fits a network-drop-then-run path; cross-ref network's HTTP slice | Search Zeek `http.log` for any `GET` returning binary content to `10.0.42.17` between 12:02:00–12:03:00 | ~2 min |
| `L-EV01-filesystem-04` | high | SYSTEM-hive write at 12:03:09 UTC corroborates the registry-side Run-key persistence claim; chain-of-custody for that finding strengthens | Read SYSTEM hive offset around the 12:03:09 timestamp via `RECmd` and confirm the affected key; cross-ref to `L-EV01-windows-artifacts-02` | ~1 min |

## Negative results

- `tsk_recover` not run — bulk-recover output (~120k entries) would dwarf the case's actual recovery surface; targeted `icat` per inode is the right tool.
- `blkls -A` for unallocated YARA sweep: not run at survey phase; will be a Phase-3 lead if the targeted recovery doesn't yield the implant binary.
- `photorec` carving by signature: not run; Recycle Bin metadata + MFT entries are intact, so signature-only carving would only matter if MFT entries were overwritten, which they were not.
- VSS (volume shadow copy) carving via `vss_carver` alias: image has zero shadow copies (`fsstat` reports `Shadow Copy Storage area not allocated`) — VSS pivot surface is empty.

## Open questions

- The cluster offset of all four deleted files is contiguous (logical clusters 14852341..14852398) — this could indicate they were written by a single allocation pass (single zip, then unzipped to adjacent files), which would suggest a staged drop archive. Worth noting in correlation; not a filesystem investigation question.
- The `\Users\jane\Downloads` directory's MFT entry shows a child-attribute reference to one inode index (`91234`) that isn't in the live directory listing — orphan reference; could be a deleted-then-recovered ADS, but cheap to ignore unless the implant analysis surfaces an ADS-based persistence claim.
