<!--
  Example survey — timeline domain (Plaso).
  Synthetic case for reference only. Use as a model when instantiating
  `.claude/skills/dfir-discipline/templates/survey-template.md` for a
  real (evidence × timeline) pair. This file lints clean against
  `.claude/skills/dfir-bootstrap/lint-survey.sh`.
-->

# Header

- **Case ID:** EXAMPLE-TIMELINE-2026-04
- **Evidence ID:** EV01
- **Evidence sha256:** 4c2e7a8b1d9f005611223344556677889900aabbccddeeff0011223344556677
- **Domain:** timeline
- **Surveyor agent version:** dfir-surveyor / discipline_v1_loaded
- **UTC timestamp:** 2026-04-26 14:55:08 UTC

## Tools run

- `pinfo.py` -> `pinfo.py -v ./analysis/timeline/case.plaso` -> exit 0 -> `./analysis/timeline/pinfo-verbose.txt`
- `log2timeline.py (narrow ingest)` -> `log2timeline.py --status_view none --parsers winevtx,winreg,prefetch,amcache,recycle_bin_*,mft ./analysis/timeline/case.plaso ./exports/registry/ ./exports/evtx/ ./exports/Prefetch/ ./exports/Recycle.Bin/ ./exports/$MFT` -> exit 0 -> `./analysis/timeline/case.plaso`
- `psort.py (incident slice)` -> `psort.py -o l2tcsv -w ./analysis/timeline/incident_window.csv ./analysis/timeline/case.plaso "date > '2026-04-18 11:00:00' AND date < '2026-04-18 14:00:00'"` -> exit 0 -> `./analysis/timeline/incident_window.csv`
- `psort.py (5-min slice around exploit)` -> `psort.py -o l2tcsv --slice '2026-04-18 12:03:14' ./analysis/timeline/case.plaso > ./analysis/timeline/slice_12_03_14.csv` -> exit 0 -> `./analysis/timeline/slice_12_03_14.csv`
- `awk` -> `awk -F, 'NR>1 {print $5}' ./analysis/timeline/incident_window.csv | sort | uniq -c | sort -rn` -> exit 0 -> `./analysis/timeline/incident_window-by-source.txt`

## Findings of interest

- The 5-min slice around 2026-04-18 12:03:14 UTC shows a clean attacker pattern: `winreg/run_keys` Run-key write at 12:03:09Z, `prefetch` first-execution of `update_helper.exe` at 12:03:14Z, `winevtx 4624 type 3` at 12:03:18Z, `winevtx 4688` (process create) at 12:03:14.123Z — process-create + Prefetch agree to the millisecond (`./analysis/timeline/slice_12_03_14.csv#L8-L17`). Lead: `L-EV01-timeline-01`
- `pinfo` reports zero parser hits for `winreg/usnjrnl_$j` and `mft` even though those parsers were enabled — the `$J` was not staged into the ingest set; subsequent timeline coverage of file create/delete events is limited to `mactime`'s view (`./analysis/timeline/pinfo-verbose.txt#L284-L301`). Lead: `L-EV01-timeline-02`
- A second cluster at 12:21:08–12:21:42 UTC contains: `recycle_bin/$I` for `report_q1.zip`, `recycle_bin/$I` for `customer_list.csv`, `winevtx 4663` (file access) for both, and `winevtx 4690` (handle close) — the deletion is logged from process PID 4488 (matches the memory-side hidden updater.exe) (`./analysis/timeline/incident_window.csv#L412-L420`). Lead: `L-EV01-timeline-03`
- A 30-minute gap between 12:31:09 UTC (last MFT write to `\Users\jane\AppData\Local\Temp\sched_xxxx.tmp`) and 13:01:14 UTC (next event of any kind in the slice) is unusual for an active workstation (`./analysis/timeline/incident_window.csv#L501-L502`). Lead: `L-EV01-timeline-04`

## Lead summary table

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV01-timeline-01` | high | The Run-key write -> Prefetch -> 4688 sequence at 12:03 UTC is the implant's first-run footprint; canonical "execute then persist" attacker order | `psort.py "date > '2026-04-18 12:02:00' AND date < '2026-04-18 12:05:00'"` for full 3-min window incl. low-noise sources | ~30 s |
| `L-EV01-timeline-02` | med  | `$J` was missing from the ingest; many file-system events are absent from this timeline and the gap may hide implant activity | Re-run `log2timeline.py --parsers usnjrnl_$j` over `./exports/$J` (already staged from sleuthkit survey); merge into a second `.plaso` and re-psort | ~6 min |
| `L-EV01-timeline-03` | high | The 12:21 deletion cluster is exfiltration cleanup tied to the same PID seen in memory; ties memory + recycle-bin + EVTX into one event | `psort.py "date > '2026-04-18 12:20:00' AND date < '2026-04-18 12:23:00' AND source contains 'WIN'"` to surface every cross-source mention | ~30 s |
| `L-EV01-timeline-04` | low  | The 30-min event gap (12:31–13:01 UTC) is interesting but normal idle behaviour also produces such gaps on a single-user workstation | After `$J` re-ingest (lead 02), psort the same window — `$J` will populate it if there were file ops Plaso missed | ~1 min |

## Negative results

- Browser parsers (`firefox_history`, `chrome_history`, `msie_history`): zero hits in the 11:00–14:00 UTC window — neither user nor implant browsed the web from this host during the incident.
- USB connection events (`winreg/winreg_default` for `USBSTOR`): no new USBSTOR mounts during the incident window; exfil was not via USB.
- Scheduled-task creation events (`winevtx TaskScheduler %4Operational EventID 106`): no new tasks created in the 11:00–14:00 UTC window.
- The narrow ingest above intentionally skipped `bsm`, `syslog`, `pe`, and `apache_access` parsers — they would not contribute on a Windows-only target host.

## Open questions

- The 12:03:14 cluster is sub-second; whether `4688` (process create) preceded `prefetch` write or vice versa is below Plaso's UTC-second resolution. Cross-checking against EvtxECmd's millisecond-precision Security.evtx would order the two events; if Prefetch precedes 4688, the implant ran via a hollowed legitimate process.
- The `pinfo` parser-coverage gap (lead 02) is likely a staging oversight, not a Plaso bug; should be raised in the case's investigator-acquisition checklist for next time.
