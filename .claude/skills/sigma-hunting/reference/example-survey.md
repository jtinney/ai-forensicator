<!--
  Example survey — sigma domain (Chainsaw + Hayabusa).
  Synthetic case for reference only. Use as a model when instantiating
  `.claude/skills/dfir-discipline/templates/survey-template.md` for a
  real (evidence × sigma) pair. This file lints clean against
  `.claude/skills/dfir-bootstrap/lint-survey.sh`.
-->

# Header

- **Case ID:** EXAMPLE-SIGMA-2026-07
- **Evidence ID:** EV01
- **Evidence sha256:** 81d6f4a9b7c3e205112233445566778899aabbccddeeff00112233445566778b
- **Domain:** sigma
- **Surveyor agent version:** dfir-surveyor / discipline_v1_loaded
- **UTC timestamp:** 2026-04-26 15:14:05 UTC

## Tools run

- `chainsaw lint` -> `chainsaw lint .claude/skills/sigma-hunting/rules/sigma/` -> exit 0 -> stdout (412 rules valid, 0 warnings)
- `chainsaw hunt (Sigma + curated mapping)` -> `chainsaw hunt ./exports/evtx/ -s .claude/skills/sigma-hunting/rules/sigma/ --mapping .claude/skills/sigma-hunting/mappings/sigma-event-logs-all.yml --csv -o ./analysis/sigma/chainsaw-sigma.csv` -> exit 0 -> `./analysis/sigma/chainsaw-sigma.csv`
- `chainsaw hunt (Chainsaw rules)` -> `chainsaw hunt ./exports/evtx/ -r .claude/skills/sigma-hunting/rules/chainsaw/ --csv -o ./analysis/sigma/chainsaw-curated.csv` -> exit 0 -> `./analysis/sigma/chainsaw-curated.csv`
- `hayabusa csv-timeline` -> `hayabusa csv-timeline -d ./exports/evtx/ -o ./analysis/sigma/hayabusa-timeline.csv -p verbose-min` -> exit 0 -> `./analysis/sigma/hayabusa-timeline.csv`
- `chainsaw search (literal IOC)` -> `chainsaw search ./exports/evtx/ -s "185.220.101.42"` -> exit 0 -> `./analysis/sigma/chainsaw-search-c2-ip.csv`
- `evtx_dump (pre-filter for noisy channels)` -> `evtx_dump -o jsonl ./exports/evtx/Microsoft-Windows-Sysmon%4Operational.evtx > ./analysis/sigma/jsonl/sysmon.jsonl` -> exit 0 -> `./analysis/sigma/jsonl/sysmon.jsonl`

## Findings of interest

- Chainsaw + Sigma fires `proc_creation_win_powershell_b64_encoded_command` rule (high severity) at 2026-04-18 12:03:15 UTC — `powershell.exe -EncodedCommand JABh...` invoked with parent `cmd.exe` PID 5012 -> grandparent `update_helper.exe` PID 4488 (`./analysis/sigma/chainsaw-sigma.csv#L88-L90`). Lead: `L-EV01-sigma-01`
- Hayabusa timeline severity-`crit` rows include three Sysmon EID 22 (DNS query) events for `news-cdn-update.com` from `update_helper.exe` PID 4488 between 12:03 and 12:18 UTC — pivots cleanly with the network domain's DNS observation (`./analysis/sigma/hayabusa-timeline.csv#L412-L417`). Lead: `L-EV01-sigma-02`
- Chainsaw curated rule `lateral_movement_detect_psexec_smb` matches Security 5145 (network-share access) for `\\PIVOT-SVR\C$\update_helper.exe` from source `10.0.42.17` at 12:11:42 UTC — surfaces a lateral-movement attempt the surveyor of just one host can't fully resolve (`./analysis/sigma/chainsaw-curated.csv#L201`). Lead: `L-EV01-sigma-03`
- The literal-IOC search for `185.220.101.42` returns 4 events: 1 Sysmon EID 3 (network-connect) + 3 Sysmon EID 22 (DNS query for the hosting domain) — confirms the IP is observed in evtx records, not just netscan/zeek (`./analysis/sigma/chainsaw-search-c2-ip.csv#L4-L7`). Lead: `L-EV01-sigma-04`

## Lead summary table

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV01-sigma-01` | high | The base64-encoded PowerShell at 12:03:15 is the implant's first-stage command-line; decoding reveals C2 callback or stager URL | `chainsaw search ./exports/evtx/ -s "EncodedCommand"` to enumerate every encoded-cmd execution; decode the matching script-block (Operational EID 4104) | ~2 min |
| `L-EV01-sigma-02` | high | Sysmon EID 22 confirms `update_helper.exe` issued the DNS for the C2 domain; ties windows-side telemetry to network capture | `chainsaw hunt --rule sigma_dns_query_to_recently_registered_domain` for related queries; cross-reference DNS query count vs network-domain observation | ~1 min |
| `L-EV01-sigma-03` | high | Source host `10.0.42.17` attempted lateral move to `PIVOT-SVR` at 12:11:42 — case scope expands beyond single host | Promote `PIVOT-SVR` to evidence-acquisition list; meanwhile, search EVTX for SMB session-create from same workstation in 12:00–12:30 UTC | ~3 min |
| `L-EV01-sigma-04` | med  | The 4 EVTX hits for the C2 IP triangulate the network observation onto host-side telemetry; chain of custody for the IP is now complete | Sanity-check by counting Sysmon EID 3 (network connect) entries from PID 4488 across full evtx — should match netscan's flow count | ~1 min |

## Negative results

- Sigma `defense_evasion_winrar_password_protect` rule: zero hits — implant did not stage exfil through WinRAR; the 4 MB POST wasn't a password-protected archive.
- Hayabusa rules tagged `attack.persistence.t1547.001`: only ONE hit, which was the Run-key write already known via windows-artifacts. No additional persistence vector found.
- Chainsaw `service_install_*` Sigma rule pack: zero matches — the implant didn't install or start a Windows service (Service Control Manager is clean).
- WMI subscription persistence Sigma rules: zero events; consistent with EvtxECmd's clean WMI-Activity finding from the windows-artifacts survey.

## Open questions

- The `proc_creation_win_powershell_b64_encoded_command` Sigma rule has known false-positive rate ~6% on enterprise images that script their own deployments; cheap disconfirmation (decode the base64 and inspect for `Net.WebClient` or `Invoke-Expression`) belongs in the investigator's lead.
- The `5145` lateral-movement event (lead 03) might be a false positive if `\\PIVOT-SVR\C$\update_helper.exe` is a legitimate IT helper — but the file name matches the implant on the original host, which is suspicious. The pivot host's evidence is required before drawing conclusions.
