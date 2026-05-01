<!--
  Example survey — network-forensics domain.
  Synthetic case for reference only. Use as a model when instantiating
  `.claude/skills/dfir-discipline/templates/survey-template.md` for a
  real (evidence × network) pair. This file lints clean against
  `.claude/skills/dfir-bootstrap/lint-survey.sh`.
-->

# Header

- **Case ID:** EXAMPLE-NETFOR-2026-02
- **Evidence ID:** EV02
- **Evidence sha256:** 3b27c81dffe204169c5b2d8a4e6f70819293847560abcdef0123456789abcdef
- **Domain:** network
- **Surveyor agent version:** dfir-surveyor / discipline_v1_loaded
- **UTC timestamp:** 2026-04-26 14:18:42 UTC

## Tools run

- `capinfos` -> `capinfos ./evidence/case.pcap` -> exit 0 -> `./analysis/network/capinfos.txt`
- `zeek_suricata_parallel.sh` -> `bash .claude/skills/network-forensics/parsers/zeek_suricata_parallel.sh ./evidence/case.pcap` -> exit 0 -> `./analysis/network/zeek/`, `./analysis/network/suricata/eve.json`, `./exports/network/slices/{dns,http,tls}.pcap`, `./analysis/network/flow-index.csv`
- `zeek-cut` -> `zeek-cut id.orig_h id.resp_h proto service duration orig_bytes resp_bytes < ./analysis/network/zeek/conn.log | sort -k7 -nr | head -20` -> exit 0 -> `./analysis/network/zeek/top20-flows.txt`
- `jq` -> `jq -r 'select(.event_type=="alert") | .alert.signature' ./analysis/network/suricata/eve.json | sort | uniq -c | sort -rn` -> exit 0 -> `./analysis/network/suricata/alerts-by-signature.txt`
- `conn_beacon.py` -> `python3 .claude/skills/network-forensics/parsers/conn_beacon.py ./analysis/network/zeek/conn.log` -> exit 0 -> `./analysis/network/zeek/beacon-candidates.csv`
- `tshark (DNS slice)` -> `tshark -r ./exports/network/slices/dns.pcap -Y dns.flags.response==0 -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -E separator=,` -> exit 0 -> `./analysis/network/dns-queries.csv`

## Findings of interest

- Suricata fires `ET MALWARE Generic Cobalt Strike Stager Beacon` 3 times on TCP/443 between `10.0.42.17` and `185.220.101.42` at 2026-04-18 12:05:11Z, 12:09:14Z, 12:13:18Z (~4 min cadence) (`./analysis/network/suricata/eve.json#L1284-L1291`). Lead: `L-EV02-network-01`
- Beacon detector flags the same `10.0.42.17 -> 185.220.101.42:443` flow with interval mean 244 s, jitter 6.2%, score 0.94 — strong periodic-callback signature (`./analysis/network/zeek/beacon-candidates.csv#L4`). Lead: `L-EV02-network-02`
- DNS slice shows `10.0.42.17` queried `news-cdn-update.com` 14 times in 65 minutes, returning the same IP `185.220.101.42` each time — domain has 2-letter TLD pattern + 3-day-old WHOIS not reflected here but flagged by suricata `ET INFO Suspicious Domain` (`./analysis/network/dns-queries.csv#L88-L101`). Lead: `L-EV02-network-03`
- HTTP slice contains a `POST /api/v2/upload` to `185.220.101.42` with `Content-Length: 4194305` at 12:31:02 UTC, no matching prior `GET` from same client — possible exfil (`./analysis/network/zeek/http.log#L42`). Lead: `L-EV02-network-04`

## Lead summary table

| lead_id | priority | hypothesis | next-step query | est-cost |
|---------|----------|------------|-----------------|----------|
| `L-EV02-network-01` | high | `10.0.42.17` is the compromised host actively beaconing to `185.220.101.42:443` (Cobalt Strike) | `tshark -r ./exports/network/slices/tls.pcap -Y "ip.addr==185.220.101.42 && tls.handshake.type==1"` for SNI/JA3 fingerprint; pivot JA3 against published Cobalt Strike profiles | ~2 min |
| `L-EV02-network-02` | high | The 244 s cadence is the default Cobalt Strike sleep mask; jitter < 10% confirms an unmodified profile | `python3 .claude/skills/network-forensics/parsers/conn_beacon.py --strict ./analysis/network/zeek/conn.log` (re-run with stricter threshold) and inspect specific flow rows | ~1 min |
| `L-EV02-network-03` | high | `news-cdn-update.com` is the operator-controlled C2 domain; recent WHOIS + lookalike pattern point at malicious registration | Pivot DNS query log to other internal hosts for the same FQDN; correlator should also test against Sysmon EVTX 22 on host side | ~3 min |
| `L-EV02-network-04` | high | The 4 MB POST is an exfiltrated archive (matches Recycle Bin `report_q1.zip` size from windows-artifacts) | `tshark --export-objects http,./exports/network/http_objects/ -r ./exports/network/slices/http.pcap` then `file` + sha256 of the carved object | ~5 min |

## Negative results

- Suricata Emerging Threats Open ruleset: zero hits on `ET POLICY` / `ET CINS` for the suspect host pair; no NTP/IRC/Tor signatures fired.
- Zeek `notice.log`: no SSL anomalies, no `Weird::expect_certificate_chain`; the TLS handshakes look clean (well-formed cert chain), so attacker is not using a self-signed C2 cert in this capture.
- Zeek `dns.log` filter for NXDOMAIN bursts: top requester is the workstation Active Directory time-sync host, ratio normal — no DGA-style fast-flux behavior.
- Suricata SMB ruleset: no inbound lateral-movement alerts; the workstation did not act as a pivot.

## Open questions

- One non-suspect host (`10.0.42.99`) makes a single `GET /update.php` request to `185.220.101.42` at 12:08 UTC — single hit so not flagged here, but second-host overlap might widen scope; correlator should cross-ref against host-side artifacts on `10.0.42.99`.
- The 4 MB POST has `User-Agent: PowerShell/7.4` — interesting if it correlates to a PowerShell `EvtxECmd Operational --inc 4104` script-block hit on `10.0.42.17`, but that's a windows-artifacts call, not network's lane.
