# Network Forensics — Tier-2/3 Fallback Workflow

Use these recipes when the full Zeek/Suricata/tshark toolchain is partially
absent. The main `SKILL.md` covers Tier-1 (preflight reports
`network-forensics: GREEN`); reach here only when preflight reports YELLOW
or RED.

## When `tshark` is missing

```bash
# Triage with the stdlib parser (DNS extraction is on by default; pass
# --no-dns to skip it)
python3 .claude/skills/network-forensics/parsers/pcap_summary.py \
  ./evidence/case.pcap \
  --top-talkers 20 \
  > ./analysis/network/pcap-triage.csv

# YARA sweep of the pcap as raw bytes
yara -s .claude/skills/yara-hunting/rules/c2-indicators.yar \
  ./evidence/case.pcap > ./analysis/network/yara-pcap-hits.txt

# bulk_extractor for carved L7 strings
bulk_extractor -e net -e url -e domain -e email \
  -o ./exports/network/carved/ ./evidence/case.pcap
```

## When Zeek is missing

`tshark` covers most of what `conn.log` / `dns.log` / `http.log` / `ssl.log`
provide. Use `tshark_wide.py` to batch the seven legacy cheap-signal queries
into a single wide `-T fields` pass plus one `-z` stats pass — same outputs
as the legacy invocations, single read instead of seven:

```bash
python3 .claude/skills/network-forensics/parsers/tshark_wide.py \
    ./evidence/case.pcap \
    --out-dir ./analysis/network
```

Outputs: `dns.csv`, `tls-sni.csv`, `http.csv`, `flow-index.csv`,
`conv-ip.txt`, `conv-ipv6.txt`, `proto-hier.txt`, plus the underlying
`wide.csv`. The `--from-csv` flag re-derives the per-protocol files from an
existing `wide.csv` without another tshark pass.

Beaconing detection without Zeek runs against a tshark CSV:

```bash
tshark -r ./evidence/case.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" \
  -T fields -E separator=, \
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport \
  > ./analysis/network/syn-events.csv

python3 .claude/skills/network-forensics/parsers/conn_beacon.py \
  ./analysis/network/syn-events.csv \
  --tshark-csv \
  > ./analysis/network/beacon-candidates.csv
```

## When Suricata is missing

YARA rules over the pcap are the closest substitute for IDS signatures. Use
the rule set at `.claude/skills/yara-hunting/rules/` and document the
limitation (no network-protocol-aware decoding, no per-flow context) in
`./reports/00_intake.md`.
