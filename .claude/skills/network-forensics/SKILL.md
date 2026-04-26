# Skill: Network Forensics (PCAP / Zeek / Suricata / Flow)

## Use this skill when
- A packet capture (`.pcap`, `.pcapng`, `.cap`) is in scope
- Zeek logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`,
  `x509.log`, `notice.log`) are available — live-collected or generated from a
  pcap with `zeek -r`
- Suricata IDS output is available (`eve.json`, `fast.log`, `stats.log`) or you
  need to run Suricata against a pcap
- NetFlow / IPFIX / sFlow records are in scope (nfcapd files, CSV exports)
- A host-side finding has produced an indicator (IP, domain, JA3, TLS SNI,
  user agent, URI path, certificate hash) and you need to confirm/expand it on
  the wire
- The case asks "what was on the wire?" / "did this host beacon?" / "was data
  exfiltrated?" / "what did the attacker download?"

**Don't reach for this skill when** the case is purely host-based and no pcap
or network log is available — go to `windows-artifacts` (DNS-Client EVTX,
Sysmon ID 3, SRUM bytes) or `memory-analysis` (`windows.netscan`) for the
host's view of network activity instead.

> **Resource constraint — serial tool execution required**
> tshark, Zeek, and Suricata each replay the entire capture file and are
> CPU/RAM-bound. Within a single surveyor or investigator invocation, run them
> **serially** (one completes before the next starts). Do NOT fan them out as
> parallel Bash calls — concurrent replay of a large pcap will saturate the
> SIFT workstation and stall all agents.

## Tool selection — pick by question

| Question | Best tool | Why |
|---|---|---|
| What is in this capture (size, time range, link layer, drops)? | `capinfos <pcap>` | One command; stays small; cheapest possible read |
| Top talkers by bytes / packets | `tshark -q -z conv,ip -r <pcap>` | Built-in conversation table; sortable |
| Protocol hierarchy (% of bytes per protocol) | `tshark -q -z io,phs -r <pcap>` | Surfaces tunneled or unexpected protocols |
| All DNS queries with responses | `tshark -r <pcap> -Y dns -T fields -e frame.time_epoch -e dns.qry.name -e dns.a -e dns.aaaa -E separator=,` | One CSV; easy to grep / pivot |
| TLS SNI + JA3 of every flow | `tshark -r <pcap> -Y "tls.handshake.type==1" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3` | SNI is the only L7 hint inside encrypted traffic |
| HTTP request URIs + Host headers | `tshark -r <pcap> -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.user_agent` | Full L7 visibility for cleartext HTTP |
| Reconstruct one TCP stream | `tshark -r <pcap> -q -z follow,tcp,raw,<stream-index>` or `tcpflow -r <pcap>` | Stream-level reassembly without GUI |
| Carve files transferred over HTTP/SMB/SMTP/FTP | `tshark -r <pcap> --export-objects http,./exports/network/http_objects/ --export-objects smb,./exports/network/smb_objects/` (one tool per protocol) | Cleanest extraction; preserves filenames where present |
| Slice capture by time window | `editcap -A "2026-04-18 12:00:00" -B "2026-04-18 13:00:00" in.pcap out.pcap` | Cheaper than re-running every tool against full capture |
| Slice capture by BPF (host/port) | `tcpdump -r in.pcap -w out.pcap 'host 10.0.0.5 and port 443'` | Filter at libpcap layer — orders of magnitude faster than tshark display filters |
| Merge multiple captures into one chronological pcap | `mergecap -w merged.pcap in1.pcap in2.pcap …` | Native; preserves nanosecond timestamps |
| Anonymize / sanitize a capture before sharing | `tcpdump -r in.pcap -w out.pcap 'not host <internal>'` + `editcap --inject-secrets ` | Always strip before external sharing |
| Generate Zeek logs from a pcap | `zeek -C -r <pcap> Log::default_logdir=./analysis/network/zeek/` | Single command produces 15+ structured logs |
| Run Suricata IDS against a pcap | `suricata -r <pcap> -l ./analysis/network/suricata/ -k none` | `-k none` disables checksum validation (replay traffic often has bad checksums) |
| Group Suricata alerts by signature | `jq -r '.alert.signature' eve.json \| sort \| uniq -c \| sort -rn` | Fastest top-N from JSONL |
| Detect beaconing / C2 jitter from Zeek conn.log | `python3 .claude/skills/network-forensics/parsers/conn_beacon.py ./analysis/network/zeek/conn.log` | Stdlib FFT-free interval analysis; fast triage |
| YARA sweep of pcap as a binary blob | `yara rules.yar <pcap>` | Catches embedded indicators in cleartext payloads |
| Carve indicators from pcap | `bulk_extractor -e net -e url -e domain -e email -o ./exports/carved/ <pcap>` | Recovers L7 strings even from partially-corrupted captures |
| Live capture (rare on SIFT) | `tcpdump -i <iface> -w ./evidence/<host>-<UTC>.pcap -G 3600 -W 24` | Hourly rotation, 24-hour retention; never collect on prod without authorization |

**Rule of thumb:** when the question is "is this IP/domain/URI in here at all?",
let `tshark`'s display filter answer it directly. When the question is
"what's the *story* of this traffic?", run Zeek to produce structured logs and
work from those — then drop back to `tshark` for byte-level confirmation of
specific records the Zeek logs flag.

## Tier reference (what to use when full toolchain is absent)

| Capability | Tier 1 (preferred) | Tier 2 | Tier 3 (stdlib fallback) |
|---|---|---|---|
| pcap metadata | `capinfos` | `tshark -r ... -q -z` | `parsers/pcap_summary.py` (header + linktype + count) |
| Top talkers / DNS / SNI | `tshark` `-T fields` | Zeek `conn.log`/`dns.log`/`ssl.log` | `parsers/pcap_summary.py` (5-tuple flow + DNS qname extraction) |
| Structured network logs | `zeek -r` | — | (none — install Zeek; pcap_summary covers basic triage) |
| IDS alerts | `suricata -r` | snort | (none — install Suricata; YARA sweep is the next-best signature pass) |
| Beaconing detection | RITA over Zeek logs | `parsers/conn_beacon.py` | `parsers/conn_beacon.py` (stdlib only — works directly on TSV `conn.log`) |
| Suricata `eve.json` triage | `jq` + `suricatasc` | `parsers/suricata_eve.py` | `parsers/suricata_eve.py` |
| Zeek log triage | `zeek-cut`, `awk` | `parsers/zeek_triage.py` | `parsers/zeek_triage.py` |
| File carving from pcap | `tshark --export-objects` | `tcpxtract` | `bulk_extractor` (already Tier 1 across project) |

If the answer is "we cannot meaningfully analyse this network evidence at any
tier on this host," flag it in `./reports/00_intake.md` and request the install
rather than producing a half-answer.

## Overview
Network forensics on SIFT is built around four toolchains:

1. **Wireshark CLI suite** (`tshark`, `capinfos`, `mergecap`, `editcap`,
   `dumpcap`) — display-filter-driven analysis of single captures.
2. **Zeek** (formerly Bro) — protocol-aware analyser that turns a pcap into
   structured TSV logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`,
   `files.log`, `x509.log`, `notice.log`, `weird.log`). The structured output
   is what most pivots key off.
3. **Suricata** — signature-based IDS/IPS engine with rich JSON output
   (`eve.json`). Runs offline against a pcap with `-r`.
4. **Carve / hunt utilities** — `bulk_extractor`, `yara`, `tcpflow`, `ngrep`,
   plus the stdlib parsers in `.claude/skills/network-forensics/parsers/` for
   the no-toolchain case.

Always work from a *copy* of the original capture under `./evidence/` —
never modify the source pcap. Outputs land in `./analysis/network/` and
`./exports/network/`.

## Analysis Discipline

`./analysis/` is not just a bucket for raw tool output. Keep both a terse audit
trail and human-written findings as you work.

- `./analysis/forensic_audit.log` — the action that triggers the entry must
  append its own UTC line describing that exact action, the tool or artifact
  reviewed, the result, and why it matters.
- `./analysis/network/findings.md` — append short notes with the artifact
  reviewed, finding, interpretation, and next pivot.
- `./reports/00_intake.md` or the active case report — update it when a
  finding changes the case narrative.

Use this format for audit entries: `<UTC timestamp> | <action> | <finding/result> | <next step>`.
The `action` field must name the exact step that caused the log entry, such as
`zeek -r case.pcap`, `tshark -Y dns extract qnames`, or
`conn_beacon.py jitter pivot on 10.0.0.5`; never use vague text like
`analysis update` or `progress`.
Never rely on the stop hook alone. If it only writes a timestamp, blank summary,
or text that does not describe the triggering action, add the missing
action-specific context manually before moving on.

---

## Preflight first

Run `.claude/skills/dfir-bootstrap/preflight.sh` at case start. Its output tells
you which tier of network tooling is actually available on this SIFT instance:

| Tier | Tools required | Capability |
|---|---|---|
| **Tier 1 — Full** | `tshark` + `zeek` + `suricata` + `capinfos` | Cleartext + structured + IDS + flow analysis |
| **Tier 2 — tshark-only** | `tshark` + `capinfos` (no Zeek/Suricata) | Display-filter analysis; manual L7 reconstruction |
| **Tier 3 — Fallback** | stdlib only | `parsers/pcap_summary.py` for triage; YARA sweep of raw pcap |

Never assume Tier 1. Zeek and Suricata are routinely absent on minimal SIFT
installs. The rest of this skill documents Tier 1 workflow; the fallback
section below maps the same questions to Tier 2/3 commands when needed.

---

## Tool Reference

| Tool | Purpose | Package on SIFT |
|------|---------|-----------------|
| `tshark` | CLI Wireshark — display filters, fields export, stream follow | `tshark` (pulls in `wireshark-common`) |
| `capinfos` | pcap metadata (time range, count, drops, link type, hashes) | `wireshark-common` |
| `mergecap` | Merge multiple captures into one chronological pcap | `wireshark-common` |
| `editcap` | Slice / sample / sanitize captures (by time, count, BPF) | `wireshark-common` |
| `dumpcap` | Lower-level capture utility (rarely used in IR — use `tcpdump`) | `wireshark-common` |
| `tcpdump` | libpcap-based capture & BPF-filtered re-write | `tcpdump` |
| `tcpflow` | TCP stream reassembly to per-flow files | `tcpflow` |
| `ngrep` | grep-style pattern match across packet payloads | `ngrep` |
| `zeek` | Protocol-aware analyser → structured TSV logs | `zeek` (jammy/universe) or upstream APT repo |
| `zeek-cut` | Field extractor for Zeek TSV logs (uses `#fields` header) | shipped with `zeek` |
| `suricata` | Signature-based IDS/IPS; `-r` mode for offline pcap analysis | `suricata` |
| `suricata-update` | Pull and merge ET Open / community rule sources | `suricata-update` |
| `nfdump` | NetFlow v5/v9/IPFIX storage and query | `nfdump` (optional) |
| `bulk_extractor` | Carve email/URL/domain/IP/JSON from raw pcap or stream | `bulk-extractor` |
| `yara` | Signature scan of pcap as a binary file | `yara` |
| `python3` + parsers | Stdlib triage of pcap/Zeek/Suricata when above are missing | `python3` |

> **GUI tools** (Wireshark, NetworkMiner, Brim/Zui) are available but rarely
> needed in CLI-driven workflow. Reach for them only when manual stream
> inspection is the cheapest answer (e.g., reconstructing an HTTP body that
> spans many packets).

---

## Workflow

### 0. Tier-1 baseline gate (MANDATORY when preflight is GREEN)

If `./analysis/preflight.md` reports `network-forensics: GREEN` (i.e. tshark
+ zeek + suricata are all installed), you **MUST** generate the Zeek +
Suricata baseline before any second `tshark -Y` deep-dive query:

```bash
mkdir -p ./analysis/network/zeek ./analysis/network/suricata
( cd ./analysis/network/zeek/ && zeek -C -r ../../../evidence/case.pcap )
suricata -r ./evidence/case.pcap -l ./analysis/network/suricata/ -k none \
  -c /etc/suricata/suricata.yaml
```

**Why mandatory:** structured logs (`conn.log`, `dns.log`, `http.log`,
`ssl.log`, `eve.json`) answer ~80% of network pivots in one pass and prevent
the case7 anti-pattern of re-implementing them by hand via 30+ tshark
queries. tshark deep-dives are for byte-level confirmation of what the
baseline flags, not the primary triage.

The baseline-artifacts contract below is enforced by
`.claude/skills/dfir-bootstrap/baseline-check.sh network`. If a required
artifact is missing when the surveyor's `survey-EV*.md` exists, the
orchestrator emits an `L-BASELINE-network-NN` lead at priority `high` and
the next investigator wave runs it FIRST, before any other open lead.

Tshark-only fallback is permitted ONLY when preflight reports tier 2/3 (no
zeek or no suricata). See § "Fallback workflow" below.

### 1. Verify the capture (always)

```bash
# Identify file type — confirms pcap vs pcapng vs other
file ./evidence/case.pcap

# Hash for chain of custody
sha256sum ./evidence/case.pcap | tee -a ./analysis/network/findings.md

# Metadata: time range, packet count, link type, drops
capinfos ./evidence/case.pcap | tee ./analysis/network/capinfos.txt
```

`capinfos` output drives the rest of the analysis:
- **First/Last packet time** → window for cross-artifact correlation.
- **Capture duration** → if very short (< 1 minute), don't expect long-running
  beaconing patterns to be visible.
- **Number of packets / data byte rate** → sanity-check expected throughput.
- **Strict time order** → if "False", run `mergecap -w ordered.pcap case.pcap`
  before further analysis or some tools mis-report timing.
- **SHA256** → record for chain of custody.

If `capinfos` is unavailable, fall back to:

```bash
python3 .claude/skills/network-forensics/parsers/pcap_summary.py \
  ./evidence/case.pcap --header-only
```

### 2. Cheap signals first (~10 min)

Run these in order. Stop and pivot the moment one returns something worth
chasing.

```bash
# 2a. Top talkers by bytes (IPv4 + IPv6 conversations)
tshark -q -z conv,ip   -r ./evidence/case.pcap > ./analysis/network/conv-ip.txt
tshark -q -z conv,ipv6 -r ./evidence/case.pcap > ./analysis/network/conv-ipv6.txt

# 2b. Protocol hierarchy — surfaces tunneled / unexpected protocols
tshark -q -z io,phs -r ./evidence/case.pcap > ./analysis/network/proto-hier.txt

# 2c. DNS queries (CSV)
tshark -r ./evidence/case.pcap -Y dns \
  -T fields -E separator=, -E quote=d \
  -e frame.time_epoch -e ip.src -e ip.dst \
  -e dns.qry.name -e dns.qry.type \
  -e dns.a -e dns.aaaa -e dns.cname \
  > ./analysis/network/dns.csv

# 2d. TLS SNI + JA3 (visible even inside encrypted traffic)
tshark -r ./evidence/case.pcap -Y "tls.handshake.type==1" \
  -T fields -E separator=, -E quote=d \
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport \
  -e tls.handshake.extensions_server_name -e tls.handshake.ja3 \
  > ./analysis/network/tls-sni.csv

# 2e. HTTP requests (cleartext URIs + Host + UA)
tshark -r ./evidence/case.pcap -Y http.request \
  -T fields -E separator=, -E quote=d \
  -e frame.time_epoch -e ip.src -e ip.dst \
  -e http.host -e http.request.method -e http.request.uri \
  -e http.user_agent -e http.referer \
  > ./analysis/network/http.csv
```

Anomalies that should immediately pivot to deep dive:
- DNS for known DGA-shaped domains (long random labels, base32-shaped)
- DNS over UDP/53 to an external resolver other than the configured one
- TLS SNI to known-suspicious hosts, or `*.tk`/`*.top` fast-flux domains
- HTTP UA strings that don't match any installed browser
- Large outbound flows during off-hours
- Traffic to IPs outside the organisation's allocated ranges with no DNS lookup
  preceding (raw-IP indicators of malware)
- ICMP tunnels (high ICMP byte rate to a single peer)
- Non-standard ports for standard protocols (SSH on tcp/8443, HTTPS on tcp/53)

### 3. Generate Zeek logs (5–60 min depending on capture size)

```bash
mkdir -p ./analysis/network/zeek/
cd ./analysis/network/zeek/
zeek -C -r ../../../evidence/case.pcap

# Optional: enable common community scripts for richer detection
zeek -C -r ../../../evidence/case.pcap \
  local "Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }"
```

Flags worth knowing:
- `-C` — disable checksum verification (replay traffic typically has bad
  checksums; without `-C` you'll see empty `conn.log`).
- `-r <pcap>` — read mode (offline).
- `local` — load `local.zeek` policy (enables HTTP file extraction, Notice
  framework, etc.).
- `Site::local_nets` — defines what counts as "local" for orig/resp direction.
  Set this to match the customer's internal ranges.

Zeek emits one log per protocol/concept, all under the current directory:

| Log | What it contains |
|-----|------------------|
| `conn.log` | Every TCP/UDP/ICMP flow — 5-tuple, bytes, duration, conn-state |
| `dns.log` | DNS queries + answers + RCODE |
| `http.log` | HTTP requests + responses + Host + UA + URI + status |
| `ssl.log` | TLS handshake — SNI, version, JA3, cert chain, ja3s |
| `x509.log` | TLS / S/MIME certificates extracted from the wire |
| `files.log` | Every file Zeek's analyser reconstructed (with hashes if `local`) |
| `notice.log` | Zeek detection-framework notices (scans, weird, etc.) |
| `weird.log` | Protocol oddities |
| `software.log` | Server/client software banners |
| `kerberos.log` | Kerberos auth (KRB5) |
| `smb_*.log` | SMB transactions / file access / mapping |
| `ntp.log` | NTP exchanges |
| `ftp.log` | FTP commands |
| `ssh.log` | SSH banners + auth result |

### 4. Triage Zeek output

```bash
# Top-talker pairs by total bytes (orig_bytes + resp_bytes)
zeek-cut id.orig_h id.resp_h proto service orig_bytes resp_bytes < conn.log \
  | awk -F'\t' 'BEGIN{OFS="\t"} {bytes=$5+$6; key=$1"\t"$2"\t"$3"\t"$4; sum[key]+=bytes} \
                END {for (k in sum) print sum[k], k}' \
  | sort -rn | head -20

# Unique DNS queries (with count)
zeek-cut query < dns.log | sort | uniq -c | sort -rn | head -50

# Long-lived connections (> 1h)
zeek-cut id.orig_h id.resp_h duration service < conn.log \
  | awk -F'\t' '$3 > 3600' | sort -k3 -rn | head

# TLS SNI sorted by JA3
zeek-cut id.resp_h server_name ja3 ja3s < ssl.log | sort -u

# Files Zeek extracted (and hashes, if enabled)
zeek-cut tx_hosts rx_hosts mime_type filename md5 sha1 < files.log
```

If `zeek-cut` is unavailable, the Python triage parser does the same job:

```bash
python3 .claude/skills/network-forensics/parsers/zeek_triage.py \
  ./analysis/network/zeek/ \
  > ./analysis/network/zeek-triage.csv
```

### 5. Beaconing detection

Beaconing — repeated outbound connections at near-fixed intervals — is the
strongest signal for C2 inside encrypted traffic. The fallback parser
implements an interval-jitter check directly against `conn.log`:

```bash
python3 .claude/skills/network-forensics/parsers/conn_beacon.py \
  ./analysis/network/zeek/conn.log \
  --min-connections 12 \
  --max-jitter 0.2 \
  > ./analysis/network/beacon-candidates.csv
```

Outputs ranked candidates: `(src, dst, port, n_conns, mean_interval_s,
jitter, total_bytes)`. Confirm any hit by:

1. Pivoting back to `tshark` with `-Y "ip.src==<src> and ip.dst==<dst>"` and
   inspecting the cadence visually.
2. Checking SNI / JA3 in `ssl.log` for the same flow — does the JA3 match a
   known C2 family?
3. Cross-referencing `<dst>` against passive-DNS / VirusTotal (offline DBs if
   no network from the analyst host).

When RITA is available (not standard on SIFT), it runs the same logic at
much higher fidelity — but the fallback parser is enough for triage.

### 6. Suricata IDS pass

```bash
mkdir -p ./analysis/network/suricata/

# Run Suricata against the pcap with the active rule set
suricata -r ./evidence/case.pcap \
  -l ./analysis/network/suricata/ \
  -k none \
  -c /etc/suricata/suricata.yaml

# Triage eve.json — group alerts by signature
jq -r 'select(.event_type=="alert") | .alert.signature' \
  ./analysis/network/suricata/eve.json \
  | sort | uniq -c | sort -rn | head -50

# Or use the fallback parser (no jq required)
python3 .claude/skills/network-forensics/parsers/suricata_eve.py \
  ./analysis/network/suricata/eve.json \
  > ./analysis/network/suricata-alerts.csv
```

Suricata flags worth knowing:
- `-k none` — skip checksum validation (replay traffic).
- `-c <yaml>` — config; the default uses `/etc/suricata/suricata.yaml` which
  in turn loads `/etc/suricata/rules/`.
- `--runmode single` — disable the multi-thread runner; useful for tiny
  captures.

Update rules before running on a hot case (requires network):
```bash
sudo suricata-update            # pulls ET Open + others
sudo systemctl restart suricata # only if also running live
```

### 7. Stream / file extraction

```bash
# All HTTP objects (one file per response body)
mkdir -p ./exports/network/http_objects/
tshark -r ./evidence/case.pcap \
  --export-objects http,./exports/network/http_objects/

# Reassembled per-flow files (TCP only)
mkdir -p ./exports/network/tcpflow/
cd ./exports/network/tcpflow/
tcpflow -r ../../../evidence/case.pcap

# A specific TCP stream as raw bytes (find index via tshark display first)
tshark -r ./evidence/case.pcap -Y "tcp.stream eq 47" -w stream-47.pcap

# Carved indicators (URLs / emails / domains) from the pcap as a blob
bulk_extractor -e net -e url -e domain -e email \
  -o ./exports/network/carved/ ./evidence/case.pcap
```

### 8. NetFlow / IPFIX

When the evidence is flow records (no pcap):

```bash
# nfcapd binary records → readable
nfdump -R ./evidence/flows/ -o extended -A srcip,dstip,dstport \
  > ./analysis/network/flows-by-dst.txt

# CSV-formatted NetFlow exports — fall back to awk
awk -F',' 'NR>1 {print $5,$6,$7,$8}' ./evidence/flows.csv \
  | sort | uniq -c | sort -rn | head -50
```

Flow-only evidence loses payload (no DNS qname, no SNI, no HTTP URI), so
limit conclusions to volume + endpoint pairs and explicitly note the gap in
`./reports/00_intake.md`.

---

## Fallback workflow (Tier 2/3) — when toolchain is partially absent

### When `tshark` is missing

```bash
# Triage with the stdlib parser
python3 .claude/skills/network-forensics/parsers/pcap_summary.py \
  ./evidence/case.pcap \
  --top-talkers 20 \
  --dns \
  > ./analysis/network/pcap-triage.csv

# YARA sweep of the pcap as raw bytes
yara -s .claude/skills/yara-hunting/rules/c2-indicators.yar \
  ./evidence/case.pcap > ./analysis/network/yara-pcap-hits.txt

# bulk_extractor for carved L7 strings
bulk_extractor -e net -e url -e domain -e email \
  -o ./exports/network/carved/ ./evidence/case.pcap
```

### When Zeek is missing

`tshark` covers most of what `conn.log` / `dns.log` / `http.log` / `ssl.log`
provide — see the "Cheap signals first" section above for the field-export
commands. Beaconing detection without Zeek runs against a tshark CSV:

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

### When Suricata is missing

YARA rules over the pcap are the closest substitute for IDS signatures. Use
the rule set at `.claude/skills/yara-hunting/rules/` and document the
limitation (no network-protocol-aware decoding, no per-flow context) in
`./reports/00_intake.md`.

---

## Output Paths

| Output | Path |
|--------|------|
| Capture metadata | `./analysis/network/capinfos.txt` |
| tshark conversation tables | `./analysis/network/conv-ip.txt`, `conv-ipv6.txt` |
| tshark protocol hierarchy | `./analysis/network/proto-hier.txt` |
| DNS / TLS / HTTP CSVs | `./analysis/network/dns.csv`, `tls-sni.csv`, `http.csv` |
| Zeek logs | `./analysis/network/zeek/*.log` |
| Zeek triage CSV | `./analysis/network/zeek-triage.csv` |
| Beaconing candidates | `./analysis/network/beacon-candidates.csv` |
| Suricata logs | `./analysis/network/suricata/eve.json`, `fast.log`, `stats.log` |
| Suricata triage CSV | `./analysis/network/suricata-alerts.csv` |
| Carved L7 indicators | `./exports/network/carved/` |
| Reassembled HTTP objects | `./exports/network/http_objects/` |
| TCP flow files | `./exports/network/tcpflow/` |
| Per-stream pcaps | `./exports/network/streams/` |
| Findings | `./analysis/network/findings.md` |

Always write to `./analysis/` or `./exports/` — never to `./evidence/` or
`/mnt/`.

---

## Required baseline artifacts

This block is parsed by
`.claude/skills/dfir-bootstrap/baseline-check.sh network`. `required` rows
are checked at every gate; `required-tier1` rows are checked only when
preflight reports `network-forensics: GREEN`. Missing artifacts produce a
high-priority `L-BASELINE-network-NN` lead that runs first in the next
investigator wave.

<!-- baseline-artifacts:start -->
required: analysis/network/capinfos.txt
required-tier1: analysis/network/zeek/conn.log
required-tier1: analysis/network/zeek/dns.log
required-tier1: analysis/network/suricata/eve.json
optional: analysis/network/proto-hier.txt
optional: analysis/network/conv-ip.txt
optional: analysis/network/conv-ipv6.txt
optional: analysis/network/dns.csv
optional: analysis/network/tls-sni.csv
optional: analysis/network/http.csv
<!-- baseline-artifacts:end -->

---

## Pivots — what to do with what you found here

| Found here | Pivot to | Skill |
|---|---|---|
| Outbound flow to suspect IP | (a) host's `windows.netscan` or Sysmon ID 3 for process attribution, (b) DNS query that resolved that IP, (c) browser history if userland, (d) SRUM bytes for the same window | `memory-analysis` + `windows-artifacts` |
| Suspicious DNS qname | (a) DNS-Client EVTX 3008 on host, (b) browser history for parent page, (c) DNS cache in memory, (d) YARA the qname literal across disk + memory | `windows-artifacts` + `memory-analysis` + `yara-hunting` |
| TLS SNI / JA3 match for a known C2 family | (a) extract more IOCs from the family's reporting (mutex, named pipe, file hashes), (b) build a YARA rule, (c) sweep memory + disk + EVTX strings | `yara-hunting` + `memory-analysis` |
| Cleartext HTTP UA mismatch | (a) Prefetch / Amcache for the binary that emitted it, (b) Sysmon 1 cmdline, (c) carve the binary if not on disk, (d) hash + YARA | `windows-artifacts` + `sleuthkit` + `yara-hunting` |
| Beaconing candidate (low jitter, high count) | (a) pivot back to tshark for visual cadence confirmation, (b) JA3 / SNI for the flow, (c) memory `netscan` if image present, (d) timeline-slice host activity at the same intervals | this skill + `memory-analysis` + `plaso-timeline` |
| File carved from HTTP / SMB | (a) hash, (b) YARA, (c) cross-reference to host filesystem (was it written to disk?), (d) `$J` for create time on host | `yara-hunting` + `sleuthkit` + `windows-artifacts` |
| Suricata alert (e.g., ET TROJAN) | (a) confirm payload bytes match signature with `tshark -Y` on the flow, (b) extract any L7 indicators (URL, host, UA), (c) build YARA from those, (d) sweep host evidence | `yara-hunting` + `windows-artifacts` |
| RDP traffic from external IP | RDP 1149 + 4624 Type 10 on the destination host; LogonType + source workstation | `windows-artifacts` |
| SMB write of executable to admin share | (a) on destination host: `$J` for the file, (b) 7045 service install in same window (PsExec signature), (c) memory psscan for the spawned process | `windows-artifacts` + `memory-analysis` |
| Large data-exfil flow | (a) browser history for cloud-storage uploads in same window, (b) USB plug-in events (was it staged via USB instead?), (c) SRUM bytes for the user's apps | `windows-artifacts` |
| Anomaly Zeek flagged in `weird.log` | Inspect the flow with `tshark -Y "frame.number==<N>"`; protocol-tunneling and L4 evasions live here | this skill |
| Indicator string (URL, domain, hash, mutex) recovered from carve | Build YARA, sweep `./exports/files/` and memory image | `yara-hunting` |

---

## Notes

- **Never modify the source pcap.** Always work from a copy under
  `./evidence/`. `editcap` and `mergecap` write new files; their inputs are
  read-only by design — but `tcpdump -w` will silently overwrite if the
  destination exists, so always `-w ./exports/network/...` not `./evidence/...`.
- **Time order matters.** If `capinfos` reports "Strict time order: False",
  run `mergecap -w ordered.pcap original.pcap` before any time-sensitive
  analysis — Zeek and Suricata both produce silently-wrong results on
  out-of-order captures.
- **Replay checksums are usually wrong.** Use `zeek -C` and `suricata -k none`
  unless the capture was taken on the live wire by you.
- **Zeek's `local.zeek` enables file extraction and notice scripts.** The
  bare `zeek -r case.pcap` invocation produces the protocol logs but not the
  file objects; load `local` for richer output.
- **Suricata rule set licensing.** ET Open is free; ET Pro and Talos require
  subscriptions. `suricata-update` defaults to ET Open — confirm policy with
  the case lead before relying on Pro/Talos signatures.
- **Beaconing detection has high false-positive rate.** Browser keepalives,
  NTP, automatic update checks, and antivirus phone-home all look like
  beaconing. Always confirm with JA3/SNI + process attribution before
  reporting.
- **Encrypted traffic limits conclusions.** SNI + JA3 + cert chain + flow size
  + cadence are the only L7-adjacent signals. State this gap explicitly in
  `findings.md` and `00_intake.md` rather than overclaiming.
- **Live capture is rarely the right call.** Most cases analyse pre-captured
  evidence. If live capture is in scope, get written authorization first and
  capture to `./evidence/<host>-<UTC>.pcap` with strict rotation
  (`tcpdump -G 3600 -W 24`) — never to a path Claude or another tool might
  rewrite.
