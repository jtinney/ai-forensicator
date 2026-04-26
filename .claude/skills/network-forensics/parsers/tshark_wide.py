#!/usr/bin/env python3
"""
tshark_wide.py — single-pass wide-field tshark wrapper + CSV splitter.

Replaces the seven serial tshark invocations in the network-forensics cheap-
signal block (DNS, TLS SNI, HTTP, conv-ip, conv-ipv6, proto-hier) with one
wide -T fields pass plus one -z stats pass. The wide CSV is then split into
the same per-protocol CSVs the operator already expects, plus a flow-index
that downstream investigators can grep instead of re-scanning the original.

Usage:
    tshark_wide.py <file.pcap[ng]> [--out-dir ./analysis/network]
    tshark_wide.py --from-csv wide.csv --out-dir ./analysis/network

Inputs:
    pcap path (default mode), or pre-existing wide.csv via --from-csv
Outputs (in --out-dir):
    wide.csv          # raw tshark -T fields output, full row per packet
    dns.csv           # subset: rows with dns.qry.name set
    tls-sni.csv       # subset: rows with tls.handshake.extensions_server_name
    http.csv          # subset: rows with http.request.method
    conv-ip.txt       # tshark -z conv,ip stats
    conv-ipv6.txt     # tshark -z conv,ipv6 stats
    proto-hier.txt    # tshark -z io,phs stats
    flow-index.csv    # parsed conv-ip + conv-ipv6 → 5-tuple-ish flow rows

Exit codes:
    0 success
    1 tshark exec failure or input parse error
    2 bad arguments / file not found
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path

# Wide-field schema — order matches what we ask tshark for and what we write.
# `tls.handshake.type` is included so the splitter can route TLS handshakes
# even when the SNI extension is absent (rare but legal — would otherwise be
# silently dropped). `tls.handshake.ja3` populates only when JA3 support is
# present (Wireshark ≥ 4.0 native, or older tshark with the ja3.lua plugin).
WIDE_FIELDS = [
    "frame.time_epoch", "frame.len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.cname",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name", "tls.handshake.ja3",
    "http.host", "http.request.method", "http.request.uri",
    "http.user_agent", "http.referer",
]
WIDE_DISPLAY_FILTER = "dns or tls.handshake.type==1 or http.request"

# Per-protocol output schemas. `src` / `dst` are synthesized columns that
# coalesce ip.src/ipv6.src (and ip.dst/ipv6.dst) so IPv6 rows aren't blank in
# the per-protocol CSVs.
DNS_COLS = ["frame.time_epoch", "src", "dst",
            "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.cname"]
TLS_COLS = ["frame.time_epoch", "src", "dst", "tcp.dstport",
            "tls.handshake.extensions_server_name", "tls.handshake.ja3"]
HTTP_COLS = ["frame.time_epoch", "src", "dst",
             "http.host", "http.request.method", "http.request.uri",
             "http.user_agent", "http.referer"]


def run_tshark_wide(pcap: Path, out_csv: Path) -> int:
    cmd = [
        "tshark", "-r", str(pcap),
        "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d",
    ]
    for f in WIDE_FIELDS:
        cmd += ["-e", f]
    cmd += ["-Y", WIDE_DISPLAY_FILTER]
    with out_csv.open("wb") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        sys.stderr.write(f"tshark wide-pass exit {proc.returncode}: "
                         f"{proc.stderr.decode(errors='replace')[:400]}\n")
    return proc.returncode


def run_tshark_stats(pcap: Path, out_dir: Path) -> int:
    # Single tshark invocation produces all three stat reports interleaved on
    # stdout, separated by '====' banners. We split them by banner rather than
    # running three separate -q -z passes.
    cmd = [
        "tshark", "-q", "-r", str(pcap),
        "-z", "conv,ip", "-z", "conv,ipv6", "-z", "io,phs",
    ]
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(f"tshark stats-pass exit {proc.returncode}: "
                         f"{proc.stderr.decode(errors='replace')[:400]}\n")
        return proc.returncode

    out = proc.stdout.decode(errors="replace")
    chunks = split_stats_output(out)
    (out_dir / "conv-ip.txt").write_text(chunks.get("ipv4_conversations", ""))
    (out_dir / "conv-ipv6.txt").write_text(chunks.get("ipv6_conversations", ""))
    (out_dir / "proto-hier.txt").write_text(chunks.get("protocol_hierarchy", ""))
    return 0


def split_stats_output(text: str) -> dict[str, str]:
    """Split tshark -q -z output into named chunks keyed by report title."""
    out: dict[str, str] = {}
    chunks = re.split(r"^=+\s*$", text, flags=re.MULTILINE)
    chunks = [c for c in chunks if c.strip()]
    # tshark's -z reports interleave: title line is the first non-blank line of
    # each chunk that doesn't start with whitespace. Map each chunk by sniffing
    # its first content line.
    for i in range(len(chunks)):
        chunk = chunks[i].strip("\n")
        first = next((ln for ln in chunk.splitlines() if ln.strip()), "")
        key = ""
        if "IPv4 Conversations" in first:
            key = "ipv4_conversations"
        elif "IPv6 Conversations" in first:
            key = "ipv6_conversations"
        elif "Protocol Hierarchy" in first:
            key = "protocol_hierarchy"
        if key:
            # Re-attach a banner around the body so the saved file looks like
            # vanilla tshark output to anything that already greps for '====='.
            out[key] = f"=" * 80 + "\n" + chunk + "\n" + "=" * 80 + "\n"
    return out


def _coalesce_ip(row: dict) -> dict:
    """Populate synthesized src/dst columns from ip.* or ipv6.*. Mutates row."""
    src4 = (row.get("ip.src") or "").strip(' "')
    src6 = (row.get("ipv6.src") or "").strip(' "')
    dst4 = (row.get("ip.dst") or "").strip(' "')
    dst6 = (row.get("ipv6.dst") or "").strip(' "')
    row["src"] = src4 or src6
    row["dst"] = dst4 or dst6
    return row


def split_wide_csv(wide_csv: Path, out_dir: Path) -> tuple[int, int, int]:
    """Read wide.csv and write dns.csv / tls-sni.csv / http.csv."""
    dns_n = tls_n = http_n = 0
    with wide_csv.open("r", newline="") as fh, \
         (out_dir / "dns.csv").open("w", newline="") as df, \
         (out_dir / "tls-sni.csv").open("w", newline="") as tf, \
         (out_dir / "http.csv").open("w", newline="") as hf:
        reader = csv.DictReader(fh)
        dw = csv.DictWriter(df, fieldnames=DNS_COLS, extrasaction="ignore",
                            quoting=csv.QUOTE_ALL)
        tw = csv.DictWriter(tf, fieldnames=TLS_COLS, extrasaction="ignore",
                            quoting=csv.QUOTE_ALL)
        hw = csv.DictWriter(hf, fieldnames=HTTP_COLS, extrasaction="ignore",
                            quoting=csv.QUOTE_ALL)
        dw.writeheader(); tw.writeheader(); hw.writeheader()
        for row in reader:
            _coalesce_ip(row)
            # Order matters: same packet can technically match >1 filter (rare),
            # so we route on the most-specific signal first.
            # Routing intentionally checks tls.handshake.type==1 (ClientHello),
            # NOT just SNI presence — SNI-less ClientHellos used to be silently
            # dropped under the old SNI-only check.
            if row.get("dns.qry.name", "").strip(' "'):
                dw.writerow(row); dns_n += 1
            elif row.get("tls.handshake.type", "").strip(' "') == "1":
                tw.writerow(row); tls_n += 1
            elif row.get("http.request.method", "").strip(' "'):
                hw.writerow(row); http_n += 1
    return dns_n, tls_n, http_n


# tshark conv,ip output line — 8 numeric columns after the IP-pair.
# Format (single row, fixed-ish whitespace):
#   <a>  <-> <b>   frames bytes [bytes]  frames bytes [bytes]  frames bytes [bytes]  rel_start  duration
# tshark ≥ 3.x suffixes byte values with the literal " bytes" and uses
# thousands separators in large counts (e.g. "1,190 bytes"). Older builds
# emitted bare integers. This regex tolerates both, plus an optional unit on
# every byte column.
#
# Column semantics per Wireshark's epan/conversation_table.c:
#   "<-" Frames/Bytes  =  packets received by A   (b → a direction)
#   "->" Frames/Bytes  =  packets sent by A       (a → b direction)
# We capture them in tshark's order (b→a first, then a→b) and assign them to
# the schema's a→b / b→a columns explicitly so direction is preserved.
CONV_LINE = re.compile(
    r"^\s*(\S+)\s+<->\s+(\S+)\s+"
    r"(\d+)\s+([\d,]+)(?:\s+bytes)?\s+"   # <-  : frames, bytes  (b → a)
    r"(\d+)\s+([\d,]+)(?:\s+bytes)?\s+"   # ->  : frames, bytes  (a → b)
    r"(\d+)\s+([\d,]+)(?:\s+bytes)?\s+"   # Total: frames, bytes
    r"\S+\s+\S+\s*$"                        # rel_start, duration (formats vary)
)


def _to_int(s: str) -> int:
    """Strip thousands-separator commas and parse to int."""
    return int(s.replace(",", ""))


def parse_conv_text(path: Path, family: str) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for raw in path.read_text(errors="replace").splitlines():
        if "<->" not in raw:
            continue
        m = CONV_LINE.match(raw)
        if not m:
            continue
        # Capture order matches tshark's column order (<-, ->, Total).
        a, b, fb2a, bb2a, fa2b, ba2b, ftot, btot = m.groups()
        rows.append({
            "family": family,
            "a": a, "b": b,
            "frames_a_to_b": _to_int(fa2b), "bytes_a_to_b": _to_int(ba2b),
            "frames_b_to_a": _to_int(fb2a), "bytes_b_to_a": _to_int(bb2a),
            "frames_total":  _to_int(ftot), "bytes_total":  _to_int(btot),
        })
    return rows


def write_flow_index(out_dir: Path) -> int:
    rows = []
    rows += parse_conv_text(out_dir / "conv-ip.txt", "ipv4")
    rows += parse_conv_text(out_dir / "conv-ipv6.txt", "ipv6")
    rows.sort(key=lambda r: r["bytes_total"], reverse=True)
    cols = ["family", "a", "b",
            "frames_a_to_b", "bytes_a_to_b",
            "frames_b_to_a", "bytes_b_to_a",
            "frames_total", "bytes_total"]
    with (out_dir / "flow-index.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, quoting=csv.QUOTE_ALL)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return len(rows)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?", help="Path to .pcap or .pcapng file")
    ap.add_argument("--out-dir", default="./analysis/network",
                    help="Output directory (default: ./analysis/network)")
    ap.add_argument("--from-csv",
                    help="Skip tshark; split an existing wide.csv instead")
    args = ap.parse_args(argv[1:])

    if not args.pcap and not args.from_csv:
        ap.error("either pcap path or --from-csv is required")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    wide_csv = Path(args.from_csv) if args.from_csv else out_dir / "wide.csv"

    if not args.from_csv:
        pcap = Path(args.pcap)
        if not pcap.exists():
            sys.stderr.write(f"no such file: {pcap}\n")
            return 2
        rc = run_tshark_wide(pcap, wide_csv)
        if rc != 0:
            return 1
        rc = run_tshark_stats(pcap, out_dir)
        if rc != 0:
            return 1

    if not wide_csv.exists():
        sys.stderr.write(f"wide CSV not found: {wide_csv}\n")
        return 1

    dns_n, tls_n, http_n = split_wide_csv(wide_csv, out_dir)
    flow_n = write_flow_index(out_dir)

    print(f"[tshark_wide] dns={dns_n} tls={tls_n} http={http_n} flows={flow_n}")
    print(f"[tshark_wide] outputs: {out_dir}/{{wide,dns,tls-sni,http,flow-index}}.csv "
          f"{out_dir}/{{conv-ip,conv-ipv6,proto-hier}}.txt")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
