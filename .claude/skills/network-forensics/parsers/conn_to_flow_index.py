#!/usr/bin/env python3
"""
conn_to_flow_index.py — Aggregate Zeek conn.log into a per-IP-pair flow index.

Reads ./analysis/network/zeek/conn.log (TSV with Zeek's #fields header) and
emits flow-index.csv. Investigators use it as a cheap "is host X in this
capture?" lookup so they don't re-scan the original pcap.

Why this script exists: Zeek already classifies every flow with full
protocol/service context, so deriving the flow index from conn.log is more
accurate than parsing tshark's ASCII conv,ip table. It also keeps the
network-forensics Tier-1 baseline single-tool (Zeek + Suricata only — no
redundant tshark passes when Zeek has already answered the same question).

Usage:
    conn_to_flow_index.py <conn.log>
    conn_to_flow_index.py <conn.log> --out ./analysis/network/flow-index.csv

Schema (CSV, all fields double-quoted):
    family,a,b,frames_a_to_b,bytes_a_to_b,frames_b_to_a,bytes_b_to_a,frames_total,bytes_total

Where:
    a              = id.orig_h (connection initiator, per Zeek)
    b              = id.resp_h (responder)
    frames_a_to_b  = sum of orig_pkts across every flow between a and b
    bytes_a_to_b   = sum of orig_ip_bytes (includes IP header bytes)
    frames_b_to_a  = sum of resp_pkts
    bytes_b_to_a   = sum of resp_ip_bytes
    *_total        = a→b plus b→a

Rows are sorted by bytes_total descending so the heaviest pairs surface first.

Exit codes:
    0 success
    1 conn.log present but malformed (no #fields header, etc.)
    2 conn.log not found / bad arguments
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


def parse_conn_log(path: Path):
    """Yield row dicts from a Zeek conn.log.

    Auto-detects format from the first non-blank byte:
      - '{'  → JSON-Lines (one object per line; produced by
        `LogAscii::use_json=T`).
      - '#'  → TSV with `#fields` header (Zeek default).

    Mirrors the auto-detection in sibling parsers (`zeek_triage.py`,
    `conn_beacon.py`) so all three accept the same conn.log regardless of
    the upstream Zeek logging policy.
    """
    fields: list[str] | None = None
    with path.open("r", errors="replace") as fh:
        first = fh.readline()
        if not first:
            return
        if first.lstrip().startswith("{"):
            try:
                yield json.loads(first)
            except json.JSONDecodeError:
                pass
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
            return

        # TSV path — replay the first line through the regular handler.
        for raw in [first] + list(fh):
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if fields is None:
                continue
            cols = line.split("\t")
            if len(cols) != len(fields):
                continue
            yield dict(zip(fields, cols))


def to_int(x: str | None) -> int:
    """Zeek writes '-' for null; coerce that and any non-numeric to 0."""
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("conn_log", help="Path to Zeek conn.log (TSV or JSON-Lines)")
    ap.add_argument("--out", default="./analysis/network/flow-index.csv",
                    help="Output CSV path (default: ./analysis/network/flow-index.csv)")
    args = ap.parse_args(argv[1:])

    src = Path(args.conn_log)
    if not src.exists():
        sys.stderr.write(f"no such file: {src}\n")
        return 2

    # Quick sniff: a Zeek conn.log opens with either a '#' comment block
    # (TSV format, default) or '{' (JSON-Lines if logged with use_json=T).
    with src.open("r", errors="replace") as fh:
        first = fh.readline().lstrip()
    if not (first.startswith("#") or first.startswith("{")):
        sys.stderr.write(f"{src} does not look like a Zeek log "
                         "(expected leading '#' header or '{' JSON-Line)\n")
        return 1

    agg: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    for row in parse_conn_log(src):
        a = row.get("id.orig_h", "")
        b = row.get("id.resp_h", "")
        if not a or not b:
            continue
        family = "ipv6" if (":" in a or ":" in b) else "ipv4"
        key = (family, a, b)
        agg[key][0] += to_int(row.get("orig_pkts"))
        agg[key][1] += to_int(row.get("orig_ip_bytes"))
        agg[key][2] += to_int(row.get("resp_pkts"))
        agg[key][3] += to_int(row.get("resp_ip_bytes"))

    rows = []
    for (fam, a, b), v in agg.items():
        rows.append({
            "family": fam, "a": a, "b": b,
            "frames_a_to_b": v[0], "bytes_a_to_b": v[1],
            "frames_b_to_a": v[2], "bytes_b_to_a": v[3],
            "frames_total":  v[0] + v[2],
            "bytes_total":   v[1] + v[3],
        })
    rows.sort(key=lambda r: r["bytes_total"], reverse=True)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cols = ["family", "a", "b",
            "frames_a_to_b", "bytes_a_to_b",
            "frames_b_to_a", "bytes_b_to_a",
            "frames_total", "bytes_total"]
    with out_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, quoting=csv.QUOTE_ALL)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"[conn_to_flow_index] {len(rows)} pair(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
