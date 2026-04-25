#!/usr/bin/env python3
"""
conn_beacon.py — Beaconing / C2 jitter detection (stdlib only).

Reads connection events and ranks (src, dst, port) tuples by how much they
look like beaconing — i.e. repeated outbound connections at near-fixed
intervals.

Two input formats are supported:

  1. Zeek conn.log (default) — TSV with `#fields` header, or JSON-Lines if
     produced with `LogAscii::use_json=T`.
     Required fields: ts, id.orig_h, id.resp_h, id.resp_p, orig_bytes,
     resp_bytes.

  2. tshark CSV (with `--tshark-csv`) — produced by:
         tshark -r case.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" \
           -T fields -E separator=, \
           -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport
     One SYN per row; the timestamp drives interval analysis.

Scoring metric: `jitter = stdev(intervals) / mean(intervals)`. Low jitter +
high connection count = beaconing-shaped traffic. The cutoff defaults
(min_connections=10, max_jitter=0.30) are deliberately loose for triage —
tighten with --max-jitter 0.15 once you have a baseline of what's normal in
the environment.

Usage:
    conn_beacon.py <conn.log>                                  # Zeek mode
    conn_beacon.py <syn-events.csv> --tshark-csv               # tshark mode
    conn_beacon.py <conn.log> --min-connections 20 --max-jitter 0.15

Output: CSV ranked by score (highest beacon-likelihood first).

Exit codes:
    0 success
    1 no flows met the minimum connection threshold
    2 bad arguments
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterator


def iter_zeek_conn(path: Path) -> Iterator[dict]:
    """Walk a conn.log (TSV or JSON-Lines) and yield records."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        if not first:
            return
        if first.startswith("{"):
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

        sep = "\t"
        fields: list[str] = []
        unset_field = "-"
        line = first
        while line:
            if not line.startswith("#"):
                break
            if line.startswith("#separator"):
                tail = line.rstrip("\n").split(" ", 1)[1].strip()
                if tail.startswith("\\x"):
                    sep = bytes.fromhex(tail.replace("\\x", "")).decode("latin-1")
            elif line.startswith("#fields"):
                fields = line.rstrip("\n").split(sep)[1:]
            elif line.startswith("#unset_field"):
                unset_field = line.rstrip("\n").split(sep, 1)[1]
            line = fh.readline()
        if not fields:
            return
        while line:
            stripped = line.rstrip("\n")
            if stripped and not stripped.startswith("#"):
                vals = stripped.split(sep)
                rec = {f: (None if (i >= len(vals) or vals[i] == unset_field)
                           else vals[i])
                       for i, f in enumerate(fields)}
                yield rec
            line = fh.readline()


def iter_tshark_csv(path: Path) -> Iterator[dict]:
    """Walk a tshark `-T fields` CSV: ts,src,dst,dport[,bytes]."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row or len(row) < 4:
                continue
            try:
                ts = float(row[0])
            except (ValueError, IndexError):
                continue
            yield {
                "ts": ts,
                "id.orig_h": row[1],
                "id.resp_h": row[2],
                "id.resp_p": row[3],
                "orig_bytes": row[4] if len(row) > 4 else "0",
                "resp_bytes": "0",
            }


def score(intervals: list[float]) -> tuple[float, float, float]:
    """Return (mean_interval, jitter, score). Higher score = more beacon-shaped."""
    if len(intervals) < 2:
        return 0.0, 1.0, 0.0
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return 0.0, 1.0, 0.0
    sd = statistics.pstdev(intervals)
    jitter = sd / mean
    # Score rewards low jitter and high count, penalises sub-second mean
    # (pings, retransmits, microbursts).
    count_factor = math.log10(len(intervals) + 1)
    interval_factor = 1.0 if mean >= 5 else mean / 5.0
    s = (1.0 - min(jitter, 1.0)) * count_factor * interval_factor
    return mean, jitter, s


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="conn.log or tshark CSV")
    ap.add_argument("--tshark-csv", action="store_true",
                    help="Treat input as tshark -T fields CSV instead of Zeek conn.log")
    ap.add_argument("--min-connections", type=int, default=10,
                    help="Minimum connection count to consider (default: 10)")
    ap.add_argument("--max-jitter", type=float, default=0.30,
                    help="Maximum jitter (stdev/mean) for a beacon candidate (default: 0.30)")
    ap.add_argument("--top", type=int, default=100,
                    help="Number of top candidates to print (default: 100)")
    args = ap.parse_args(argv[1:])

    path = Path(args.input)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2

    iterator = iter_tshark_csv(path) if args.tshark_csv else iter_zeek_conn(path)

    flows: defaultdict[tuple, list] = defaultdict(lambda: [[], 0, 0])
    # key: (src, dst, port) -> [ts_list, total_orig_bytes, total_resp_bytes]
    for rec in iterator:
        try:
            ts = float(rec.get("ts") or rec.get("timestamp") or 0)
        except (TypeError, ValueError):
            continue
        if ts <= 0:
            continue
        src = rec.get("id.orig_h") or ""
        dst = rec.get("id.resp_h") or ""
        port = str(rec.get("id.resp_p") or "")
        if not src or not dst or not port:
            continue
        key = (src, dst, port)
        flows[key][0].append(ts)
        try:
            flows[key][1] += int(float(rec.get("orig_bytes") or 0))
        except (TypeError, ValueError):
            pass
        try:
            flows[key][2] += int(float(rec.get("resp_bytes") or 0))
        except (TypeError, ValueError):
            pass

    candidates: list[dict] = []
    for (src, dst, port), (ts_list, ob, rb) in flows.items():
        if len(ts_list) < args.min_connections:
            continue
        ts_sorted = sorted(ts_list)
        intervals = [ts_sorted[i + 1] - ts_sorted[i]
                     for i in range(len(ts_sorted) - 1)]
        intervals = [iv for iv in intervals if iv > 0]
        if len(intervals) < 2:
            continue
        mean, jitter, s = score(intervals)
        if jitter > args.max_jitter:
            continue
        candidates.append({
            "src": src,
            "dst": dst,
            "port": port,
            "n_conns": len(ts_sorted),
            "first_ts": ts_sorted[0],
            "last_ts": ts_sorted[-1],
            "mean_interval_s": round(mean, 3),
            "jitter": round(jitter, 4),
            "score": round(s, 4),
            "orig_bytes": ob,
            "resp_bytes": rb,
        })

    if not candidates:
        print("no flows met the beaconing threshold; try lowering "
              "--min-connections or raising --max-jitter", file=sys.stderr)
        return 1

    candidates.sort(key=lambda c: c["score"], reverse=True)

    w = csv.writer(sys.stdout)
    fields = ["src", "dst", "port", "n_conns", "mean_interval_s", "jitter",
              "score", "orig_bytes", "resp_bytes", "first_ts", "last_ts"]
    w.writerow(fields)
    for c in candidates[:args.top]:
        w.writerow([c.get(f, "") for f in fields])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
