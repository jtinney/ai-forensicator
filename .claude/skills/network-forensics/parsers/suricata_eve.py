#!/usr/bin/env python3
"""
suricata_eve.py — Stdlib triage of a Suricata eve.json file.

Substitutes for `jq | sort | uniq -c` pipelines when jq is missing or when a
single-pass summary is faster than four separate jq invocations.

eve.json is JSON-Lines: one JSON object per line. Suricata emits multiple
event types into the same file: `alert`, `dns`, `http`, `tls`, `flow`,
`fileinfo`, `anomaly`, `stats`. This script focuses on the events that drive
investigation: `alert`, `fileinfo`, `anomaly`.

Usage:
    suricata_eve.py <path/to/eve.json>           # CSV to stdout
    suricata_eve.py <path/to/eve.json> --json    # JSON to stdout
    suricata_eve.py <path/to/eve.json> --severity 1   # only severity <= 1

Exit codes:
    0 success
    1 no records found
    2 bad arguments
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("eve", help="Path to eve.json")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON instead of CSV")
    ap.add_argument("--severity", type=int, default=None,
                    help="Only include alerts with severity <= N")
    args = ap.parse_args(argv[1:])

    path = Path(args.eve)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2

    by_signature: Counter[tuple[int, str, int]] = Counter()
    by_category: Counter[str] = Counter()
    by_dst: Counter[tuple[str, int]] = Counter()  # (dst_ip, dst_port)
    by_src: Counter[str] = Counter()
    file_events: list[dict] = []
    anomalies: Counter[str] = Counter()
    total_records = 0
    total_alerts = 0

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total_records += 1
            etype = rec.get("event_type")
            if etype == "alert":
                a = rec.get("alert") or {}
                sev = int(a.get("severity") or 99)
                if args.severity is not None and sev > args.severity:
                    continue
                total_alerts += 1
                sid = int(a.get("signature_id") or 0)
                sig = a.get("signature") or ""
                cat = a.get("category") or ""
                key = (sid, sig, sev)
                by_signature[key] += 1
                if cat:
                    by_category[cat] += 1
                src = rec.get("src_ip") or ""
                dst = rec.get("dest_ip") or ""
                dport = int(rec.get("dest_port") or 0)
                if src:
                    by_src[src] += 1
                if dst:
                    by_dst[(dst, dport)] += 1
            elif etype == "fileinfo":
                fi = rec.get("fileinfo") or {}
                file_events.append({
                    "timestamp": rec.get("timestamp") or "",
                    "src_ip": rec.get("src_ip") or "",
                    "dst_ip": rec.get("dest_ip") or "",
                    "filename": fi.get("filename") or "",
                    "magic": fi.get("magic") or "",
                    "size": int(fi.get("size") or 0),
                    "md5": fi.get("md5") or "",
                    "sha1": fi.get("sha1") or "",
                    "sha256": fi.get("sha256") or "",
                })
            elif etype == "anomaly":
                an = rec.get("anomaly") or {}
                code = an.get("event") or "unknown"
                anomalies[code] += 1

    if total_records == 0:
        print(f"no records in {path}", file=sys.stderr)
        return 1

    report = {
        "summary": {
            "file": str(path),
            "records_total": total_records,
            "alerts_total": total_alerts,
        },
        "top_signatures": [
            {"sid": k[0], "signature": k[1], "severity": k[2], "count": c}
            for k, c in by_signature.most_common(50)
        ],
        "top_categories": [
            {"category": cat, "count": c}
            for cat, c in by_category.most_common(20)
        ],
        "top_destinations": [
            {"dst_ip": k[0], "dst_port": k[1], "count": c}
            for k, c in by_dst.most_common(50)
        ],
        "top_sources": [
            {"src_ip": s, "count": c}
            for s, c in by_src.most_common(30)
        ],
        "anomalies": [
            {"event": e, "count": c}
            for e, c in anomalies.most_common()
        ],
        "file_events": file_events[:200],
    }

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    w = csv.writer(sys.stdout)
    for section, payload in report.items():
        if isinstance(payload, dict):
            w.writerow([f"# {section}"])
            for k, v in payload.items():
                w.writerow([k, v])
            w.writerow([])
        elif isinstance(payload, list):
            if not payload:
                continue
            w.writerow([f"# {section}"])
            fieldnames = list(payload[0].keys())
            w.writerow(fieldnames)
            for r in payload:
                w.writerow([r.get(k, "") for k in fieldnames])
            w.writerow([])
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
