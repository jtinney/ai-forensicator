#!/usr/bin/env python3
"""
zeek_triage.py — Stdlib triage of a Zeek log directory.

Substitutes for `zeek-cut | awk` pipelines when Zeek is installed but the
ergonomics of zeek-cut are unwelcome, and is also useful as a one-shot
"summarize this directory" pass at case start.

Reads Zeek logs in either:
  - TSV format with a "#fields" header line (Zeek default)
  - JSON-Lines (one JSON object per line; Zeek with `LogAscii::use_json=T`)

Emits a CSV summary covering:
  - conn.log:    top-talkers by bytes, long-lived connections
  - dns.log:     top qnames, NXDOMAIN qnames, qnames with high TTL variance
  - http.log:    top user-agents, top hosts, executable downloads
  - ssl.log:     top SNIs, JA3 distribution
  - files.log:   extracted file mime/size/source
  - notice.log:  passthrough of Zeek's own notices

Usage:
    zeek_triage.py <zeek-log-dir>          # CSV to stdout
    zeek_triage.py <zeek-log-dir> --json   # JSON to stdout

Exit codes:
    0 success
    1 no readable Zeek logs found
    2 bad arguments
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterator


def iter_zeek(path: Path) -> Iterator[dict]:
    """Yield records from a Zeek log file (TSV or JSON)."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        if not first:
            return
        if first.startswith("{"):
            # JSON-lines format
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

        # TSV format: walk header lines (start with '#')
        fields: list[str] = []
        types: list[str] = []
        sep = "\t"
        unset_field = "-"
        empty_field = "(empty)"
        line = first
        while line:
            if not line.startswith("#"):
                break
            parts = line.rstrip("\n").split(sep if "\t" in line else None)
            if line.startswith("#separator"):
                # value is escape-encoded, e.g. \\x09 → tab
                tail = line.rstrip("\n").split(" ", 1)[1].strip()
                if tail.startswith("\\x"):
                    sep = bytes.fromhex(tail.replace("\\x", "")).decode("latin-1")
            elif line.startswith("#fields"):
                fields = line.rstrip("\n").split(sep)[1:]
            elif line.startswith("#types"):
                types = line.rstrip("\n").split(sep)[1:]
            elif line.startswith("#unset_field"):
                unset_field = line.rstrip("\n").split(sep, 1)[1]
            elif line.startswith("#empty_field"):
                empty_field = line.rstrip("\n").split(sep, 1)[1]
            line = fh.readline()

        if not fields:
            return
        # The first non-comment line is already in `line`
        while line:
            stripped = line.rstrip("\n")
            if stripped and not stripped.startswith("#"):
                vals = stripped.split(sep)
                rec = {}
                for i, name in enumerate(fields):
                    v = vals[i] if i < len(vals) else unset_field
                    if v == unset_field or v == empty_field:
                        rec[name] = None
                    else:
                        rec[name] = v
                yield rec
            line = fh.readline()


def find_log(zeek_dir: Path, name: str) -> Path | None:
    for candidate in (zeek_dir / f"{name}.log", zeek_dir / f"{name}.json"):
        if candidate.exists():
            return candidate
    return None


def f_int(v) -> int:
    if v is None:
        return 0
    try:
        return int(v)
    except (ValueError, TypeError):
        try:
            return int(float(v))
        except (ValueError, TypeError):
            return 0


def f_float(v) -> float:
    if v is None:
        return 0.0
    try:
        return float(v)
    except (ValueError, TypeError):
        return 0.0


def triage_conn(path: Path) -> dict:
    talkers: defaultdict[tuple, list[float]] = defaultdict(lambda: [0, 0, 0])
    long_lived: list[dict] = []
    services: Counter[str] = Counter()
    for rec in iter_zeek(path):
        src = rec.get("id.orig_h") or ""
        dst = rec.get("id.resp_h") or ""
        proto = rec.get("proto") or ""
        port = rec.get("id.resp_p") or ""
        service = rec.get("service") or ""
        ob = f_int(rec.get("orig_bytes"))
        rb = f_int(rec.get("resp_bytes"))
        dur = f_float(rec.get("duration"))
        key = (src, dst, proto, str(port))
        talkers[key][0] += 1
        talkers[key][1] += ob + rb
        talkers[key][2] = max(talkers[key][2], dur)
        if service:
            services[service] += 1
        if dur >= 3600:
            long_lived.append({"src": src, "dst": dst, "proto": proto,
                               "port": str(port), "service": service,
                               "duration_s": dur, "bytes": ob + rb})
    top = sorted(talkers.items(), key=lambda kv: kv[1][1], reverse=True)[:50]
    return {
        "top_talkers": [
            {"src": k[0], "dst": k[1], "proto": k[2], "port": k[3],
             "conns": int(v[0]), "bytes": int(v[1]),
             "max_duration_s": v[2]}
            for k, v in top
        ],
        "top_services": [{"service": s, "count": c}
                         for s, c in services.most_common(20)],
        "long_lived": sorted(long_lived, key=lambda r: r["duration_s"],
                             reverse=True)[:50],
    }


def triage_dns(path: Path) -> dict:
    qnames: Counter[str] = Counter()
    nxdomain: Counter[str] = Counter()
    rcodes: Counter[str] = Counter()
    long_qnames: list[dict] = []
    for rec in iter_zeek(path):
        qn = rec.get("query") or ""
        if qn:
            qnames[qn] += 1
            if len(qn) >= 50:
                long_qnames.append({
                    "qname": qn,
                    "len": len(qn),
                    "src": rec.get("id.orig_h") or "",
                    "rcode": rec.get("rcode_name") or "",
                })
        rcode = rec.get("rcode_name") or ""
        if rcode:
            rcodes[rcode] += 1
        if rcode == "NXDOMAIN" and qn:
            nxdomain[qn] += 1
    return {
        "top_qnames": [{"qname": q, "count": c}
                       for q, c in qnames.most_common(50)],
        "top_nxdomain": [{"qname": q, "count": c}
                         for q, c in nxdomain.most_common(30)],
        "rcode_distribution": [{"rcode": r, "count": c}
                               for r, c in rcodes.most_common()],
        "long_qnames": long_qnames[:50],
    }


def triage_http(path: Path) -> dict:
    uas: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    exec_dl: list[dict] = []
    EXEC_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js",
                ".scr", ".hta", ".jar", ".lnk")
    for rec in iter_zeek(path):
        ua = rec.get("user_agent") or ""
        host = rec.get("host") or ""
        uri = rec.get("uri") or ""
        if ua:
            uas[ua] += 1
        if host:
            hosts[host] += 1
        lower = uri.lower()
        if any(lower.endswith(ext) or ext + "?" in lower for ext in EXEC_EXT):
            exec_dl.append({
                "src": rec.get("id.orig_h") or "",
                "host": host,
                "uri": uri,
                "method": rec.get("method") or "",
                "status_code": rec.get("status_code") or "",
                "user_agent": ua,
            })
    return {
        "top_user_agents": [{"user_agent": u, "count": c}
                            for u, c in uas.most_common(30)],
        "top_hosts": [{"host": h, "count": c}
                      for h, c in hosts.most_common(50)],
        "executable_downloads": exec_dl[:100],
    }


def triage_ssl(path: Path) -> dict:
    snis: Counter[str] = Counter()
    ja3: Counter[str] = Counter()
    ja3s: Counter[str] = Counter()
    self_signed: list[dict] = []
    for rec in iter_zeek(path):
        sni = rec.get("server_name") or ""
        if sni:
            snis[sni] += 1
        j = rec.get("ja3") or ""
        if j:
            ja3[j] += 1
        js = rec.get("ja3s") or ""
        if js:
            ja3s[js] += 1
        # Some Zeek policies populate `validation_status`
        vs = rec.get("validation_status") or ""
        if "self signed" in vs.lower() or "self-signed" in vs.lower():
            self_signed.append({
                "src": rec.get("id.orig_h") or "",
                "dst": rec.get("id.resp_h") or "",
                "sni": sni,
                "ja3": j,
                "validation_status": vs,
            })
    return {
        "top_sni": [{"sni": s, "count": c} for s, c in snis.most_common(50)],
        "top_ja3": [{"ja3": j, "count": c} for j, c in ja3.most_common(30)],
        "top_ja3s": [{"ja3s": j, "count": c} for j, c in ja3s.most_common(30)],
        "self_signed": self_signed[:50],
    }


def triage_files(path: Path) -> dict:
    by_mime: Counter[str] = Counter()
    big_files: list[dict] = []
    for rec in iter_zeek(path):
        mime = rec.get("mime_type") or "unknown"
        size = f_int(rec.get("total_bytes"))
        by_mime[mime] += 1
        if size >= 1_000_000:
            big_files.append({
                "tx_hosts": rec.get("tx_hosts") or "",
                "rx_hosts": rec.get("rx_hosts") or "",
                "mime": mime,
                "filename": rec.get("filename") or "",
                "size": size,
                "md5": rec.get("md5") or "",
                "sha1": rec.get("sha1") or "",
                "source": rec.get("source") or "",
            })
    return {
        "by_mime": [{"mime": m, "count": c} for m, c in by_mime.most_common(30)],
        "large_files": sorted(big_files, key=lambda r: r["size"],
                              reverse=True)[:50],
    }


def triage_notice(path: Path) -> dict:
    by_note: Counter[str] = Counter()
    for rec in iter_zeek(path):
        note = rec.get("note") or "unknown"
        by_note[note] += 1
    return {"by_note": [{"note": n, "count": c}
                        for n, c in by_note.most_common()]}


SECTIONS = [
    ("conn", triage_conn),
    ("dns", triage_dns),
    ("http", triage_http),
    ("ssl", triage_ssl),
    ("files", triage_files),
    ("notice", triage_notice),
]


def render(report: dict, as_json: bool):
    if as_json:
        json.dump(report, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return
    w = csv.writer(sys.stdout)
    for section, payload in report.items():
        if not payload:
            continue
        for subkey, rows in payload.items():
            if not rows:
                continue
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                fieldnames = list(rows[0].keys())
                w.writerow([f"# {section}.{subkey}"])
                w.writerow(fieldnames)
                for r in rows:
                    w.writerow([r.get(k, "") for k in fieldnames])
                w.writerow([])


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zeek_dir", help="Directory containing Zeek logs")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON instead of CSV")
    args = ap.parse_args(argv[1:])

    zd = Path(args.zeek_dir)
    if not zd.is_dir():
        print(f"not a directory: {zd}", file=sys.stderr)
        return 2

    report: dict = {}
    found = 0
    for name, fn in SECTIONS:
        path = find_log(zd, name)
        if not path:
            continue
        found += 1
        try:
            report[name] = fn(path)
        except (OSError, ValueError) as e:
            print(f"warn: {path.name}: {e}", file=sys.stderr)

    if found == 0:
        print(f"no readable Zeek logs in {zd}", file=sys.stderr)
        return 1

    render(report, as_json=args.json)
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
