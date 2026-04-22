#!/usr/bin/env python3
"""
rb_parse.py — Windows Recycle Bin $I metadata parser (stdlib only).

Substitutes for RBCmd when EZ Tools are unavailable. Parses both the Win7/8
($I version 1) and Win10+ ($I version 2) formats and emits CSV with the
columns every case actually pivots on: which SID deleted the file, what the
original path was, when, and how big.

Usage:
    rb_parse.py <directory>             # recurse, find all $I* files
    rb_parse.py <file1> [file2 ...]     # parse specific $I files

Exit codes:
    0 success, 1 no $I files found, 2 bad args

Format reference (both versions):
    bytes  0..7   : header version (int64 LE; 1 = Win7/8, 2 = Win10+)
    bytes  8..15  : original file size (int64 LE)
    bytes 16..23  : deletion FILETIME (int64 LE, 100ns intervals since 1601-01-01 UTC)
    Version 1:
        bytes 24..  : original path, UTF-16LE, null-terminated (MAX_PATH-sized buffer)
    Version 2:
        bytes 24..27: name length in wide chars (uint32 LE)
        bytes 28..  : original path, UTF-16LE, length indicated above, null-terminated
"""

from __future__ import annotations

import csv
import datetime as dt
import os
import re
import struct
import sys
from pathlib import Path

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
SID_DIR_RE = re.compile(r"S-1-5-21-[\d-]+")


def filetime_to_utc(ft: int) -> str:
    if ft <= 0:
        return ""
    try:
        return (FILETIME_EPOCH + dt.timedelta(microseconds=ft // 10)).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (OverflowError, OSError):
        return ""


def parse_i_file(path: Path) -> dict | None:
    """Parse one $I file. Return dict or None on malformed input."""
    try:
        data = path.read_bytes()
    except OSError as e:
        return {"error": f"read failed: {e}", "path": str(path)}

    if len(data) < 24:
        return {"error": "truncated header", "path": str(path)}

    version, size, ft = struct.unpack("<qqq", data[:24])

    name = ""
    if version == 1:
        # UTF-16LE null-terminated, fixed MAX_PATH=260 wide chars buffer
        raw = data[24:]
        chunks = []
        for i in range(0, len(raw) - 1, 2):
            pair = raw[i : i + 2]
            if pair == b"\x00\x00":
                break
            chunks.append(pair)
        name = b"".join(chunks).decode("utf-16-le", errors="replace")
    elif version == 2:
        if len(data) < 28:
            return {"error": "v2 name length missing", "path": str(path)}
        nlen = struct.unpack("<I", data[24:28])[0]
        end = 28 + nlen * 2
        name_raw = data[28:end]
        name = name_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    else:
        return {"error": f"unknown $I version {version}", "path": str(path)}

    sid_match = SID_DIR_RE.search(str(path))
    sid = sid_match.group(0) if sid_match else ""

    return {
        "i_file": path.name,
        "sid": sid,
        "version": version,
        "size_bytes": size,
        "deletion_utc": filetime_to_utc(ft),
        "original_path": name,
        "source": str(path),
    }


def collect_inputs(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for arg in args:
        p = Path(arg)
        if not p.exists():
            print(f"warn: {p} does not exist", file=sys.stderr)
            continue
        if p.is_dir():
            # Look for $I prefix (case-insensitive) — Windows is case-insensitive
            for root, _, files in os.walk(p):
                for name in files:
                    if name.startswith("$I") or name.startswith("$i"):
                        out.append(Path(root) / name)
        else:
            out.append(p)
    return sorted(out)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    inputs = collect_inputs(argv[1:])
    if not inputs:
        print("no $I files found", file=sys.stderr)
        return 1

    writer = csv.writer(sys.stdout)
    writer.writerow(
        ["i_file", "sid", "version", "size_bytes", "deletion_utc", "original_path", "source"]
    )

    for p in inputs:
        row = parse_i_file(p)
        if row is None:
            continue
        if "error" in row:
            print(f"warn: {row['path']}: {row['error']}", file=sys.stderr)
            continue
        writer.writerow(
            [
                row["i_file"],
                row["sid"],
                row["version"],
                row["size_bytes"],
                row["deletion_utc"],
                row["original_path"],
                row["source"],
            ]
        )
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
