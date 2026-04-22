#!/usr/bin/env python3
"""
prefetch_parse.py — Windows Prefetch (SCCA) parser, stdlib only.

Substitutes for PECmd when EZ Tools are unavailable. Parses uncompressed
(.pf) files for Windows XP/7/8; for Windows 10/11 the files are MAM-LZXpress
compressed and require decompression first (see notes).

Supported SCCA versions:
    17 (Win XP)          — 1 last-run timestamp
    23 (Win 7 / 2008 R2) — 1 last-run timestamp (offset 0x80)
    26 (Win 8 / 2012)    — 8 last-run timestamps (offset 0x80, 8 * 8 bytes)
    30 (Win 10/11)       — 8 last-run timestamps (offset 0x80, 8 * 8 bytes),
                           but file is usually MAM-compressed on disk.

Output CSV columns:
    filename, scca_version, exec_name, hash_hex, run_count,
    last_run_utc, run2_utc ... run8_utc, source

Usage:
    prefetch_parse.py <dir_or_files...>

Notes:
    - A prefetch file starting with bytes "MAM\\x04" is LZXpress-compressed.
      This parser skips those with a warning; install `python3-regipy` or run
      `PECmd` for Win10 cases, or decompress with external tools first.
    - Version 23 (Win7) LastRunTime lives at 0x80, NOT 0x78 — a subtle offset
      error will produce FILETIMEs of 1601-01-01 00:07 and similar garbage.
      This parser uses the correct offset per version.
"""

from __future__ import annotations

import csv
import datetime as dt
import os
import struct
import sys
from pathlib import Path

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)


def filetime_to_utc(ft: int) -> str:
    if ft <= 0:
        return ""
    try:
        return (FILETIME_EPOCH + dt.timedelta(microseconds=ft // 10)).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (OverflowError, OSError):
        return ""


def parse_pf(path: Path) -> dict | None:
    try:
        data = path.read_bytes()
    except OSError as e:
        return {"error": f"read failed: {e}", "source": str(path)}

    if len(data) < 0x100:
        return {"error": "too small to be valid SCCA", "source": str(path)}

    # Detect Windows 10+ MAM-compressed prefetch
    if data[:4] == b"MAM\x04":
        return {
            "error": "MAM-compressed (Win10+) — decompress first or use PECmd",
            "source": str(path),
        }

    if data[4:8] != b"SCCA":
        return {"error": "not SCCA-signature prefetch", "source": str(path)}

    version = struct.unpack("<I", data[0:4])[0]

    # Executable name (UTF-16LE, null-terminated, 60 wide chars max)
    exec_raw = data[0x10:0x10 + 60 * 2]
    exec_name = exec_raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]

    # Prefetch hash at 0x4C (uint32 LE)
    hash_hex = f"{struct.unpack('<I', data[0x4C:0x50])[0]:08X}"

    # Version-specific last-run + run-count offsets.
    # Correct offsets — learned the hard way; 0x78 is WRONG for v23 on Win7.
    if version == 17:
        last_offsets = [0x78]
        run_count_off = 0x90
    elif version == 23:
        last_offsets = [0x80]
        run_count_off = 0x98
    elif version == 26:
        last_offsets = [0x80 + i * 8 for i in range(8)]
        run_count_off = 0xD0
    elif version == 30:
        last_offsets = [0x80 + i * 8 for i in range(8)]
        run_count_off = 0xD0
    else:
        return {"error": f"unknown SCCA version {version}", "source": str(path)}

    last_runs = []
    for off in last_offsets:
        if off + 8 > len(data):
            last_runs.append("")
            continue
        ft = struct.unpack("<Q", data[off : off + 8])[0]
        last_runs.append(filetime_to_utc(ft))

    run_count = (
        struct.unpack("<I", data[run_count_off : run_count_off + 4])[0]
        if run_count_off + 4 <= len(data)
        else 0
    )

    return {
        "filename": path.name,
        "scca_version": version,
        "exec_name": exec_name,
        "hash_hex": hash_hex,
        "run_count": run_count,
        "last_runs": last_runs,
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
            for root, _, files in os.walk(p):
                for name in files:
                    if name.lower().endswith(".pf"):
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
        print("no .pf files found", file=sys.stderr)
        return 1

    writer = csv.writer(sys.stdout)
    header = ["filename", "scca_version", "exec_name", "hash_hex", "run_count", "last_run_utc"]
    for i in range(2, 9):
        header.append(f"run{i}_utc")
    header.append("source")
    writer.writerow(header)

    for p in inputs:
        row = parse_pf(p)
        if row is None:
            continue
        if "error" in row:
            print(f"warn: {row['source']}: {row['error']}", file=sys.stderr)
            continue
        runs = row["last_runs"] + [""] * (8 - len(row["last_runs"]))
        writer.writerow(
            [
                row["filename"],
                row["scca_version"],
                row["exec_name"],
                row["hash_hex"],
                row["run_count"],
                *runs,
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
