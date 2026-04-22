#!/usr/bin/env python3
"""
hive_strings.py — degraded registry hive string extractor, stdlib only.

When regipy / python-registry / RECmd are unavailable, you still need
*something* to find usernames, USBSTOR device descriptors, typed paths,
MountedDevices, UserAssist entries, and the like. This script walks the raw
hive bytes and prints every ASCII run (likely key names) and every UTF-16LE
run (likely value data) above a minimum length.

This is a fallback. It cannot:
    - reconstruct key -> value relationships structurally
    - decode UserAssist ROT13
    - parse shellbag BagMRU binary structures
    - extract FILETIMEs from cell headers
    - decode REG_DWORD / REG_BINARY payloads in a meaningful way

If any of those matter for the case, install python3-regipy:
    sudo apt install python3-regipy

Usage:
    hive_strings.py <hive_file> [--min <N>]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}")
UTF16_RUN_TEMPLATE = rb"(?:[\x20-\x7e]\x00){%d,}"


def extract(path: Path, min_len: int) -> int:
    try:
        data = path.read_bytes()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    header = data[:4]
    if header != b"regf":
        print(
            f"warn: {path} does not start with 'regf' signature — may not be a registry hive",
            file=sys.stderr,
        )

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_re = re.compile(UTF16_RUN_TEMPLATE % min_len)

    print(f"# hive: {path}")
    print(f"# size: {len(data)} bytes")
    print(f"# min run length: {min_len}")
    print(f"# ----- ASCII strings (likely key names / short values) -----")
    seen: set[str] = set()
    for m in ascii_re.finditer(data):
        s = m.group(0).decode("ascii", errors="replace")
        if s in seen:
            continue
        seen.add(s)
        print(f"{m.start():#010x}\tA\t{s}")

    print(f"# ----- UTF-16LE strings (likely REG_SZ / REG_MULTI_SZ values) -----")
    for m in utf16_re.finditer(data):
        s = m.group(0).decode("utf-16-le", errors="replace").rstrip("\x00")
        if not s or s in seen:
            continue
        seen.add(s)
        print(f"{m.start():#010x}\tW\t{s}")

    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("hive", type=Path, help="path to registry hive file")
    parser.add_argument("--min", type=int, default=5, help="minimum run length (default: 5)")
    args = parser.parse_args(argv[1:])

    if not args.hive.exists():
        print(f"error: {args.hive} does not exist", file=sys.stderr)
        return 2

    return extract(args.hive, args.min)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        # caller closed stdout (e.g. | head); exit cleanly
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
