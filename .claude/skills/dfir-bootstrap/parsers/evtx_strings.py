#!/usr/bin/env python3
"""
evtx_strings.py — triage-only EVTX string extractor, stdlib only.

When python-evtx / EvtxECmd are unavailable, you can still surface readable
content from Security.evtx and friends: account names, hostnames, LogonType
labels, PowerShell script blocks, image paths, and so on. This is a SEVERELY
degraded substitute — it CANNOT reconstruct records, recover LogonType,
SubjectUserSid, TargetUserSid, TimeCreated, or any other structured field.

If you need those (and in almost every case you do), install python-evtx:
    sudo apt install python3-evtx

Usage:
    evtx_strings.py <file.evtx> [--min N] [--grep PATTERN]

Tips:
    - EVTX records are binary XML (BinXML); strings are UTF-16LE.
    - Use --grep "EventID|LogonType|TargetUserName|4624" to narrow noise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("evtx", type=Path)
    parser.add_argument("--min", type=int, default=6)
    parser.add_argument("--grep", type=str, default=None, help="regex applied case-insensitively")
    args = parser.parse_args(argv[1:])

    if not args.evtx.exists():
        print(f"error: {args.evtx} does not exist", file=sys.stderr)
        return 2

    data = args.evtx.read_bytes()
    if data[:8] != b"ElfFile\x00":
        print("warn: missing ElfFile signature — may not be a valid EVTX", file=sys.stderr)

    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % args.min)
    grep_re = re.compile(args.grep, re.IGNORECASE) if args.grep else None

    seen: set[str] = set()
    for m in utf16_re.finditer(data):
        s = m.group(0).decode("utf-16-le", errors="replace").rstrip("\x00")
        if not s or s in seen:
            continue
        seen.add(s)
        if grep_re and not grep_re.search(s):
            continue
        print(f"{m.start():#010x}\t{s}")
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
