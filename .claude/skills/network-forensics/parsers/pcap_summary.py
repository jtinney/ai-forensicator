#!/usr/bin/env python3
"""
pcap_summary.py — Stdlib-only pcap / pcapng triage.

Substitutes for `capinfos` + `tshark -q -z conv,ip` + `tshark -Y dns` when
those tools are unavailable. Parses the libpcap classic and pcapng (Section
Header / Interface Description / Enhanced Packet) block formats and emits a
short triage report (CSV by default, or JSON with --json).

Usage:
    pcap_summary.py <file.pcap[ng]>                       # full triage
    pcap_summary.py <file.pcap[ng]> --header-only         # just metadata
    pcap_summary.py <file.pcap[ng]> --top-talkers 50      # change top-N
    pcap_summary.py <file.pcap[ng]> --no-dns              # skip DNS extraction
    pcap_summary.py <file.pcap[ng]> --json                # machine-readable output

Coverage:
    - Pcap classic (LE + BE magic), nanosecond + microsecond variants
    - Pcapng (SHB/IDB/EPB; SPB tolerated, others skipped)
    - Ethernet (link type 1) and Linux SLL (113); 802.1Q VLAN unwrapping
    - IPv4 + IPv6
    - TCP, UDP, ICMP, ICMPv6 — extracts 5-tuple per packet
    - DNS qname extraction over UDP/53 (request and response)

Limitations:
    - No TCP reassembly (so no SNI / no HTTP body)
    - No JA3 (requires reassembled TLS Client Hello)
    - DNS only over UDP/53; DoH / DoT / DNS-over-TCP not extracted
    - 802.11 / radiotap captures not supported (linktype != 1, 113)

Exit codes:
    0 success
    1 unrecognised file format
    2 bad arguments
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterator

# ── pcap classic magic ──────────────────────────────────────────────────────
PCAP_MAGIC_LE_US = 0xA1B2C3D4   # microsecond resolution, little-endian
PCAP_MAGIC_BE_US = 0xD4C3B2A1
PCAP_MAGIC_LE_NS = 0xA1B23C4D   # nanosecond resolution
PCAP_MAGIC_BE_NS = 0x4D3CB2A1

# ── pcapng ──────────────────────────────────────────────────────────────────
PCAPNG_BLOCK_SHB = 0x0A0D0D0A   # Section Header Block
PCAPNG_BLOCK_IDB = 0x00000001   # Interface Description Block
PCAPNG_BLOCK_EPB = 0x00000006   # Enhanced Packet Block
PCAPNG_BLOCK_SPB = 0x00000003   # Simple Packet Block (no timestamp)
PCAPNG_SHB_BOM_LE = 0x1A2B3C4D

# ── link types ──────────────────────────────────────────────────────────────
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

# ── ethertypes ──────────────────────────────────────────────────────────────
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8

# ── IP protocols ────────────────────────────────────────────────────────────
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58


def fmt_epoch(ts: float) -> str:
    """Format epoch seconds as ISO-8601 UTC."""
    if ts <= 0:
        return ""
    import datetime as dt
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


# ─── pcap (classic) reader ──────────────────────────────────────────────────
def iter_pcap(fh) -> Iterator[tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, raw_packet_bytes) tuples from a libpcap file."""
    header = fh.read(24)
    if len(header) < 24:
        raise ValueError("truncated pcap header")
    magic = struct.unpack("<I", header[:4])[0]
    if magic == PCAP_MAGIC_LE_US:
        endian, ts_div = "<", 1_000_000
    elif magic == PCAP_MAGIC_BE_US:
        endian, ts_div = ">", 1_000_000
    elif magic == PCAP_MAGIC_LE_NS:
        endian, ts_div = "<", 1_000_000_000
    elif magic == PCAP_MAGIC_BE_NS:
        endian, ts_div = ">", 1_000_000_000
    else:
        raise ValueError(f"unknown pcap magic 0x{magic:08x}")

    # version_major(2), version_minor(2), thiszone(4), sigfigs(4), snaplen(4), network(4)
    _vmaj, _vmin, _tz, _sf, _sn, network = struct.unpack(endian + "HHiIII", header[4:24])
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", rec)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            return
        yield ts_sec + ts_frac / ts_div, network, data


# ─── pcapng reader ──────────────────────────────────────────────────────────
def iter_pcapng(fh) -> Iterator[tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, raw_packet_bytes) tuples from a pcapng file."""
    interfaces: list[tuple[int, int]] = []  # list of (linktype, ts_resol_div)
    while True:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            return
        block_type, block_total_len = struct.unpack("<II", head)
        if block_total_len < 12:
            return
        body = fh.read(block_total_len - 8)
        if len(body) < block_total_len - 8:
            return

        if block_type == PCAPNG_BLOCK_SHB:
            bom = struct.unpack("<I", body[:4])[0]
            if bom != PCAPNG_SHB_BOM_LE:
                # Big-endian SHBs are rare; skip rather than mis-parse
                raise ValueError("big-endian pcapng not supported")
            interfaces = []  # new section resets interface table
        elif block_type == PCAPNG_BLOCK_IDB:
            linktype, _reserved, _snaplen = struct.unpack("<HHI", body[:8])
            ts_resol_div = 1_000_000  # default microseconds (per spec)
            # Walk options for if_tsresol
            opts = body[8:-4]  # strip trailing block-total-length
            i = 0
            while i + 4 <= len(opts):
                code, length = struct.unpack("<HH", opts[i:i + 4])
                i += 4
                if code == 0:  # opt_endofopt
                    break
                val = opts[i:i + length]
                i += length
                # pad to 4-byte boundary
                i += (4 - (length % 4)) % 4
                if code == 9 and len(val) >= 1:  # if_tsresol
                    raw = val[0]
                    if raw & 0x80:
                        ts_resol_div = 1 << (raw & 0x7F)
                    else:
                        ts_resol_div = 10 ** (raw & 0x7F)
            interfaces.append((linktype, ts_resol_div))
        elif block_type == PCAPNG_BLOCK_EPB:
            if len(body) < 20:
                continue
            iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack(
                "<IIIII", body[:20]
            )
            data = body[20:20 + cap_len]
            if iface_id < len(interfaces):
                linktype, ts_div = interfaces[iface_id]
            else:
                linktype, ts_div = LINKTYPE_ETHERNET, 1_000_000
            ts_full = (ts_high << 32) | ts_low
            yield ts_full / ts_div, linktype, data
        elif block_type == PCAPNG_BLOCK_SPB:
            # No timestamp; use 0
            if len(body) < 4:
                continue
            _orig_len = struct.unpack("<I", body[:4])[0]
            data = body[4:]
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield 0.0, linktype, data
        # Unknown block types silently skipped


def detect_format(fh) -> str:
    head = fh.read(4)
    fh.seek(0)
    if len(head) < 4:
        return "unknown"
    magic = struct.unpack("<I", head)[0]
    if magic in (PCAP_MAGIC_LE_US, PCAP_MAGIC_BE_US, PCAP_MAGIC_LE_NS, PCAP_MAGIC_BE_NS):
        return "pcap"
    magic_be = struct.unpack(">I", head)[0]
    if magic_be in (PCAP_MAGIC_LE_US, PCAP_MAGIC_BE_US):
        return "pcap"
    if magic == PCAPNG_BLOCK_SHB:
        return "pcapng"
    return "unknown"


# ─── L2/L3/L4 decode ────────────────────────────────────────────────────────
def decode_packet(linktype: int, data: bytes):
    """Return (src_ip, dst_ip, proto, src_port, dst_port, payload, ip_total_len) or None."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack(">H", data[12:14])[0]
        offset = 14
        # Strip up to two VLAN tags
        for _ in range(2):
            if ethertype in (ETH_VLAN, ETH_QINQ):
                if len(data) < offset + 4:
                    return None
                ethertype = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                offset += 4
            else:
                break
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        ethertype = struct.unpack(">H", data[14:16])[0]
        offset = 16
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        ethertype = struct.unpack(">H", data[0:2])[0]
        offset = 20
    elif linktype == LINKTYPE_RAW:
        if not data:
            return None
        version = (data[0] & 0xF0) >> 4
        ethertype = ETH_IPV4 if version == 4 else ETH_IPV6 if version == 6 else 0
        offset = 0
    else:
        return None

    if ethertype == ETH_IPV4:
        return decode_ipv4(data, offset)
    if ethertype == ETH_IPV6:
        return decode_ipv6(data, offset)
    return None


def decode_ipv4(data: bytes, offset: int):
    if len(data) < offset + 20:
        return None
    vihl = data[offset]
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < offset + ihl:
        return None
    total_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
    proto = data[offset + 9]
    src = ".".join(str(b) for b in data[offset + 12:offset + 16])
    dst = ".".join(str(b) for b in data[offset + 16:offset + 20])
    payload_off = offset + ihl
    return _decode_l4(src, dst, proto, data, payload_off, total_len)


def decode_ipv6(data: bytes, offset: int):
    if len(data) < offset + 40:
        return None
    payload_len = struct.unpack(">H", data[offset + 4:offset + 6])[0]
    next_header = data[offset + 6]
    src = _format_ipv6(data[offset + 8:offset + 24])
    dst = _format_ipv6(data[offset + 24:offset + 40])
    payload_off = offset + 40
    return _decode_l4(src, dst, next_header, data, payload_off, payload_len + 40)


def _format_ipv6(b: bytes) -> str:
    parts = [f"{(b[i] << 8) | b[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def _decode_l4(src: str, dst: str, proto: int, data: bytes,
               payload_off: int, ip_total_len: int):
    sport = dport = 0
    payload = b""
    if proto == IPPROTO_TCP and len(data) >= payload_off + 20:
        sport, dport = struct.unpack(">HH", data[payload_off:payload_off + 4])
        data_off = (data[payload_off + 12] >> 4) * 4
        payload = data[payload_off + data_off:]
    elif proto == IPPROTO_UDP and len(data) >= payload_off + 8:
        sport, dport = struct.unpack(">HH", data[payload_off:payload_off + 4])
        payload = data[payload_off + 8:]
    elif proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        payload = data[payload_off:]
    return src, dst, proto, sport, dport, payload, ip_total_len


# ─── DNS qname extraction (UDP/53 only) ─────────────────────────────────────
def parse_dns_qname(payload: bytes) -> str | None:
    """Return the first qname in a DNS message, or None if not parseable."""
    if len(payload) < 12:
        return None
    qdcount = struct.unpack(">H", payload[4:6])[0]
    if qdcount == 0:
        return None
    i = 12
    labels = []
    while i < len(payload):
        ln = payload[i]
        if ln == 0:
            break
        if ln & 0xC0:
            # compression pointer in question section is unusual; bail
            return None
        i += 1
        if i + ln > len(payload):
            return None
        try:
            labels.append(payload[i:i + ln].decode("ascii"))
        except UnicodeDecodeError:
            return None
        i += ln
        if i > len(payload):
            return None
    if not labels:
        return None
    return ".".join(labels)


# ─── triage main ────────────────────────────────────────────────────────────
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def proto_name(p: int) -> str:
    return PROTO_NAMES.get(p, f"ip-{p}")


def triage(path: Path, top_talkers: int, do_dns: bool, header_only: bool):
    fh = path.open("rb")
    fmt = detect_format(fh)
    if fmt == "unknown":
        print(f"unknown format: {path}", file=sys.stderr)
        return 1
    iterator = iter_pcap(fh) if fmt == "pcap" else iter_pcapng(fh)

    pkt_count = 0
    byte_count = 0
    first_ts = None
    last_ts = None
    linktypes: Counter[int] = Counter()
    flows: defaultdict[tuple, list[int]] = defaultdict(lambda: [0, 0])
    # (src,dst,proto,dport) -> [packets, bytes]
    dns_qnames: Counter[str] = Counter()
    dport_count: Counter[tuple[str, int]] = Counter()  # (proto, port) -> count

    for ts, linktype, raw in iterator:
        pkt_count += 1
        byte_count += len(raw)
        if first_ts is None or ts < first_ts:
            first_ts = ts
        if last_ts is None or ts > last_ts:
            last_ts = ts
        linktypes[linktype] += 1

        if header_only:
            continue

        decoded = decode_packet(linktype, raw)
        if decoded is None:
            continue
        src, dst, proto, sport, dport, payload, total_len = decoded
        key = (src, dst, proto, dport)
        flows[key][0] += 1
        flows[key][1] += total_len if total_len > 0 else len(raw)
        if proto in (IPPROTO_TCP, IPPROTO_UDP):
            dport_count[(proto_name(proto), dport)] += 1
        if do_dns and proto == IPPROTO_UDP and dport == 53 and payload:
            qn = parse_dns_qname(payload)
            if qn:
                dns_qnames[qn] += 1
        if do_dns and proto == IPPROTO_UDP and sport == 53 and payload:
            qn = parse_dns_qname(payload)
            if qn:
                dns_qnames[qn] += 1

    fh.close()

    summary = {
        "file": str(path),
        "format": fmt,
        "packets": pkt_count,
        "bytes": byte_count,
        "first_packet_utc": fmt_epoch(first_ts) if first_ts else "",
        "last_packet_utc": fmt_epoch(last_ts) if last_ts else "",
        "duration_s": (last_ts - first_ts) if (first_ts and last_ts) else 0,
        "linktypes": dict(linktypes),
    }
    return summary, flows, dns_qnames, dport_count, top_talkers, do_dns, header_only


def render(summary, flows, dns_qnames, dport_count, top_talkers, do_dns,
           header_only, as_json: bool):
    if as_json:
        out = dict(summary)
        if not header_only:
            out["top_flows"] = [
                {"src": k[0], "dst": k[1], "proto": proto_name(k[2]),
                 "dport": k[3], "packets": v[0], "bytes": v[1]}
                for k, v in sorted(flows.items(), key=lambda kv: kv[1][1],
                                   reverse=True)[:top_talkers]
            ]
            out["top_dports"] = [
                {"proto": p, "port": port, "count": c}
                for (p, port), c in dport_count.most_common(20)
            ]
            if do_dns:
                out["top_dns_qnames"] = [
                    {"qname": q, "count": c}
                    for q, c in dns_qnames.most_common(50)
                ]
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    w = csv.writer(sys.stdout)
    w.writerow(["section", "key", "value"])
    for k, v in summary.items():
        w.writerow(["meta", k, v])
    if header_only:
        return
    w.writerow([])
    w.writerow(["top_flows", "src,dst,proto,dport", "packets,bytes"])
    for k, v in sorted(flows.items(), key=lambda kv: kv[1][1], reverse=True)[:top_talkers]:
        src, dst, proto, dport = k
        w.writerow(["flow", f"{src},{dst},{proto_name(proto)},{dport}",
                    f"{v[0]},{v[1]}"])
    w.writerow([])
    w.writerow(["top_dports", "proto:port", "count"])
    for (p, port), c in dport_count.most_common(20):
        w.writerow(["dport", f"{p}:{port}", c])
    if do_dns:
        w.writerow([])
        w.writerow(["top_dns_qnames", "qname", "count"])
        for q, c in dns_qnames.most_common(50):
            w.writerow(["dns", q, c])


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", help="Path to .pcap or .pcapng file")
    ap.add_argument("--header-only", action="store_true",
                    help="Stop after parsing capture metadata")
    ap.add_argument("--top-talkers", type=int, default=20,
                    help="Number of top flows to report (default: 20)")
    ap.add_argument("--no-dns", dest="dns", action="store_false",
                    help="Skip DNS qname extraction")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON instead of CSV")
    args = ap.parse_args(argv[1:])

    path = Path(args.pcap)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2

    try:
        result = triage(path, args.top_talkers, args.dns, args.header_only)
    except ValueError as e:
        print(f"parse error: {e}", file=sys.stderr)
        return 1
    if isinstance(result, int):
        return result

    render(*result, as_json=args.json)
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
