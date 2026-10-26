"""Minimal DNS / mDNS wire-format parser and PTR query builder (RFC 1035, RFC 6762).

Packets come from other devices on the LAN, so every read is bounds-checked
and compression pointers are limited to stop loops.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33

MAX_POINTER_HOPS = 32


class MalformedPacket(ValueError):
    pass


@dataclass
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: object  # str for A/AAAA/PTR, dict for SRV, list[str] for TXT, bytes otherwise


@dataclass
class Message:
    id: int
    flags: int
    questions: list[tuple[str, int]]
    records: list[Record]

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)


def _read_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None
    hops = 0
    while True:
        if offset >= len(buf):
            raise MalformedPacket("name runs past end of packet")
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise MalformedPacket("truncated compression pointer")
            hops += 1
            if hops > MAX_POINTER_HOPS:
                raise MalformedPacket("compression pointer loop")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | buf[offset + 1]
            continue
        if length & 0xC0:
            raise MalformedPacket("unsupported label type")
        offset += 1
        if offset + length > len(buf):
            raise MalformedPacket("label runs past end of packet")
        labels.append(buf[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (end if end is not None else offset)


def parse(buf: bytes) -> Message:
    if len(buf) < 12:
        raise MalformedPacket("shorter than a DNS header")
    msg_id, flags, qd, an, ns, ar = struct.unpack_from("!6H", buf, 0)
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = _read_name(buf, offset)
        if offset + 4 > len(buf):
            raise MalformedPacket("truncated question")
        qtype, _qclass = struct.unpack_from("!HH", buf, offset)
        offset += 4
        questions.append((name, qtype))
    records = []
    for _ in range(an + ns + ar):
        name, offset = _read_name(buf, offset)
        if offset + 10 > len(buf):
            raise MalformedPacket("truncated resource record")
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", buf, offset)
        offset += 10
        if offset + rdlen > len(buf):
            raise MalformedPacket("rdata runs past end of packet")
        rdata = buf[offset : offset + rdlen]
        data: object = rdata
        if rtype == TYPE_A and rdlen == 4:
            data = str(ipaddress.IPv4Address(rdata))
        elif rtype == TYPE_AAAA and rdlen == 16:
            data = str(ipaddress.IPv6Address(rdata))
        elif rtype == TYPE_PTR:
            data, _ = _read_name(buf, offset)
        elif rtype == TYPE_SRV and rdlen >= 7:
            prio, weight, port = struct.unpack_from("!HHH", buf, offset)
            target, _ = _read_name(buf, offset + 6)
            data = {"priority": prio, "weight": weight, "port": port, "target": target}
        elif rtype == TYPE_TXT:
            items, i = [], 0
            while i < len(rdata):
                n = rdata[i]
                items.append(rdata[i + 1 : i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            data = items
        records.append(Record(name, rtype, rclass & 0x7FFF, ttl, data))  # top bit = mDNS cache-flush
        offset += rdlen
    return Message(msg_id, flags, questions, records)


def _strip_local(name: str) -> str:
    name = name.rstrip(".")
    return name[: -len(".local")] if name.lower().endswith(".local") else name


def mdns_hostnames(msg: Message) -> dict[str, str]:
    """Map IPv4 address -> hostname from A records in an mDNS response."""
    out: dict[str, str] = {}
    if not msg.is_response:
        return out
    for rec in msg.records:
        if rec.rtype == TYPE_A and isinstance(rec.data, str) and rec.ttl > 0:
            out[rec.data] = _strip_local(rec.name)
    return out


def mdns_services(msg: Message) -> list[str]:
    """Service instance names advertised (e.g. ``Living Room._googlecast._tcp``)."""
    names = []
    for rec in msg.records:
        if rec.rtype == TYPE_PTR and isinstance(rec.data, str) and rec.name.startswith("_") and "in-addr" not in rec.name:
            names.append(_strip_local(rec.data))
    return names


def build_ptr_query(ip: str, query_id: int) -> bytes:
    """Standard recursive PTR query for ``ip`` (sent only to the confirmed gateway)."""
    rev = ".".join(reversed(str(ipaddress.IPv4Address(ip)).split("."))) + ".in-addr.arpa"
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in rev.split(".")) + b"\x00"
    return struct.pack("!6H", query_id & 0xFFFF, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", TYPE_PTR, 1)


def ptr_answer(msg: Message) -> str | None:
    for rec in msg.records:
        if rec.rtype == TYPE_PTR and isinstance(rec.data, str) and rec.data:
            return rec.data.rstrip(".")
    return None
