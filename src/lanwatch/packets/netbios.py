"""NetBIOS Name Service (RFC 1002) parser and node-status query builder.

Passively, Windows and Samba hosts broadcast name registrations on UDP 137.
Actively (only with an ActiveAuthorization), a unicast node-status query
returns the host's names and its MAC, like ``nbtstat -A``.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

from ..mac import normalize_mac
from .dns import MalformedPacket

TYPE_NB = 0x0020
TYPE_NBSTAT = 0x0021


def encode_name(name: str, suffix: int = 0x00) -> bytes:
    """First-level encoding: 16 bytes -> 32 letters 'A'..'P', length-prefixed."""
    if name == "*":
        raw = b"*" + b"\x00" * 15
    else:
        raw = name.upper().encode("ascii")[:15].ljust(15, b" ") + bytes([suffix])
    encoded = bytes(c for b in raw for c in (ord("A") + (b >> 4), ord("A") + (b & 0x0F)))
    return bytes([32]) + encoded + b"\x00"


def decode_name(encoded: bytes) -> tuple[str, int]:
    if len(encoded) != 32:
        raise MalformedPacket("NetBIOS name must encode to 32 bytes")
    raw = bytes(((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41) for i in range(0, 32, 2))
    return raw[:15].decode("ascii", "replace").rstrip(" \x00"), raw[15]


def _read_encoded_name(buf: bytes, offset: int) -> tuple[str, int, int]:
    if offset >= len(buf):
        raise MalformedPacket("truncated name")
    if buf[offset] & 0xC0 == 0xC0:  # pointer, always back to the question name at 12
        ptr = ((buf[offset] & 0x3F) << 8) | buf[offset + 1]
        name, suffix, _ = _read_encoded_name(buf, ptr)
        return name, suffix, offset + 2
    if buf[offset] != 32 or offset + 34 > len(buf):
        raise MalformedPacket("unexpected NetBIOS name length")
    name, suffix = decode_name(buf[offset + 1 : offset + 33])
    # skip optional scope labels
    i = offset + 33
    while i < len(buf) and buf[i] != 0:
        i += 1 + buf[i]
    return name, suffix, i + 1


@dataclass
class NameRegistration:
    name: str
    suffix: int
    ip: str | None
    is_group: bool


def parse_registration(buf: bytes) -> NameRegistration | None:
    """Parse a broadcast registration / refresh (opcode 5, 8 or 9). Other packets return None."""
    if len(buf) < 12:
        return None
    _tid, flags, qd, an, ns, ar = struct.unpack_from("!6H", buf, 0)
    opcode = (flags >> 11) & 0x0F
    if flags & 0x8000 or opcode not in (5, 8, 9) or qd != 1 or ar < 1:
        return None
    name, suffix, offset = _read_encoded_name(buf, 12)
    offset += 4  # qtype, qclass
    _, _, offset = _read_encoded_name(buf, offset)  # additional record name (pointer)
    if offset + 10 > len(buf):
        return None
    rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", buf, offset)
    offset += 10
    if rtype != TYPE_NB or rdlen < 6 or offset + 6 > len(buf):
        return None
    nb_flags = struct.unpack_from("!H", buf, offset)[0]
    ip = str(ipaddress.IPv4Address(buf[offset + 2 : offset + 6]))
    return NameRegistration(name=name, suffix=suffix, ip=ip, is_group=bool(nb_flags & 0x8000))


def build_node_status_query(transaction_id: int) -> bytes:
    header = struct.pack("!6H", transaction_id & 0xFFFF, 0x0000, 1, 0, 0, 0)
    return header + encode_name("*") + struct.pack("!HH", TYPE_NBSTAT, 1)


@dataclass
class NodeStatus:
    names: list[tuple[str, int, bool]] = field(default_factory=list)  # (name, suffix, is_group)
    mac: str | None = None

    @property
    def workstation_name(self) -> str | None:
        for name, suffix, group in self.names:
            if suffix == 0x00 and not group:
                return name
        return None


def parse_node_status(buf: bytes) -> NodeStatus | None:
    if len(buf) < 12:
        return None
    _tid, flags, _qd, an, _ns, _ar = struct.unpack_from("!6H", buf, 0)
    if not flags & 0x8000 or an < 1:
        return None
    _, _, offset = _read_encoded_name(buf, 12)
    if offset + 10 > len(buf):
        raise MalformedPacket("truncated NBSTAT record")
    rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", buf, offset)
    offset += 10
    if rtype != TYPE_NBSTAT or offset + rdlen > len(buf) or rdlen < 1:
        return None
    count = buf[offset]
    offset += 1
    status = NodeStatus()
    for _ in range(count):
        if offset + 18 > len(buf):
            raise MalformedPacket("truncated name table")
        raw = buf[offset : offset + 18]
        name = raw[:15].decode("ascii", "replace").rstrip(" \x00")
        flags16 = struct.unpack_from("!H", raw, 16)[0]
        status.names.append((name, raw[15], bool(flags16 & 0x8000)))
        offset += 18
    if offset + 6 <= len(buf):
        status.mac = normalize_mac(bytes(buf[offset : offset + 6]))
        if status.mac == "00:00:00:00:00:00":
            status.mac = None
    return status
