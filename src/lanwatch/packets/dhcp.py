"""DHCP client-message parser (RFC 2131 / 2132). Clients broadcast DISCOVER and
REQUEST, which carry their MAC (chaddr) and usually their hostname (option 12)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..mac import normalize_mac

MAGIC_COOKIE = b"\x63\x82\x53\x63"
MESSAGE_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


@dataclass
class DhcpInfo:
    op: int
    message_type: str | None
    mac: str | None
    hostname: str | None
    requested_ip: str | None
    client_ip: str | None
    vendor_class: str | None


def parse(buf: bytes) -> DhcpInfo | None:
    if len(buf) < 240 or buf[236:240] != MAGIC_COOKIE:
        return None
    op, htype, hlen = buf[0], buf[1], buf[2]
    ciaddr = buf[12:16]
    chaddr = buf[28 : 28 + 16]
    mac = normalize_mac(bytes(chaddr[:6])) if htype == 1 and hlen == 6 else None

    options: dict[int, bytes] = {}
    i = 240
    while i < len(buf):
        code = buf[i]
        if code == 0:  # pad
            i += 1
            continue
        if code == 255:  # end
            break
        if i + 1 >= len(buf):
            break
        length = buf[i + 1]
        if i + 2 + length > len(buf):
            break
        options[code] = buf[i + 2 : i + 2 + length]
        i += 2 + length

    def text(code: int) -> str | None:
        raw = options.get(code)
        return raw.decode("utf-8", "replace").rstrip("\x00") if raw else None

    hostname = text(12)
    if not hostname and 81 in options and len(options[81]) > 3:  # client FQDN, ASCII form
        hostname = options[81][3:].decode("utf-8", "replace").split(".")[0] or None
    requested = options.get(50)
    msg_type = options.get(53)
    return DhcpInfo(
        op=op,
        message_type=MESSAGE_TYPES.get(msg_type[0]) if msg_type else None,
        mac=mac,
        hostname=hostname,
        requested_ip=str(ipaddress.IPv4Address(requested)) if requested and len(requested) == 4 else None,
        client_ip=str(ipaddress.IPv4Address(ciaddr)) if ciaddr != b"\x00\x00\x00\x00" else None,
        vendor_class=text(60),
    )

