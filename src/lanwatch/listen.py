"""Passive listeners: receive mDNS, SSDP, DHCP and NetBIOS broadcasts for a
few seconds. They only receive; nothing is transmitted.

Windows Defender Firewall drops unsolicited inbound UDP for apps without an
allow rule, and Windows itself owns UDP 137 when NetBIOS over TCP/IP is on.
Each listener that cannot bind is skipped and reported, never forced.
"""

from __future__ import annotations

import ipaddress
import select
import socket
import struct
import time
from dataclasses import dataclass, field

from .models import Observation
from .packets import dhcp, dns, netbios, ssdp

MDNS_GROUP = "224.0.0.251"
SSDP_GROUP = "239.255.255.250"


@dataclass
class ListenResult:
    observations: list[Observation] = field(default_factory=list)
    bound: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    packets: int = 0


def observations_from_packet(kind: str, payload: bytes, src_ip: str, network: ipaddress.IPv4Network) -> list[Observation]:
    """Turn one received datagram into observations. Pure; used by tests with fixtures."""
    out: list[Observation] = []

    def on_lan(ip: str | None) -> bool:
        try:
            return ip is not None and ipaddress.IPv4Address(ip) in network
        except ValueError:
            return False

    try:
        if kind == "mdns":
            msg = dns.parse(payload)
            for ip, host in dns.mdns_hostnames(msg).items():
                if on_lan(ip):
                    out.append(Observation("mdns", ip=ip, hostname=host))
        elif kind == "ssdp":
            ann = ssdp.parse(payload)
            if ann and ann.server and on_lan(src_ip):
                out.append(Observation("ssdp", ip=src_ip, model_hint=ann.server))
        elif kind == "dhcp":
            info = dhcp.parse(payload)
            if info and info.op == 1 and info.mac:
                ip = info.requested_ip or info.client_ip
                out.append(Observation("dhcp", mac=info.mac, ip=ip if on_lan(ip) else None, hostname=info.hostname, model_hint=info.vendor_class))
        elif kind == "netbios":
            reg = netbios.parse_registration(payload)
            if reg and not reg.is_group and reg.suffix == 0x00 and on_lan(reg.ip):
                out.append(Observation("netbios", ip=reg.ip, hostname=reg.name))
    except (dns.MalformedPacket, ValueError, IndexError, struct.error):
        return []
    return out


def _multicast_socket(port: int, group: str, iface_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    mreq = socket.inet_aton(group) + socket.inet_aton(iface_ip)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setblocking(False)
    return s


def _broadcast_socket(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", port))
    s.setblocking(False)
    return s


def listen(seconds: float, iface_ip: str, network: ipaddress.IPv4Network) -> ListenResult:
    result = ListenResult()
    sockets: dict[socket.socket, str] = {}
    openers = {
        "mdns": lambda: _multicast_socket(5353, MDNS_GROUP, iface_ip),
        "ssdp": lambda: _multicast_socket(1900, SSDP_GROUP, iface_ip),
        "dhcp": lambda: _broadcast_socket(67),
        "netbios": lambda: _broadcast_socket(137),
    }
    for kind, opener in openers.items():
        try:
            sockets[opener()] = kind
            result.bound.append(kind)
        except OSError as exc:
            result.skipped[kind] = exc.strerror or str(exc)
    deadline = time.monotonic() + seconds
    try:
        while sockets and (remaining := deadline - time.monotonic()) > 0:
            ready, _, _ = select.select(list(sockets), [], [], min(remaining, 1.0))
            for sock in ready:
                try:
                    payload, (src_ip, _port) = sock.recvfrom(9000)
                except OSError:
                    continue
                result.packets += 1
                result.observations.extend(observations_from_packet(sockets[sock], payload, src_ip, network))
    finally:
        for sock in sockets:
            sock.close()
    return result
