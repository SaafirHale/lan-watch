"""Local network configuration and the OS neighbor table (both read-only).

Everything here reads state Windows already has. Nothing in this module
sends a packet.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass, field
from importlib import resources

from .mac import normalize_mac

# Adapter descriptions that indicate a VPN / tunnel client is up. When any of
# these is "Up" the run is refused: the laptop may be on the employer network.
VPN_PATTERN = re.compile(
    r"anyconnect|secure client|vpn|wireguard|wintun|tap-windows|openvpn|tunnel|"
    r"zscaler|globalprotect|pangp|fortinet|forticlient|juniper|pulse secure|ivanti|"
    r"tailscale|zerotier|nordlynx",
    re.IGNORECASE,
)
UMBRELLA_PATTERN = re.compile(r"umbrella", re.IGNORECASE)


@dataclass
class Adapter:
    alias: str
    index: int
    description: str
    status: str
    mac: str | None
    virtual: bool

    @property
    def is_up(self) -> bool:
        return self.status.lower() == "up"

    @property
    def looks_like_vpn(self) -> bool:
        return bool(VPN_PATTERN.search(self.description) or VPN_PATTERN.search(self.alias))


@dataclass
class Interface:
    """The interface that carries the default route, with its IPv4 details."""

    alias: str
    index: int
    description: str
    mac: str | None
    ip: ipaddress.IPv4Address
    network: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    profile_name: str
    profile_category: str
    dns_servers: list[str] = field(default_factory=list)


@dataclass
class Snapshot:
    adapters: list[Adapter]
    primary: Interface | None
    default_route_indexes: list[int]
    services: list[dict]

    @property
    def vpn_adapters_up(self) -> list[Adapter]:
        return [a for a in self.adapters if a.is_up and a.looks_like_vpn]

    @property
    def umbrella_running(self) -> list[str]:
        return [
            s["display"]
            for s in self.services
            if s.get("status", "").lower() == "running"
            and UMBRELLA_PATTERN.search(s.get("display", "") + s.get("name", ""))
        ]


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_snapshot(payload: dict) -> Snapshot:
    adapters = [
        Adapter(
            alias=a.get("alias") or "",
            index=int(a.get("index", -1)),
            description=a.get("description") or "",
            status=a.get("status") or "",
            mac=normalize_mac(a.get("mac")),
            virtual=bool(a.get("virtual")),
        )
        for a in _as_list(payload.get("adapters"))
    ]
    by_index = {a.index: a for a in adapters}
    routes = sorted(
        (r for r in _as_list(payload.get("routes")) if r.get("nexthop") not in (None, "", "0.0.0.0")),
        key=lambda r: r.get("metric", 0),
    )
    route_indexes = [int(r["index"]) for r in routes]

    primary: Interface | None = None
    for route in routes:
        idx = int(route["index"])
        adapter = by_index.get(idx)
        if adapter is None or not adapter.is_up:
            continue
        addrs = [a for a in _as_list(payload.get("addresses")) if int(a.get("index", -1)) == idx]
        addrs = [a for a in addrs if not str(a.get("ip", "")).startswith("169.254.")]
        if not addrs:
            continue
        addr = addrs[0]
        ip = ipaddress.IPv4Address(addr["ip"])
        network = ipaddress.IPv4Network(f"{ip}/{int(addr['prefix'])}", strict=False)
        profile = next((p for p in _as_list(payload.get("profiles")) if int(p.get("index", -1)) == idx), {})
        dns = next((d for d in _as_list(payload.get("dns")) if int(d.get("index", -1)) == idx), {})
        primary = Interface(
            alias=adapter.alias,
            index=idx,
            description=adapter.description,
            mac=adapter.mac,
            ip=ip,
            network=network,
            gateway=ipaddress.IPv4Address(route["nexthop"]),
            profile_name=profile.get("name") or "",
            profile_category=profile.get("category") or "",
            dns_servers=[str(s) for s in _as_list(dns.get("servers"))],
        )
        break

    return Snapshot(
        adapters=adapters,
        primary=primary,
        default_route_indexes=route_indexes,
        services=[s for s in _as_list(payload.get("services")) if isinstance(s, dict)],
    )


# --- Neighbor table -------------------------------------------------------


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac: str | None
    state: str  # Reachable, Stale, Delay, Probe, Permanent, Unreachable, Incomplete, dynamic, static


_ARP_LINE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(?P<type>\w+)\s*$"
)
_ARP_IFACE = re.compile(r"^Interface:\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+---\s+(?P<idx>0x[0-9a-fA-F]+)")


def parse_arp_a(text: str, interface_ip: str | None = None) -> list[Neighbor]:
    """Parse ``arp -a`` output. If ``interface_ip`` is given, keep only that block."""
    out: list[Neighbor] = []
    current_iface: str | None = None
    for line in text.splitlines():
        m = _ARP_IFACE.match(line)
        if m:
            current_iface = m.group("ip")
            continue
        m = _ARP_LINE.match(line)
        if not m:
            continue
        if interface_ip and current_iface != interface_ip:
            continue
        out.append(Neighbor(ip=m.group("ip"), mac=normalize_mac(m.group("mac")), state=m.group("type").lower()))
    return out


def parse_get_netneighbor(payload) -> list[Neighbor]:
    return [
        Neighbor(ip=str(r.get("ip")), mac=normalize_mac(r.get("mac") or ""), state=str(r.get("state") or ""))
        for r in _as_list(payload)
        if r and r.get("ip")
    ]


_DEAD_STATES = {"unreachable", "incomplete", "invalid"}


def usable_neighbors(neighbors: list[Neighbor], network: ipaddress.IPv4Network) -> list[Neighbor]:
    """Drop entries outside the subnet, broadcast/multicast and failed resolutions."""
    from .mac import is_usable_unicast

    keep = []
    for n in neighbors:
        try:
            ip = ipaddress.IPv4Address(n.ip)
        except ValueError:
            continue
        if ip not in network or ip in (network.network_address, network.broadcast_address):
            continue
        if n.state.lower() in _DEAD_STATES or not is_usable_unicast(n.mac):
            continue
        keep.append(n)
    return keep


# --- Live readers (Windows only) -------------------------------------------


def _run_ps(script_name: str, *args: str, timeout: float = 60.0) -> str:
    script = resources.files("lanwatch").joinpath("ps", script_name)
    with resources.as_file(script) as path:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path), *args],
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    if proc.returncode != 0:
        raise RuntimeError(f"{script_name} failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout.decode("utf-8-sig", "replace").strip()


def read_snapshot() -> Snapshot:
    return parse_snapshot(json.loads(_run_ps("snapshot.ps1")))


def read_neighbors(interface_index: int) -> list[Neighbor]:
    text = _run_ps("neighbors.ps1", "-InterfaceIndex", str(int(interface_index)))
    return parse_get_netneighbor(json.loads(text) if text else [])
