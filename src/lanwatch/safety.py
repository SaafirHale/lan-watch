"""The safety model.

1. A human confirms one network once (`lanwatch confirm`). The confirmation
   pins the interface, subnet, gateway, gateway MAC and Windows network
   profile name. It is stored outside the repo.
2. Every run re-reads the live configuration and compares it to the
   confirmation. If a VPN/tunnel adapter is up, the default route moved, or
   the subnet/gateway/profile differ, the run records nothing and sends
   nothing.
3. Active probes (ARP sweep, NetBIOS/PTR queries, the opt-in TCP check) need
   an ActiveAuthorization. The only way to get one is ``authorize_active``,
   which also requires the gateway MAC to match and ``allow_active`` to be
   set at confirmation time. Every probe then calls ``check_target`` on each
   address before a packet leaves.
4. Only RFC 1918 IPv4 subnets between /22 and /30 can be confirmed at all.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .netinfo import Snapshot

RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
MIN_PREFIX = 22  # at most 1022 hosts: a home LAN, never a corporate range
MAX_PREFIX = 30

CONFIRMATION_FILE = "confirmed-network.json"


class SafetyError(Exception):
    """Raised whenever an action would leave the confirmed home subnet."""


def require_home_sized_rfc1918(network: ipaddress.IPv4Network) -> None:
    if network.version != 4:
        raise SafetyError("only IPv4 subnets are supported")
    if not any(network.subnet_of(block) for block in RFC1918):
        raise SafetyError(f"{network} is not inside an RFC 1918 private range")
    if not MIN_PREFIX <= network.prefixlen <= MAX_PREFIX:
        raise SafetyError(f"/{network.prefixlen} is outside the allowed /{MIN_PREFIX}../{MAX_PREFIX} size")


@dataclass
class ConfirmedNetwork:
    interface_alias: str
    interface_index: int
    cidr: str
    local_ip: str
    gateway_ip: str
    gateway_mac: str | None
    profile_name: str
    allow_active: bool = False
    confirmed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.cidr)

    def save(self, data_dir: Path) -> Path:
        require_home_sized_rfc1918(self.network)
        data_dir.mkdir(parents=True, exist_ok=True)
        path = data_dir / CONFIRMATION_FILE
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, data_dir: Path) -> "ConfirmedNetwork | None":
        path = data_dir / CONFIRMATION_FILE
        if not path.exists():
            return None
        conf = cls(**json.loads(path.read_text(encoding="utf-8")))
        require_home_sized_rfc1918(conf.network)  # a hand-edited file gets the same check
        return conf


def build_confirmation(snapshot: Snapshot, gateway_mac: str | None, typed_cidr: str, allow_active: bool) -> ConfirmedNetwork:
    """Create a confirmation only if the human typed the subnet that is live right now."""
    problems = preflight_problems(snapshot)
    if problems:
        raise SafetyError("; ".join(problems))
    iface = snapshot.primary
    assert iface is not None
    try:
        typed = ipaddress.IPv4Network(typed_cidr.strip(), strict=True)
    except ValueError as exc:
        raise SafetyError(f"'{typed_cidr}' is not a subnet in CIDR form") from exc
    if typed != iface.network:
        raise SafetyError(f"typed subnet {typed} does not match the live subnet {iface.network}")
    return ConfirmedNetwork(
        interface_alias=iface.alias,
        interface_index=iface.index,
        cidr=str(iface.network),
        local_ip=str(iface.ip),
        gateway_ip=str(iface.gateway),
        gateway_mac=gateway_mac,
        profile_name=iface.profile_name,
        allow_active=allow_active,
    )


def preflight_problems(snapshot: Snapshot) -> list[str]:
    """Reasons this machine must not be inventoried right now, independent of any confirmation."""
    problems = []
    for adapter in snapshot.vpn_adapters_up:
        problems.append(f"VPN/tunnel adapter is up: {adapter.alias} ({adapter.description})")
    if snapshot.primary is None:
        problems.append("no IPv4 interface with a default route")
        return problems
    try:
        require_home_sized_rfc1918(snapshot.primary.network)
    except SafetyError as exc:
        problems.append(str(exc))
    if snapshot.primary.gateway not in snapshot.primary.network:
        problems.append("default gateway is not on the local subnet")
    return problems


@dataclass
class Verdict:
    passive_ok: bool
    active_ok: bool
    reasons: list[str]
    gateway_mac_observed: str | None = None

    @property
    def gateway_mac_changed(self) -> bool:
        return any(r.startswith("gateway MAC changed") for r in self.reasons)


def evaluate(snapshot: Snapshot, confirmed: ConfirmedNetwork | None, gateway_mac_now: str | None) -> Verdict:
    """Decide what this run may do. Passive needs a matching network; active also needs a matching gateway MAC."""
    if confirmed is None:
        return Verdict(False, False, ["no confirmed network yet: run `lanwatch confirm`"], gateway_mac_now)
    reasons = preflight_problems(snapshot)
    iface = snapshot.primary
    if iface is not None:
        if snapshot.default_route_indexes and snapshot.default_route_indexes[0] != confirmed.interface_index:
            reasons.append("default route is not on the confirmed interface")
        if iface.alias != confirmed.interface_alias or iface.index != confirmed.interface_index:
            reasons.append(f"interface is {iface.alias}, confirmed {confirmed.interface_alias}")
        if str(iface.network) != confirmed.cidr:
            reasons.append("subnet differs from the confirmed subnet")
        if str(iface.gateway) != confirmed.gateway_ip:
            reasons.append("gateway differs from the confirmed gateway")
        if confirmed.profile_name and iface.profile_name != confirmed.profile_name:
            reasons.append("Windows network profile differs from the confirmed network")
    passive_ok = not reasons

    active_reasons = list(reasons)
    if passive_ok and confirmed.gateway_mac and gateway_mac_now and gateway_mac_now != confirmed.gateway_mac:
        active_reasons.append("gateway MAC changed since confirmation (possible ARP spoofing); re-confirm before probing")
    if passive_ok and not confirmed.allow_active:
        active_reasons.append("active discovery was not enabled at confirmation")
    return Verdict(passive_ok, passive_ok and len(active_reasons) == len(reasons), active_reasons, gateway_mac_now)


class ActiveAuthorization:
    """Proof that the safety checks passed for this run. Probes require one."""

    _token = object()

    def __init__(self, token: object, confirmed: ConfirmedNetwork, local_ip: str) -> None:
        if token is not ActiveAuthorization._token:
            raise SafetyError("ActiveAuthorization can only be created by authorize_active()")
        self.network = confirmed.network
        self.local_ip = ipaddress.IPv4Address(local_ip)
        require_home_sized_rfc1918(self.network)

    def check_target(self, target: str | ipaddress.IPv4Address) -> ipaddress.IPv4Address:
        """Raise SafetyError unless ``target`` is a host address inside the confirmed subnet."""
        ip = ipaddress.IPv4Address(str(target))
        if not any(ip in block for block in RFC1918):
            raise SafetyError(f"{ip} is not an RFC 1918 address")
        if ip not in self.network:
            raise SafetyError(f"{ip} is outside the confirmed subnet")
        if ip in (self.network.network_address, self.network.broadcast_address):
            raise SafetyError(f"{ip} is the network or broadcast address")
        if ip == self.local_ip:
            raise SafetyError(f"{ip} is this machine")
        return ip

    def hosts(self) -> list[ipaddress.IPv4Address]:
        return [h for h in self.network.hosts() if h != self.local_ip]


def authorize_active(snapshot: Snapshot, confirmed: ConfirmedNetwork | None, gateway_mac_now: str | None) -> ActiveAuthorization:
    verdict = evaluate(snapshot, confirmed, gateway_mac_now)
    if not verdict.active_ok:
        raise SafetyError("active discovery refused: " + "; ".join(verdict.reasons))
    assert confirmed is not None and snapshot.primary is not None
    return ActiveAuthorization(ActiveAuthorization._token, confirmed, str(snapshot.primary.ip))
