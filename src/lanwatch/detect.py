"""Turn one run's observations into inventory updates, timeline events and alerts.

Detections:
- new device (a MAC never seen before)
- new device on a private/randomised MAC (locally administered bit set):
  recorded and shown, but batched into one low-key notice instead of an
  "intruder" alert, because phones rotate these addresses
- private MAC rotation: a new randomised MAC announcing the same hostname as
  a device already in the inventory (hint only; hostnames are spoofable, so
  it never inherits "known")
- IP conflict: two MACs claiming one IP in the same run, or an IP changing
  hands within a short window while the previous holder vanished
- gateway ARP change: the gateway IP resolving to a MAC other than the one
  confirmed, or the gateway's MAC also answering for another IP (the
  classic ARP-spoofing signature)
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .db import Inventory
from .mac import is_locally_administered, is_usable_unicast
from .models import HOSTNAME_PRIORITY, Observation
from .oui import OuiDatabase

MAC_SOURCES = {"arp", "sweep", "dhcp", "netbios"}


@dataclass
class Context:
    network: ipaddress.IPv4Network
    gateway_ip: str
    gateway_mac_baseline: str | None
    oui: OuiDatabase | None = None
    conflict_window: timedelta = timedelta(minutes=30)
    dedupe_window: timedelta = timedelta(hours=24)


@dataclass
class Alert:
    severity: str  # info, warning, critical
    title: str
    body: str
    kind: str


@dataclass
class RunResult:
    device_count: int = 0
    new_devices: list[str] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    events: int = 0


@dataclass
class _Agg:
    ips: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    hostname: str | None = None
    hostname_source: str | None = None
    model_hint: str | None = None

    def offer_hostname(self, name: str | None, source: str) -> None:
        if not name:
            return
        if self.hostname is None or HOSTNAME_PRIORITY.get(source, 0) > HOSTNAME_PRIORITY.get(self.hostname_source or "", 0):
            self.hostname, self.hostname_source = name, source


def _shift(ts: str, delta: timedelta) -> str:
    return (datetime.fromisoformat(ts) - delta).isoformat(timespec="seconds")


def _in_net(ip: str | None, network: ipaddress.IPv4Network) -> bool:
    try:
        return ip is not None and ipaddress.IPv4Address(ip) in network
    except ValueError:
        return False


def _display(row_or_mac, hostname: str | None = None) -> str:
    if isinstance(row_or_mac, str):
        return hostname or row_or_mac
    return row_or_mac["label"] or row_or_mac["hostname"] or row_or_mac["mac"]


def analyze(inv: Inventory, run_id: int, observations: list[Observation], ctx: Context, now: str) -> RunResult:
    result = RunResult()
    since_dedupe = _shift(now, ctx.dedupe_window)

    def event(kind: str, severity: str, message: str, mac: str | None = None, ip: str | None = None, data: dict | None = None) -> None:
        inv.add_event(now, run_id, kind, severity, message, mac=mac, ip=ip, data=data)
        result.events += 1

    # 1. IP -> MAC bindings from sources that carry a MAC
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    for o in observations:
        if o.mac and is_usable_unicast(o.mac) and _in_net(o.ip, ctx.network) and o.source in MAC_SOURCES:
            ip_to_macs[o.ip].add(o.mac)

    # 2. aggregate per MAC; MAC-less observations (mDNS, SSDP, PTR) attach by IP
    agg: dict[str, _Agg] = defaultdict(_Agg)
    for o in observations:
        mac = o.mac if o.mac and is_usable_unicast(o.mac) else None
        if mac is None and _in_net(o.ip, ctx.network):
            holders = ip_to_macs.get(o.ip, set())
            if len(holders) == 1:
                mac = next(iter(holders))
        if mac is None:
            continue
        a = agg[mac]
        a.sources.add(o.source)
        if o.ip and _in_net(o.ip, ctx.network) and (o.source in MAC_SOURCES):
            a.ips.add(o.ip)
        a.offer_hostname(o.hostname, o.source)
        if o.model_hint and not a.model_hint:
            a.model_hint = o.model_hint

    # 3. same-run IP conflicts
    for ip, macs in sorted(ip_to_macs.items()):
        if len(macs) > 1 and ip != ctx.gateway_ip:
            if not inv.recent_event("ip_conflict", since_dedupe, ip=ip):
                event("ip_conflict", "warning", f"{ip} is claimed by {len(macs)} devices at once", ip=ip, data={"macs": sorted(macs)})
                result.alerts.append(Alert("warning", "IP conflict", f"{ip} is claimed by {len(macs)} different devices.", "ip_conflict"))

    # 4. gateway ARP integrity
    gw_macs = ip_to_macs.get(ctx.gateway_ip, set())
    for gw_mac in sorted(gw_macs):
        if ctx.gateway_mac_baseline and gw_mac != ctx.gateway_mac_baseline:
            if inv.get_meta("alerted_gateway_mac") != gw_mac:
                event(
                    "gateway_mac_changed", "critical",
                    "Gateway now resolves to a different MAC than the one confirmed. Possible ARP spoofing, or the router was replaced.",
                    mac=gw_mac, ip=ctx.gateway_ip, data={"expected": ctx.gateway_mac_baseline, "observed": gw_mac},
                )
                inv.set_meta("alerted_gateway_mac", gw_mac)
                result.alerts.append(Alert("critical", "Gateway MAC changed", "Your router's address now maps to a different device. Possible ARP spoofing. Active probing is paused until you re-confirm.", "gateway_mac_changed"))
        for ip, macs in ip_to_macs.items():
            if ip != ctx.gateway_ip and gw_mac in macs and not inv.recent_event("gateway_mac_shared", since_dedupe, ip=ip):
                severity = "critical" if gw_mac != ctx.gateway_mac_baseline else "warning"
                event("gateway_mac_shared", severity,
                      f"The gateway's MAC also answers for {ip}: classic ARP-spoofing signature (or a router/extender proxying ARP).",
                      mac=gw_mac, ip=ip)
                result.alerts.append(Alert(severity, "Gateway MAC shared", f"The router's MAC also answers for {ip}.", "gateway_mac_shared"))

    # 5. per-device inventory updates
    random_new: list[str] = []
    for mac, a in sorted(agg.items()):
        ip = sorted(a.ips)[0] if a.ips else None
        row = inv.device(mac)
        randomized = is_locally_administered(mac)
        if row is None:
            vendor = ctx.oui.lookup(mac) if ctx.oui else None
            inv.insert_device(
                mac, now, last_ip=ip, vendor=vendor, hostname=a.hostname, hostname_source=a.hostname_source,
                model_hint=a.model_hint, known=0, randomized=1 if randomized else 0, last_sources=",".join(sorted(a.sources)),
            )
            result.new_devices.append(mac)
            name = a.hostname or vendor or "unknown vendor"
            if randomized:
                twins = [d for d in (inv.devices_with_hostname(a.hostname) if a.hostname else []) if d["mac"] != mac]
                if twins:
                    twin = twins[0]
                    event("mac_rotated", "info",
                          f"New private MAC announcing '{a.hostname}', the same name as {_display(twin)}. Probably the same device with a rotated address; hostnames can be spoofed, so confirm before marking it known.",
                          mac=mac, ip=ip, data={"previous_mac": twin["mac"]})
                else:
                    event("new_device", "info", f"New device on a private (randomised) MAC: {name}", mac=mac, ip=ip, data={"randomized": True})
                    random_new.append(name)
            else:
                event("new_device", "warning", f"New device joined: {name}", mac=mac, ip=ip, data={"vendor": vendor})
                result.alerts.append(Alert("warning", "New device on your network", f"{name} at {ip or 'unknown IP'}. Open the dashboard to label it or mark it known.", "new_device"))
        else:
            updates: dict = {"last_seen": now, "last_sources": ",".join(sorted(a.sources))}
            if ip and ip != row["last_ip"]:
                updates["last_ip"] = ip
                if row["last_ip"]:
                    event("ip_changed", "info", f"{_display(row)} moved from {row['last_ip']} to {ip}", mac=mac, ip=ip)
            if a.hostname and (
                row["hostname"] is None
                or HOSTNAME_PRIORITY.get(a.hostname_source or "", 0) >= HOSTNAME_PRIORITY.get(row["hostname_source"] or "", 0)
            ):
                updates["hostname"], updates["hostname_source"] = a.hostname, a.hostname_source
            if a.model_hint and not row["model_hint"]:
                updates["model_hint"] = a.model_hint
            if ctx.oui:
                vendor = ctx.oui.lookup(mac)  # picks up refreshed OUI data
                if vendor and vendor != row["vendor"]:
                    updates["vendor"] = vendor
            inv.update_device(mac, **updates)

        # 6. cross-run conflict: this IP belonged to someone else very recently
        for this_ip in a.ips:
            if this_ip == ctx.gateway_ip:
                continue
            for other in inv.other_holders(this_ip, mac):
                if other["last_seen"] < _shift(now, ctx.conflict_window):
                    continue
                other_now = agg.get(other["mac"])
                if other_now and this_ip not in other_now.ips:
                    continue  # the previous holder simply moved
                if not inv.recent_event("ip_conflict", since_dedupe, ip=this_ip):
                    event("ip_conflict", "warning",
                          f"{this_ip} changed hands within {int(ctx.conflict_window.total_seconds() // 60)} minutes: possible IP conflict or spoofing",
                          mac=mac, ip=this_ip, data={"previous_mac": other["mac"]})
                    result.alerts.append(Alert("warning", "Possible IP conflict", f"{this_ip} changed hands between two devices within minutes.", "ip_conflict"))
            inv.touch_ip(mac, this_ip, now)

    if random_new:
        listed = ", ".join(random_new[:3]) + (f" and {len(random_new) - 3} more" if len(random_new) > 3 else "")
        result.alerts.append(Alert(
            "info", f"{len(random_new)} new device(s) on private MACs",
            f"{listed}. Phones and laptops randomise their Wi-Fi MAC for privacy, so this is usually a known device. Check the dashboard.",
            "new_device_random",
        ))

    result.device_count = len(agg)
    inv.commit()
    return result
