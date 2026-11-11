"""One inventory run, start to finish, with the safety gate in front."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import active, listen, netinfo, notify, oui
from .db import Inventory, utcnow
from .detect import Context, RunResult, analyze
from .models import Observation
from .safety import ConfirmedNetwork, SafetyError, authorize_active, evaluate

DASHBOARD_PORT = 8765


def data_dir() -> Path:
    override = os.environ.get("LANWATCH_HOME")
    if override:
        return Path(override)
    # Not %LOCALAPPDATA%: Windows silently redirects AppData writes made from
    # packaged (MSIX) apps into a private per-app copy, so a terminal inside
    # such an app and the scheduled task would each see different data. The
    # profile root is never virtualised.
    return Path.home() / ".lan-watch"


def db_path(home: Path | None = None) -> Path:
    return (home or data_dir()) / "inventory.sqlite3"


@dataclass
class RunReport:
    status: str  # ok, skipped, error
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    result: RunResult | None = None
    toasts_sent: int = 0
    run_id: int | None = None


def run_once(
    *,
    want_active: bool = False,
    listen_seconds: float = 0.0,
    send_toasts: bool = True,
    home: Path | None = None,
    read_snapshot: Callable[[], netinfo.Snapshot] = netinfo.read_snapshot,
    read_neighbors: Callable[[int], list[netinfo.Neighbor]] = netinfo.read_neighbors,
    toast_sender=notify.show_toast,
) -> RunReport:
    home = home or data_dir()
    inv = Inventory(db_path(home))
    mode = "active" if want_active else "passive"
    run_id = inv.start_run(mode, utcnow())
    report = RunReport(status="ok", run_id=run_id)
    try:
        confirmed = ConfirmedNetwork.load(home)
        snapshot = read_snapshot()

        # Gate 1: is this the confirmed home network, with no VPN up? Checked
        # before the neighbor table is even read, so nothing from another
        # network is ever stored.
        gate = evaluate(snapshot, confirmed, gateway_mac_now=None)
        if not gate.passive_ok:
            report.status, report.reasons = "skipped", gate.reasons
            inv.finish_run(run_id, "skipped", note="; ".join(gate.reasons))
            return report
        assert confirmed is not None and snapshot.primary is not None
        iface = snapshot.primary

        neighbors = netinfo.usable_neighbors(read_neighbors(iface.index), iface.network)
        observations = [Observation("arp", mac=n.mac, ip=n.ip) for n in neighbors]
        gateway_mac_now = next((n.mac for n in neighbors if n.ip == str(iface.gateway)), None)

        if listen_seconds > 0:
            heard = listen.listen(listen_seconds, str(iface.ip), iface.network)
            observations += heard.observations
            report.notes.append(f"listened {listen_seconds:.0f}s on {', '.join(heard.bound) or 'nothing'}: {heard.packets} packets")
            for kind, why in heard.skipped.items():
                report.notes.append(f"{kind} listener skipped: {why}")

        if want_active:
            # Gate 2: active probing additionally needs allow_active and an unchanged gateway MAC.
            try:
                auth = authorize_active(snapshot, confirmed, gateway_mac_now)
            except SafetyError as exc:
                report.notes.append(str(exc))
            else:
                swept = active.arp_sweep(auth)
                observations += swept
                ips = sorted({o.ip for o in observations if o.ip and o.ip != str(iface.ip)})
                observations += active.netbios_names(auth, ips)
                if str(iface.gateway) in iface.dns_servers:
                    observations += active.ptr_names(auth, str(iface.gateway), ips)
                report.notes.append(f"ARP sweep answered by {len(swept)} hosts")

        ctx = Context(
            network=iface.network,
            gateway_ip=str(iface.gateway),
            gateway_mac_baseline=confirmed.gateway_mac,
            oui=oui.load_from_dir(home),
        )
        result = analyze(inv, run_id, observations, ctx, utcnow())
        report.result = result
        if send_toasts and result.alerts:
            report.toasts_sent = notify.deliver(result.alerts, f"http://127.0.0.1:{DASHBOARD_PORT}/", sender=toast_sender)
        inv.finish_run(run_id, "ok", device_count=result.device_count, new_count=len(result.new_devices), note="; ".join(report.notes) or None)
        return report
    except Exception as exc:
        report.status, report.reasons = "error", [f"{type(exc).__name__}: {exc}"]
        inv.finish_run(run_id, "error", note=report.reasons[0][:500])
        return report
    finally:
        inv.close()
