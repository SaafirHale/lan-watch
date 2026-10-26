"""Command-line entry point: ``lanwatch <command>`` or ``python -m lanwatch``."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from . import TAGLINE, __version__, netinfo, notify, oui
from .db import Inventory
from .mac import normalize_mac
from .runner import DASHBOARD_PORT, data_dir, db_path, run_once
from .safety import ConfirmedNetwork, SafetyError, authorize_active, build_confirmation, evaluate, preflight_problems


def _home(args) -> Path:
    return Path(args.home) if getattr(args, "home", None) else data_dir()


def cmd_status(args) -> int:
    home = _home(args)
    snap = netinfo.read_snapshot()
    confirmed = ConfirmedNetwork.load(home)
    iface = snap.primary
    print(f"lan-watch {__version__}   -  data: {home}")
    if iface:
        print(f"Interface   {iface.alias} ({iface.description})")
        print(f"Address     {iface.ip}/{iface.network.prefixlen}   subnet {iface.network}")
        print(f"Gateway     {iface.gateway}")
        print(f"Profile     {iface.profile_name or '-'} ({iface.profile_category or '-'})")
    else:
        print("No IPv4 interface with a default route.")
    for a in snap.vpn_adapters_up:
        print(f"VPN UP      {a.alias} ({a.description})")
    for name in snap.umbrella_running:
        print(f"Running     {name}")
    gw_mac = None
    if iface and confirmed and iface.index == confirmed.interface_index:
        gw_mac = next((n.mac for n in netinfo.read_neighbors(iface.index) if n.ip == str(iface.gateway)), None)
    verdict = evaluate(snap, confirmed, gw_mac)
    print(f"Passive run allowed: {'yes' if verdict.passive_ok else 'no'}")
    print(f"Active probing allowed: {'yes' if verdict.active_ok else 'no'}")
    for r in verdict.reasons:
        print(f"  - {r}")
    return 0


def cmd_confirm(args) -> int:
    home = _home(args)
    snap = netinfo.read_snapshot()
    problems = preflight_problems(snap)
    iface = snap.primary
    if iface:
        print("Detected network (read from Windows; nothing has been sent):")
        print(f"  Interface  {iface.alias}  ({iface.description})")
        print(f"  This PC    {iface.ip}")
        print(f"  Subnet     {iface.network}")
        print(f"  Gateway    {iface.gateway}")
        print(f"  Profile    {iface.profile_name or '-'}")
    for name in snap.umbrella_running:
        print(f"  Note: {name} is running (DNS filtering only; it does not change the LAN).")
    if problems:
        print("\nRefusing to confirm:")
        for p in problems:
            print(f"  - {p}")
        return 2
    assert iface is not None
    neighbors = netinfo.read_neighbors(iface.index)
    gw_mac = next((n.mac for n in neighbors if n.ip == str(iface.gateway)), None)
    print(f"  Gateway MAC {gw_mac or 'not in the ARP cache yet'}")
    typed = args.subnet
    if not typed:
        print("\nOnly confirm this if it is your HOME network and any work VPN is disconnected.")
        typed = input(f"Type the subnet exactly ({iface.network}) to confirm, or press Enter to cancel: ").strip()
        if not typed:
            print("Cancelled.")
            return 1
    allow_active = args.allow_active
    if allow_active is None and not args.subnet:
        allow_active = input("Allow light active discovery (rate-limited ARP sweep of this subnet)? [y/N]: ").strip().lower() == "y"
    try:
        conf = build_confirmation(snap, gw_mac, typed, bool(allow_active))
    except SafetyError as exc:
        print(f"Refused: {exc}")
        return 2
    path = conf.save(home)
    print(f"Confirmed {conf.cidr} on {conf.interface_alias}. Active discovery: {'on' if conf.allow_active else 'off'}. Saved to {path}")
    return 0


def _print_report(report) -> None:
    if report.status != "ok":
        print(f"Run {report.status}:")
        for r in report.reasons:
            print(f"  - {r}")
    else:
        res = report.result
        print(f"Run ok: {res.device_count} devices seen, {len(res.new_devices)} new, {res.events} events, {report.toasts_sent} toasts.")
    for n in report.notes:
        print(f"   - {n}")


def cmd_run(args) -> int:
    report = run_once(want_active=args.active, listen_seconds=args.listen, send_toasts=not args.no_toast, home=_home(args))
    if not args.quiet:
        _print_report(report)
    return 0 if report.status in ("ok", "skipped") else 1


def cmd_serve(args) -> int:
    from .web import serve

    home = _home(args)
    server = serve(args.port, db_path(home), home)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"lan-watch dashboard on {url} (127.0.0.1 only). Ctrl+C to stop.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def cmd_devices(args) -> int:
    inv = Inventory(db_path(_home(args)))
    try:
        for d in inv.devices():
            flag = "known  " if d["known"] else "UNKNOWN"
            priv = " private-MAC" if d["randomized"] else ""
            name = d["label"] or d["hostname"] or d["vendor"] or "-"
            print(f"{flag} {d['mac']} {d['last_ip'] or '-':15} {name}{priv}  (last {d['last_seen']})")
    finally:
        inv.close()
    return 0


def _device_mac(value: str) -> str:
    mac = normalize_mac(value)
    if not mac:
        raise SystemExit(f"not a MAC address: {value}")
    return mac


def cmd_known(args) -> int:
    inv = Inventory(db_path(_home(args)))
    try:
        ok = inv.set_known(_device_mac(args.mac), not args.unset)
    finally:
        inv.close()
    print("updated" if ok else "no such device")
    return 0 if ok else 1


def cmd_label(args) -> int:
    inv = Inventory(db_path(_home(args)))
    try:
        ok = inv.set_label(_device_mac(args.mac), " ".join(args.text))
    finally:
        inv.close()
    print("updated" if ok else "no such device")
    return 0 if ok else 1


def cmd_ports(args) -> int:
    from . import active

    home = _home(args)
    snap = netinfo.read_snapshot()
    confirmed = ConfirmedNetwork.load(home)
    iface = snap.primary
    gw_mac = None
    if iface and confirmed and iface.index == confirmed.interface_index:
        gw_mac = next((n.mac for n in netinfo.read_neighbors(iface.index) if n.ip == str(iface.gateway)), None)
    try:
        auth = authorize_active(snap, confirmed, gw_mac)
        target = auth.check_target(args.ip)
    except (SafetyError, ValueError) as exc:
        print(f"Refused: {exc}")
        return 2
    if not args.yes:
        answer = input(f"TCP connect check of {len(active.TOP20_TCP)} common ports on {target}, one at a time. Proceed? [y/N]: ")
        if answer.strip().lower() != "y":
            print("Cancelled.")
            return 1
    results = active.tcp_top20(auth, str(target))
    open_ports = [p for p, is_open in results.items() if is_open]
    print(f"{target}: open {', '.join(map(str, open_ports)) if open_ports else 'none of the top 20'}")
    return 0


def cmd_update_oui(args) -> int:
    home = _home(args)
    sizes = oui.download(home)
    for name, size in sizes.items():
        print(f"{name}: {size / 1_000_000:.1f} MB")
    print(f"{len(oui.load_from_dir(home))} vendor prefixes cached in {home}")
    return 0


def cmd_notify_test(args) -> int:
    ok = notify.show_toast("lan-watch test", "Notifications are working.", f"http://127.0.0.1:{DASHBOARD_PORT}/")
    print("toast shown" if ok else "toast failed")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lanwatch", description=f"lan-watch {__version__}  - {TAGLINE}: home-network inventory, passive first.")
    p.add_argument("--home", help="data directory (default %%LOCALAPPDATA%%\\lan-watch or $LANWATCH_HOME)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show the live network and what the safety gate allows").set_defaults(func=cmd_status)

    c = sub.add_parser("confirm", help="confirm the current network as home (required before any run)")
    c.add_argument("--subnet", help="the live subnet in CIDR form, typed as confirmation")
    c.add_argument("--allow-active", action=argparse.BooleanOptionalAction, default=None, help="permit the rate-limited ARP sweep")
    c.set_defaults(func=cmd_confirm)

    r = sub.add_parser("run", help="one inventory run (passive unless --active)")
    r.add_argument("--active", action="store_true", help="add the rate-limited ARP sweep and name queries (needs allow-active)")
    r.add_argument("--listen", type=float, default=0.0, metavar="SECONDS", help="also listen for mDNS/SSDP/DHCP/NetBIOS broadcasts")
    r.add_argument("--no-toast", action="store_true")
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("serve", help="dashboard on 127.0.0.1")
    s.add_argument("--port", type=int, default=DASHBOARD_PORT)
    s.add_argument("--open", action="store_true", help="open the browser")
    s.set_defaults(func=cmd_serve)

    sub.add_parser("devices", help="list the inventory").set_defaults(func=cmd_devices)

    k = sub.add_parser("known", help="mark a device as known")
    k.add_argument("mac")
    k.add_argument("--unset", action="store_true")
    k.set_defaults(func=cmd_known)

    lb = sub.add_parser("label", help="give a device a name")
    lb.add_argument("mac")
    lb.add_argument("text", nargs="+")
    lb.set_defaults(func=cmd_label)

    po = sub.add_parser("ports", help="opt-in: TCP connect check of 20 common ports on ONE device")
    po.add_argument("ip")
    po.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    po.set_defaults(func=cmd_ports)

    sub.add_parser("update-oui", help="download the IEEE OUI/MA-M/MA-S CSVs for offline vendor lookup").set_defaults(func=cmd_update_oui)
    sub.add_parser("notify-test", help="show a test toast").set_defaults(func=cmd_notify_test)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # names from the network may not fit the console code page
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
