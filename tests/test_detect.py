import ipaddress

import pytest
from conftest import FIXTURES

from lanwatch.db import Inventory
from lanwatch.detect import Context, analyze
from lanwatch.models import Observation
from lanwatch.oui import OuiDatabase

GW = "192.168.50.1"
GW_MAC = "a4:91:b1:12:34:56"
T0 = "2026-10-20T10:00:00+00:00"
T1 = "2026-10-20T10:15:00+00:00"
T2 = "2026-10-21T12:00:00+00:00"


@pytest.fixture
def inv():
    db = Inventory(":memory:")
    yield db
    db.close()


@pytest.fixture
def ctx():
    oui = OuiDatabase()
    oui.load_csv(FIXTURES / "oui_sample.csv")
    return Context(network=ipaddress.IPv4Network("192.168.50.0/24"), gateway_ip=GW, gateway_mac_baseline=GW_MAC, oui=oui)


def arp(mac, ip):
    return Observation("arp", mac=mac, ip=ip)


def run(inv, ctx, obs, ts):
    return analyze(inv, inv.start_run("passive", ts), obs, ctx, ts)


def kinds(inv):
    return [e["kind"] for e in inv.events()]


def test_first_run_inventories_and_alerts_on_vendor_macs(inv, ctx):
    res = run(inv, ctx, [arp(GW_MAC, GW), arp("3c:7c:3f:1a:2b:4d", "192.168.50.20")], T0)
    assert res.device_count == 2 and len(res.new_devices) == 2
    assert {a.kind for a in res.alerts} == {"new_device"}
    dev = inv.device("3c:7c:3f:1a:2b:4d")
    assert dev["vendor"] == "Example PC Maker" and dev["randomized"] == 0 and dev["known"] == 0


def test_second_run_is_quiet_and_updates_last_seen(inv, ctx):
    run(inv, ctx, [arp(GW_MAC, GW)], T0)
    res = run(inv, ctx, [arp(GW_MAC, GW)], T1)
    assert res.new_devices == [] and res.alerts == []
    assert inv.device(GW_MAC)["last_seen"] == T1 and inv.device(GW_MAC)["first_seen"] == T0


def test_private_mac_is_logged_but_batched(inv, ctx):
    res = run(inv, ctx, [arp(GW_MAC, GW), arp("da:a1:19:5e:22:07", "192.168.50.44"), arp("f6:00:00:00:00:02", "192.168.50.45")], T0)
    by_kind = {a.kind: a for a in res.alerts}
    assert "new_device_random" in by_kind
    assert by_kind["new_device_random"].severity == "info"
    assert "randomise" in by_kind["new_device_random"].body
    assert inv.device("da:a1:19:5e:22:07")["randomized"] == 1
    assert inv.device("da:a1:19:5e:22:07")["vendor"] is None
    # one summary, not one alert per phone
    assert sum(1 for a in res.alerts if "private" in a.title) == 1


def test_rotated_private_mac_links_to_earlier_device_without_trusting_it(inv, ctx):
    run(inv, ctx, [arp("da:a1:19:5e:22:07", "192.168.50.44"), Observation("dhcp", mac="da:a1:19:5e:22:07", ip="192.168.50.44", hostname="Pixel-8")], T0)
    inv.set_known("da:a1:19:5e:22:07", True)
    res = run(inv, ctx, [Observation("dhcp", mac="9a:00:00:00:00:09", ip="192.168.50.46", hostname="Pixel-8")], T2)
    assert "mac_rotated" in kinds(inv)
    assert res.alerts == []
    assert inv.device("9a:00:00:00:00:09")["known"] == 0  # hostnames are spoofable


def test_hostname_attaches_by_ip_and_respects_priority(inv, ctx):
    run(inv, ctx, [arp("f4:f5:d8:aa:bb:01", "192.168.50.31"), Observation("ptr", ip="192.168.50.31", hostname="tv-router-name")], T0)
    assert inv.device("f4:f5:d8:aa:bb:01")["hostname"] == "tv-router-name"
    run(inv, ctx, [arp("f4:f5:d8:aa:bb:01", "192.168.50.31"), Observation("mdns", ip="192.168.50.31", hostname="Living-Room-TV"),
                   Observation("ssdp", ip="192.168.50.31", model_hint="Linux UPnP/1.0")], T1)
    dev = inv.device("f4:f5:d8:aa:bb:01")
    assert dev["hostname"] == "Living-Room-TV" and dev["hostname_source"] == "mdns"
    assert dev["model_hint"] == "Linux UPnP/1.0"


def test_ip_change_and_history(inv, ctx):
    run(inv, ctx, [arp("3c:7c:3f:1a:2b:4d", "192.168.50.20")], T0)
    run(inv, ctx, [arp("3c:7c:3f:1a:2b:4d", "192.168.50.21")], T2)
    assert "ip_changed" in kinds(inv)
    assert {h["ip"] for h in inv.ip_history("3c:7c:3f:1a:2b:4d")} == {"192.168.50.20", "192.168.50.21"}


def test_same_run_ip_conflict(inv, ctx):
    res = run(inv, ctx, [arp("3c:7c:3f:1a:2b:4d", "192.168.50.20"), Observation("dhcp", mac="00:11:22:33:44:55", ip="192.168.50.20")], T0)
    assert any(a.kind == "ip_conflict" for a in res.alerts)
    # deduplicated for 24 h
    res = run(inv, ctx, [arp("3c:7c:3f:1a:2b:4d", "192.168.50.20"), Observation("dhcp", mac="00:11:22:33:44:55", ip="192.168.50.20")], T1)
    assert not any(a.kind == "ip_conflict" for a in res.alerts)


def test_cross_run_ip_takeover(inv, ctx):
    run(inv, ctx, [arp("3c:7c:3f:1a:2b:4d", "192.168.50.20")], T0)
    res = run(inv, ctx, [arp("00:11:22:33:44:55", "192.168.50.20")], T1)  # 15 min later, someone else
    assert any(a.kind == "ip_conflict" for a in res.alerts)


def test_moved_previous_holder_is_not_a_conflict(inv, ctx):
    run(inv, ctx, [arp("3c:7c:3f:1a:2b:4d", "192.168.50.20")], T0)
    res = run(inv, ctx, [arp("00:11:22:33:44:55", "192.168.50.20"), arp("3c:7c:3f:1a:2b:4d", "192.168.50.22")], T1)
    assert not any(a.kind == "ip_conflict" for a in res.alerts)


def test_gateway_mac_change_is_critical_and_alerts_once(inv, ctx):
    run(inv, ctx, [arp(GW_MAC, GW)], T0)
    evil = "00:de:ad:be:ef:01"
    res = run(inv, ctx, [arp(evil, GW), arp(evil, "192.168.50.66")], T1)
    crit = [a for a in res.alerts if a.severity == "critical"]
    assert {a.kind for a in crit} == {"gateway_mac_changed", "gateway_mac_shared"}
    res = run(inv, ctx, [arp(evil, GW)], T2)
    assert not any(a.kind == "gateway_mac_changed" for a in res.alerts)


def test_router_proxy_arp_is_a_warning_not_critical(inv, ctx):
    res = run(inv, ctx, [arp(GW_MAC, GW), arp(GW_MAC, "192.168.50.2")], T0)
    shared = [a for a in res.alerts if a.kind == "gateway_mac_shared"]
    assert shared and shared[0].severity == "warning"
