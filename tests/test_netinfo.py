import ipaddress

from conftest import fixture_json, fixture_text

from lanwatch.netinfo import parse_arp_a, parse_get_netneighbor, usable_neighbors

NET = ipaddress.IPv4Network("192.168.50.0/24")


def test_parse_arp_a_selects_interface_block():
    rows = parse_arp_a(fixture_text("arp_a.txt"), interface_ip="192.168.50.23")
    assert len(rows) == 9
    assert rows[0].ip == "192.168.50.1" and rows[0].mac == "a4:91:b1:12:34:56" and rows[0].state == "dynamic"
    all_rows = parse_arp_a(fixture_text("arp_a.txt"))
    assert any(r.ip == "172.27.111.255" for r in all_rows)


def test_usable_neighbors_from_arp_a():
    rows = usable_neighbors(parse_arp_a(fixture_text("arp_a.txt"), "192.168.50.23"), NET)
    assert [r.ip for r in rows] == ["192.168.50.1", "192.168.50.20", "192.168.50.31", "192.168.50.44"]


def test_get_netneighbor_filters_dead_multicast_and_offnet():
    rows = usable_neighbors(parse_get_netneighbor(fixture_json("neighbors.json")), NET)
    ips = [r.ip for r in rows]
    assert ips == ["192.168.50.1", "192.168.50.20", "192.168.50.31", "192.168.50.44"]
    assert "10.20.30.40" not in ips      # outside the subnet
    assert "192.168.50.77" not in ips    # Unreachable
    assert "192.168.50.255" not in ips   # broadcast


def test_snapshot_picks_default_route_interface(home_snapshot):
    p = home_snapshot.primary
    assert p.alias == "Wi-Fi" and p.index == 19
    assert str(p.network) == "192.168.50.0/24" and str(p.gateway) == "192.168.50.1"
    assert p.profile_name == "HomeNet" and p.dns_servers == ["192.168.50.1"]
    assert home_snapshot.vpn_adapters_up == []          # AnyConnect adapter exists but is Disconnected
    assert home_snapshot.umbrella_running == []


def test_snapshot_detects_vpn(vpn_snapshot):
    assert [a.alias for a in vpn_snapshot.vpn_adapters_up] == ["Ethernet 3"]
    assert vpn_snapshot.primary.alias == "Ethernet 3"   # VPN holds the lowest-metric default route
    assert vpn_snapshot.umbrella_running == ["Cisco Secure Client - Umbrella Agent"]


def test_single_object_json_is_accepted():
    # ConvertTo-Json emits a bare object for one item in some PowerShell paths
    rows = parse_get_netneighbor({"ip": "192.168.50.1", "mac": "A4-91-B1-12-34-56", "state": "Reachable"})
    assert len(rows) == 1
