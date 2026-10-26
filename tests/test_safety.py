import copy
import ipaddress

import pytest
from conftest import fixture_json

from lanwatch.netinfo import parse_snapshot
from lanwatch.safety import (
    ActiveAuthorization,
    ConfirmedNetwork,
    SafetyError,
    authorize_active,
    build_confirmation,
    evaluate,
    require_home_sized_rfc1918,
)


@pytest.mark.parametrize("cidr", ["192.168.1.0/24", "10.0.0.0/22", "172.16.5.0/24", "192.168.50.128/25"])
def test_home_sized_private_subnets_are_allowed(cidr):
    require_home_sized_rfc1918(ipaddress.IPv4Network(cidr))


@pytest.mark.parametrize("cidr", [
    "8.8.8.0/24",          # public
    "100.64.0.0/24",       # CGNAT is not RFC 1918
    "169.254.0.0/24",      # link-local
    "10.0.0.0/16",         # private but corporate-sized
    "172.32.0.0/24",       # just outside 172.16/12
    "192.168.0.0/21",
])
def test_everything_else_is_refused(cidr):
    with pytest.raises(SafetyError):
        require_home_sized_rfc1918(ipaddress.IPv4Network(cidr))


def test_confirmation_requires_typing_the_live_subnet(home_snapshot):
    with pytest.raises(SafetyError, match="does not match"):
        build_confirmation(home_snapshot, None, "192.168.1.0/24", False)
    with pytest.raises(SafetyError, match="CIDR"):
        build_confirmation(home_snapshot, None, "yes", False)
    conf = build_confirmation(home_snapshot, "a4:91:b1:12:34:56", " 192.168.50.0/24 ", False)
    assert conf.cidr == "192.168.50.0/24" and conf.gateway_ip == "192.168.50.1" and conf.profile_name == "HomeNet"


def test_confirmation_refused_while_vpn_is_up(vpn_snapshot):
    with pytest.raises(SafetyError, match="VPN"):
        build_confirmation(vpn_snapshot, None, "192.168.50.0/24", False)


def test_confirmation_roundtrip_and_tamper_check(tmp_path, confirmed):
    confirmed.save(tmp_path)
    assert ConfirmedNetwork.load(tmp_path) == confirmed
    # A hand-edited file widening the range is refused on load.
    text = (tmp_path / "confirmed-network.json").read_text().replace("192.168.50.0/24", "10.0.0.0/8")
    (tmp_path / "confirmed-network.json").write_text(text)
    with pytest.raises(SafetyError):
        ConfirmedNetwork.load(tmp_path)


def test_evaluate_matching_network(home_snapshot, confirmed):
    v = evaluate(home_snapshot, confirmed, "a4:91:b1:12:34:56")
    assert v.passive_ok and v.active_ok and v.reasons == []


def test_evaluate_without_confirmation(home_snapshot):
    v = evaluate(home_snapshot, None, None)
    assert not v.passive_ok and not v.active_ok


def test_evaluate_vpn_blocks_everything(vpn_snapshot, confirmed):
    v = evaluate(vpn_snapshot, confirmed, None)
    assert not v.passive_ok and not v.active_ok
    assert any("VPN" in r for r in v.reasons)


def test_evaluate_different_network_blocks_everything(confirmed):
    payload = copy.deepcopy(fixture_json("snapshot_home.json"))
    payload["profiles"][0]["name"] = "CoffeeShop"
    v = evaluate(parse_snapshot(payload), confirmed, None)
    assert not v.passive_ok
    payload = copy.deepcopy(fixture_json("snapshot_home.json"))
    payload["addresses"][0]["ip"] = "192.168.60.23"
    payload["routes"][0]["nexthop"] = "192.168.60.1"
    v = evaluate(parse_snapshot(payload), confirmed, None)
    assert not v.passive_ok and "subnet differs from the confirmed subnet" in v.reasons


def test_gateway_mac_change_keeps_passive_but_blocks_active(home_snapshot, confirmed):
    v = evaluate(home_snapshot, confirmed, "de:ad:be:ef:00:01")
    assert v.passive_ok and not v.active_ok and v.gateway_mac_changed


def test_active_needs_opt_in(home_snapshot, confirmed):
    confirmed.allow_active = False
    v = evaluate(home_snapshot, confirmed, "a4:91:b1:12:34:56")
    assert v.passive_ok and not v.active_ok
    with pytest.raises(SafetyError, match="not enabled"):
        authorize_active(home_snapshot, confirmed, "a4:91:b1:12:34:56")


def test_authorization_cannot_be_forged(confirmed):
    with pytest.raises(SafetyError):
        ActiveAuthorization(object(), confirmed, "192.168.50.23")


def test_check_target_hard_limits(home_snapshot, confirmed):
    auth = authorize_active(home_snapshot, confirmed, "a4:91:b1:12:34:56")
    assert str(auth.check_target("192.168.50.31")) == "192.168.50.31"
    for bad in ("192.168.51.5", "10.0.0.1", "8.8.8.8", "192.168.50.0", "192.168.50.255", "192.168.50.23"):
        with pytest.raises(SafetyError):
            auth.check_target(bad)
    hosts = auth.hosts()
    assert len(hosts) == 253 and ipaddress.IPv4Address("192.168.50.23") not in hosts
