import pytest
from conftest import fixture_json

from lanwatch.db import Inventory
from lanwatch.netinfo import parse_get_netneighbor, parse_snapshot
from lanwatch.runner import db_path, run_once


def neighbors_fixture(_index):
    return parse_get_netneighbor(fixture_json("neighbors.json"))


def forbidden_neighbors(_index):
    raise AssertionError("neighbor table must not be read when the gate fails")


@pytest.fixture
def toasts():
    sent = []
    return sent


def sender_into(sent):
    def send(title, body, url):
        sent.append((title, body, url))
        return True
    return send


def test_unconfirmed_network_records_nothing(tmp_path, toasts):
    report = run_once(home=tmp_path, read_snapshot=lambda: parse_snapshot(fixture_json("snapshot_home.json")),
                      read_neighbors=forbidden_neighbors, toast_sender=sender_into(toasts))
    assert report.status == "skipped" and "confirm" in report.reasons[0]
    inv = Inventory(db_path(tmp_path))
    assert inv.devices() == [] and inv.runs()[0]["status"] == "skipped"
    inv.close()


def test_vpn_up_skips_before_reading_neighbors(tmp_path, confirmed, toasts):
    confirmed.save(tmp_path)
    report = run_once(home=tmp_path, read_snapshot=lambda: parse_snapshot(fixture_json("snapshot_vpn.json")),
                      read_neighbors=forbidden_neighbors, toast_sender=sender_into(toasts))
    assert report.status == "skipped" and any("VPN" in r for r in report.reasons)
    assert toasts == []


def test_passive_run_on_confirmed_network(tmp_path, confirmed, toasts):
    confirmed.save(tmp_path)
    report = run_once(home=tmp_path, read_snapshot=lambda: parse_snapshot(fixture_json("snapshot_home.json")),
                      read_neighbors=neighbors_fixture, toast_sender=sender_into(toasts))
    assert report.status == "ok", report.reasons
    assert report.result.device_count == 4
    inv = Inventory(db_path(tmp_path))
    assert {d["mac"] for d in inv.devices()} == {"a4:91:b1:12:34:56", "3c:7c:3f:1a:2b:4d", "f4:f5:d8:aa:bb:01", "da:a1:19:5e:22:07"}
    inv.close()
    # 3 vendor-MAC devices + 1 private summary, capped at 3 toasts, the last one a roll-up
    assert len(toasts) == 3 and toasts[-1][0] == "More network alerts"
    assert all(url == "http://127.0.0.1:8765/" for _, _, url in toasts)
    # second identical run: nothing new, nothing shown
    toasts.clear()
    report = run_once(home=tmp_path, read_snapshot=lambda: parse_snapshot(fixture_json("snapshot_home.json")),
                      read_neighbors=neighbors_fixture, toast_sender=sender_into(toasts))
    assert report.result.new_devices == [] and toasts == []


def test_active_request_without_opt_in_stays_passive(tmp_path, confirmed, toasts):
    confirmed.allow_active = False
    confirmed.save(tmp_path)
    report = run_once(want_active=True, home=tmp_path, read_snapshot=lambda: parse_snapshot(fixture_json("snapshot_home.json")),
                      read_neighbors=neighbors_fixture, toast_sender=sender_into(toasts))
    assert report.status == "ok"
    assert any("active discovery refused" in n for n in report.notes)
