import ipaddress
import xml.dom.minidom

import pytest

from lanwatch import active
from lanwatch.detect import Alert
from lanwatch.notify import MAX_TOASTS_PER_RUN, plan_toasts, toast_xml
from lanwatch.safety import SafetyError, authorize_active


def test_rate_limiter_spaces_calls():
    now = [0.0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    rl = active.RateLimiter(10.0, clock=lambda: now[0], sleep=sleep)
    for _ in range(5):
        rl.acquire()
    assert now[0] == pytest.approx(0.4)  # first is free, then 100 ms apart


def test_sweep_only_touches_confirmed_hosts(home_snapshot, confirmed):
    auth = authorize_active(home_snapshot, confirmed, "a4:91:b1:12:34:56")
    asked = []

    def fake_resolver(ip):
        asked.append(ip)
        return "3c:7c:3f:1a:2b:4d" if str(ip) == "192.168.50.20" else None

    obs = active.arp_sweep(auth, rate_per_sec=1e6, resolver=fake_resolver)
    assert [(o.source, o.ip, o.mac) for o in obs] == [("sweep", "192.168.50.20", "3c:7c:3f:1a:2b:4d")]
    assert len(asked) == 253
    net = ipaddress.IPv4Network("192.168.50.0/24")
    assert all(ip in net for ip in asked)


def test_port_check_refuses_outside_targets(home_snapshot, confirmed):
    auth = authorize_active(home_snapshot, confirmed, "a4:91:b1:12:34:56")
    for target in ("8.8.8.8", "192.168.51.1", "10.0.0.1"):
        with pytest.raises(SafetyError):
            active.tcp_top20(auth, target)
    with pytest.raises(SafetyError):
        active.ptr_names(auth, "1.1.1.1", ["192.168.50.20"])
    assert len(active.TOP20_TCP) == 20


def test_toast_xml_escapes_packet_text():
    xml_text = toast_xml('New <device> "x"', "hostname & </text><script>", "http://127.0.0.1:8765/?a=1&b=2")
    doc = xml.dom.minidom.parseString(xml_text)  # still well-formed
    texts = [t.firstChild.data for t in doc.getElementsByTagName("text")]
    assert texts[0] == 'New <device> "x"' and texts[1] == "hostname & </text><script>"
    assert doc.documentElement.getAttribute("launch") == "http://127.0.0.1:8765/?a=1&b=2"


def test_plan_toasts_orders_and_caps():
    alerts = [Alert("info", "i", "", "x"), Alert("critical", "c", "", "x"), Alert("warning", "w1", "", "x"),
              Alert("warning", "w2", "", "x"), Alert("warning", "w3", "", "x")]
    plan = plan_toasts(alerts)
    assert len(plan) == MAX_TOASTS_PER_RUN
    assert plan[0][0] == "c" and plan[1][0] == "w1"
    assert plan[-1][0] == "More network alerts" and "3 more" in plan[-1][1]
    assert [t for t, _ in plan_toasts(alerts[:2])] == ["c", "i"]
