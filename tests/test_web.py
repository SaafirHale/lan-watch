import http.client
import json
import threading

import pytest

from lanwatch.db import Inventory
from lanwatch.runner import db_path
from lanwatch.web import DashboardServer, mask_ip


@pytest.fixture
def server(tmp_path, confirmed):
    confirmed.save(tmp_path)
    inv = Inventory(db_path(tmp_path))
    run = inv.start_run("passive", "2026-10-20T10:00:00+00:00")
    inv.insert_device("3c:7c:3f:1a:2b:4d", "2026-10-20T10:00:00+00:00", last_ip="192.168.50.20", hostname="DESKTOP-7Q2LM", vendor="Example PC Maker")
    inv.touch_ip("3c:7c:3f:1a:2b:4d", "192.168.50.20", "2026-10-20T10:00:00+00:00")
    inv.add_event("2026-10-20T10:00:00+00:00", run, "new_device", "warning", "New device joined: DESKTOP-7Q2LM at 192.168.50.20", mac="3c:7c:3f:1a:2b:4d", ip="192.168.50.20")
    inv.finish_run(run, "ok", 1, 1)
    inv.close()
    srv = DashboardServer(0, db_path(tmp_path), tmp_path)
    port = srv.server_address[1]
    srv.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, port
    srv.shutdown()
    srv.server_close()


def request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Host": f"127.0.0.1:{port}"}
    hdrs.update(headers or {})
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp, data


def test_binds_loopback_only(server):
    srv, _ = server
    assert srv.server_address[0] == "127.0.0.1"


def test_index_has_token_and_security_headers(server):
    srv, port = server
    resp, body = request(port, "GET", "/")
    assert resp.status == 200 and srv.csrf_token.encode() in body
    assert "script-src 'self'" in resp.getheader("Content-Security-Policy")
    assert resp.getheader("X-Frame-Options") == "DENY"


def test_dns_rebinding_host_is_refused(server):
    _, port = server
    resp, _ = request(port, "GET", "/api/state", headers={"Host": "attacker.example:80"})
    assert resp.status == 421


def test_state_and_privacy_masking(server):
    _, port = server
    _, body = request(port, "GET", "/api/state")
    state = json.loads(body)
    assert state["devices"][0]["mac"] == "3c:7c:3f:1a:2b:4d" and state["devices"][0]["id"]
    _, body = request(port, "GET", "/api/state?privacy=1")
    text = body.decode()
    assert "3c:7c:3f:1a:2b:4d" not in text and "192.168.50.20" not in text and "DESKTOP-7Q2LM" not in text
    assert "HomeNet" not in text and "192.168.50.0" not in text
    state = json.loads(body)
    assert state["devices"][0]["mac"] == "3c:7c:3f:••:••:••"
    assert state["devices"][0]["id"] is None
    assert state["events"][0]["message"] == "New device joined: DES••• at •.•.•.20"


def test_mark_known_requires_csrf_and_json(server):
    srv, port = server
    path = "/api/devices/3c:7c:3f:1a:2b:4d/known"
    resp, _ = request(port, "POST", path, json.dumps({"known": True}), {"Content-Type": "application/json"})
    assert resp.status == 403
    resp, _ = request(port, "POST", path, "known=1", {"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": srv.csrf_token})
    assert resp.status == 415
    resp, _ = request(port, "POST", path, json.dumps({"known": True}),
                      {"Content-Type": "application/json", "X-CSRF-Token": srv.csrf_token, "Origin": "http://evil.example"})
    assert resp.status == 403
    resp, _ = request(port, "POST", path, json.dumps({"known": True}),
                      {"Content-Type": "application/json", "X-CSRF-Token": srv.csrf_token, "Origin": f"http://127.0.0.1:{port}"})
    assert resp.status == 200
    _, body = request(port, "GET", "/api/state")
    assert json.loads(body)["devices"][0]["known"] is True


def test_label_and_unknown_device(server):
    srv, port = server
    hdrs = {"Content-Type": "application/json", "X-CSRF-Token": srv.csrf_token}
    resp, _ = request(port, "POST", "/api/devices/3c:7c:3f:1a:2b:4d/label", json.dumps({"label": "Office PC"}), hdrs)
    assert resp.status == 200
    resp, _ = request(port, "POST", "/api/devices/00:00:00:00:00:99/label", json.dumps({"label": "x"}), hdrs)
    assert resp.status == 404


def test_static_path_traversal_blocked(server):
    _, port = server
    for path in ("/static/../web.py", "/static/..%2Fweb.py", "/static/app.py", "/static/nope.js"):
        resp, _ = request(port, "GET", path)
        assert resp.status == 404, path
    resp, _ = request(port, "GET", "/static/app.js")
    assert resp.status == 200


def test_mask_ip():
    assert mask_ip("192.168.50.20") == "•.•.•.20"
    assert mask_ip("192.168.50.0/24") == "•.•.•.0/24"
