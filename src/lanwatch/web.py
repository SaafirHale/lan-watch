"""Local dashboard on 127.0.0.1 only (stdlib http.server, no framework).

Hardening, because a page on any website can try to reach localhost:
- the socket binds to 127.0.0.1; there is no option to change that
- the Host header must be 127.0.0.1:<port> or localhost:<port> (stops DNS rebinding)
- state-changing requests need a per-process CSRF token, JSON content type
  and, when the browser sends one, a matching Origin
- strict Content-Security-Policy; the page renders packet-derived names with
  textContent only
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import TAGLINE, __version__
from .db import Inventory
from .mac import mask_mac, normalize_mac
from .safety import ConfirmedNetwork

BIND_HOST = "127.0.0.1"
STATIC_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
_DEVICE_ROUTE = re.compile(r"^/api/devices/(?P<mac>[0-9a-fA-F:\-]{12,17})/(?P<action>known|label)$")


def mask_ip(ip: str | None) -> str | None:
    if not ip:
        return ip
    if "/" in ip:
        net = ipaddress.IPv4Network(ip, strict=False)
        return f"•.•.•.0/{net.prefixlen}"
    return "•.•.•." + ip.rsplit(".", 1)[-1]


def mask_text(value: str | None) -> str | None:
    if not value:
        return value
    return value[:3] + "•••"


def build_state(inv: Inventory, confirmed: ConfirmedNetwork | None, privacy: bool) -> dict:
    mip = mask_ip if privacy else (lambda v: v)
    mmac = mask_mac if privacy else (lambda v: v)
    mtxt = mask_text if privacy else (lambda v: v)

    devices = []
    for d in inv.devices():
        devices.append({
            # Privacy view is a read-only presentation mode: no real MAC anywhere in the payload.
            "id": None if privacy else d["mac"],
            "mac": mmac(d["mac"]),
            "ip": mip(d["last_ip"]),
            "vendor": d["vendor"],
            "hostname": mtxt(d["hostname"]),
            "hostname_source": d["hostname_source"],
            "model_hint": d["model_hint"],
            "label": mtxt(d["label"]),
            "known": bool(d["known"]),
            "randomized": bool(d["randomized"]),
            "first_seen": d["first_seen"],
            "last_seen": d["last_seen"],
            "sources": (d["last_sources"] or "").split(",") if d["last_sources"] else [],
            "ip_history": [{"ip": mip(h["ip"]), "first_seen": h["first_seen"], "last_seen": h["last_seen"]} for h in inv.ip_history(d["mac"])],
        })
    events = [{
        "id": e["id"], "ts": e["ts"], "kind": e["kind"], "severity": e["severity"],
        "mac": mmac(e["mac"]) if e["mac"] else None, "ip": mip(e["ip"]),
        "message": _mask_message(e["message"], e["mac"], e["ip"], privacy, inv),
    } for e in inv.events(150)]
    runs = [dict(r) for r in inv.runs(30)]
    if privacy:
        for r in runs:
            r["note"] = None
    network = None
    if confirmed:
        network = {
            "profile": "•••••" if privacy and confirmed.profile_name else confirmed.profile_name,  # the Wi-Fi name is an identifier
            "cidr": mip(confirmed.cidr),
            "gateway": mip(confirmed.gateway_ip),
            "interface": confirmed.interface_alias,
            "allow_active": confirmed.allow_active,
            "confirmed_at": confirmed.confirmed_at,
        }
    return {"version": __version__, "tagline": TAGLINE, "privacy": privacy, "network": network, "devices": devices, "events": events, "runs": runs}


_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_MAC_RE = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b")


def _mask_message(message: str, mac: str | None, ip: str | None, privacy: bool, inv: Inventory) -> str:
    if not privacy:
        return message
    message = _IP_RE.sub(lambda m: mask_ip(m.group(0)) or "", message)
    message = _MAC_RE.sub(lambda m: mask_mac(m.group(0)), message)
    # hostnames and labels quoted in messages
    for d in inv.devices():
        for value in (d["hostname"], d["label"]):
            if value and value in message:
                message = message.replace(value, mask_text(value) or "")
    return message


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, db_file: Path, home: Path) -> None:
        self.port = port
        self.db_file = db_file
        self.home = home
        self.csrf_token = secrets.token_urlsafe(32)
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        super().__init__((BIND_HOST, port), Handler)


class Handler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "lan-watch"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        pass

    # --- helpers --------------------------------------------------------
    def _headers(self, status: int, ctype: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self._headers(status, ctype, len(body))
        self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _inventory(self) -> Inventory:
        return Inventory(self.server.db_file)

    # --- GET ------------------------------------------------------------
    def do_GET(self) -> None:
        if not self._host_ok():
            return self._send(HTTPStatus.MISDIRECTED_REQUEST, b"bad host", "text/plain")
        url = urlsplit(self.path)
        if url.path in ("/", "/index.html"):
            html = resources.files("lanwatch").joinpath("static", "index.html").read_text(encoding="utf-8")
            html = html.replace("{{CSRF}}", self.server.csrf_token).replace("{{VERSION}}", __version__)
            return self._send(HTTPStatus.OK, html.encode("utf-8"), "text/html; charset=utf-8")
        if url.path.startswith("/static/"):
            name = url.path.removeprefix("/static/")
            suffix = Path(name).suffix
            if "/" in name or "\\" in name or ".." in name or suffix not in STATIC_TYPES:
                return self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            res = resources.files("lanwatch").joinpath("static", name)
            if not res.is_file():
                return self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            return self._send(HTTPStatus.OK, res.read_bytes(), STATIC_TYPES[suffix])
        if url.path == "/api/state":
            privacy = parse_qs(url.query).get("privacy", ["0"])[0] == "1"
            inv = self._inventory()
            try:
                state = build_state(inv, ConfirmedNetwork.load(self.server.home), privacy)
            finally:
                inv.close()
            return self._json(HTTPStatus.OK, state)
        self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")

    # --- POST -----------------------------------------------------------
    def do_POST(self) -> None:
        if not self._host_ok():
            return self._send(HTTPStatus.MISDIRECTED_REQUEST, b"bad host", "text/plain")
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc not in self.server.allowed_hosts:
            return self._json(HTTPStatus.FORBIDDEN, {"error": "cross-origin request refused"})
        token = self.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(token, self.server.csrf_token):
            return self._json(HTTPStatus.FORBIDDEN, {"error": "missing or wrong CSRF token"})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "JSON only"})
        m = _DEVICE_ROUTE.match(urlsplit(self.path).path)
        mac = normalize_mac(m.group("mac")) if m else None
        if not m or not mac:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "unknown route"})
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
        inv = self._inventory()
        try:
            if m.group("action") == "known":
                ok = inv.set_known(mac, bool(body.get("known", True)))
            else:
                label = body.get("label")
                ok = inv.set_label(mac, label if isinstance(label, str) else None)
        finally:
            inv.close()
        if not ok:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "no such device"})
        self._json(HTTPStatus.OK, {"ok": True})


def serve(port: int, db_file: Path, home: Path) -> DashboardServer:
    return DashboardServer(port, db_file, home)
