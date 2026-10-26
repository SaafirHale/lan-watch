"""Light active discovery. Every function takes an ActiveAuthorization and
checks each target with it before sending anything.

- ARP sweep through Windows' own SendARP (iphlpapi.dll): no Npcap, no admin,
  one ARP request per address, rate-limited.
- NetBIOS node-status and DNS PTR queries: one small UDP packet per device
  already discovered (PTR goes only to the confirmed gateway).
- Opt-in TCP connect check of 20 common ports on ONE chosen device.
"""

from __future__ import annotations

import ctypes
import ipaddress
import random
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .mac import normalize_mac
from .models import Observation
from .packets import dns, netbios
from .safety import ActiveAuthorization

# nmap's top-20 TCP ports by frequency (nmap-services)
TOP20_TCP = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080)

DEFAULT_RATE_PER_SEC = 10.0
DEFAULT_WORKERS = 8


class RateLimiter:
    """At most ``rate`` acquisitions per second across threads."""

    def __init__(self, rate: float, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.interval = 1.0 / rate
        self._next = 0.0
        self._lock = threading.Lock()
        self._clock, self._sleep = clock, sleep

    def acquire(self) -> None:
        with self._lock:
            now = self._clock()
            wait = self._next - now
            self._next = max(now, self._next) + self.interval
        if wait > 0:
            self._sleep(wait)


def _send_arp(ip: ipaddress.IPv4Address) -> str | None:
    iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
    dest = struct.unpack("<I", ip.packed)[0]  # IPAddr is network byte order in memory
    mac_buf = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(8)
    rc = iphlpapi.SendARP(ctypes.c_ulong(dest), ctypes.c_ulong(0), ctypes.byref(mac_buf), ctypes.byref(length))
    if rc != 0 or length.value < 6:
        return None
    return normalize_mac(bytes(mac_buf[:6]))


def arp_sweep(
    auth: ActiveAuthorization,
    rate_per_sec: float = DEFAULT_RATE_PER_SEC,
    workers: int = DEFAULT_WORKERS,
    resolver: Callable[[ipaddress.IPv4Address], str | None] = _send_arp,
) -> list[Observation]:
    limiter = RateLimiter(rate_per_sec)
    targets = auth.hosts()

    def probe(ip: ipaddress.IPv4Address) -> Observation | None:
        auth.check_target(ip)
        limiter.acquire()
        mac = resolver(ip)
        return Observation("sweep", mac=mac, ip=str(ip)) if mac else None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [o for o in pool.map(probe, targets) if o]


def netbios_names(auth: ActiveAuthorization, ips: list[str], timeout: float = 1.0, rate_per_sec: float = 5.0) -> list[Observation]:
    out = []
    limiter = RateLimiter(rate_per_sec)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for ip in ips:
            target = auth.check_target(ip)
            limiter.acquire()
            tid = random.randint(0, 0xFFFF)
            try:
                s.sendto(netbios.build_node_status_query(tid), (str(target), 137))
                payload, (src, _) = s.recvfrom(2048)
            except OSError:
                continue
            if src != str(target):
                continue
            try:
                status = netbios.parse_node_status(payload)
            except Exception:
                continue
            if status and status.workstation_name:
                out.append(Observation("netbios", mac=status.mac, ip=str(target), hostname=status.workstation_name))
    return out


def ptr_names(auth: ActiveAuthorization, gateway_ip: str, ips: list[str], timeout: float = 1.0, rate_per_sec: float = 10.0) -> list[Observation]:
    """Ask the home router (and only the router) for reverse names it learned via DHCP."""
    resolver = str(auth.check_target(gateway_ip))
    out = []
    limiter = RateLimiter(rate_per_sec)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for ip in ips:
            auth.check_target(ip)
            limiter.acquire()
            qid = random.randint(0, 0xFFFF)
            try:
                s.sendto(dns.build_ptr_query(ip, qid), (resolver, 53))
                payload, (src, _) = s.recvfrom(2048)
                msg = dns.parse(payload)
            except (OSError, dns.MalformedPacket):
                continue
            if src != resolver or msg.id != qid:
                continue
            name = dns.ptr_answer(msg)
            if name:
                out.append(Observation("ptr", ip=ip, hostname=name.split(".")[0]))
    return out


def tcp_top20(auth: ActiveAuthorization, ip: str, timeout: float = 1.0, delay: float = 0.25) -> dict[int, bool]:
    """TCP connect check, one port at a time. Returns {port: open}."""
    target = str(auth.check_target(ip))
    results = {}
    for port in TOP20_TCP:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            results[port] = s.connect_ex((target, port)) == 0
        time.sleep(delay)
    return results
