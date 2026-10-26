"""Shared data types."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Priority when several sources name the same device. DHCP option 12 is what
# the device calls itself; mDNS is close behind; PTR from the router is last
# because many routers synthesise names.
HOSTNAME_PRIORITY = {"dhcp": 4, "mdns": 3, "netbios": 2, "ptr": 1}

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean_name(value: str | None, limit: int = 63) -> str | None:
    """Names come from untrusted packets: strip control characters and cap length."""
    if not value:
        return None
    value = _CONTROL.sub("", value).strip()
    return value[:limit] or None


@dataclass
class Observation:
    """One fact learned about one device during a run."""

    source: str  # arp, sweep, dhcp, mdns, ssdp, netbios, ptr
    mac: str | None = None
    ip: str | None = None
    hostname: str | None = None
    model_hint: str | None = None

    def __post_init__(self) -> None:
        self.hostname = clean_name(self.hostname)
        self.model_hint = clean_name(self.model_hint, 120)
