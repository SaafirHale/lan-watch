"""SSDP (UPnP discovery) announcement parser. Text over UDP 1900."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SsdpAnnouncement:
    kind: str  # NOTIFY, M-SEARCH or RESPONSE
    server: str | None
    location: str | None
    nt: str | None
    usn: str | None
    nts: str | None


def parse(buf: bytes) -> SsdpAnnouncement | None:
    try:
        text = buf.decode("utf-8", "replace")
    except Exception:
        return None
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines:
        return None
    start = lines[0].strip().upper()
    if start.startswith("NOTIFY "):
        kind = "NOTIFY"
    elif start.startswith("M-SEARCH "):
        kind = "M-SEARCH"
    elif start.startswith("HTTP/1.1 200"):
        kind = "RESPONSE"
    else:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().upper()] = value.strip()
    return SsdpAnnouncement(
        kind=kind,
        server=headers.get("SERVER"),
        location=headers.get("LOCATION"),
        nt=headers.get("NT") or headers.get("ST"),
        usn=headers.get("USN"),
        nts=headers.get("NTS"),
    )
