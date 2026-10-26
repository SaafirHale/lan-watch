"""MAC address helpers: normalisation, the locally-administered bit, masking."""

from __future__ import annotations

import re

_SEPARATORS = re.compile(r"[\s:\-.]")
_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str | bytes | None) -> str | None:
    """Return ``aa:bb:cc:dd:ee:ff`` or None if ``value`` is not a 48-bit MAC.

    Accepts the Windows form (``A4-91-B1-12-34-56``), colon form, Cisco dotted
    form (``a491.b112.3456``) and raw 6-byte values from packets.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 6:
            return None
        return ":".join(f"{b:02x}" for b in value)
    raw = _SEPARATORS.sub("", value).lower()
    if not _HEX12.match(raw):
        return None
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def first_octet(mac: str) -> int:
    return int(mac[0:2], 16)


def is_multicast(mac: str) -> bool:
    """I/G bit: least-significant bit of the first octet."""
    return bool(first_octet(mac) & 0x01)


def is_locally_administered(mac: str) -> bool:
    """U/L bit: second-least-significant bit of the first octet.

    Phones and laptops set this bit when they use a private (randomised)
    Wi-Fi address, so the first octet ends in 2, 6, A or E.
    """
    return bool(first_octet(mac) & 0x02)


def is_usable_unicast(mac: str | None) -> bool:
    """True for a real station address: not multicast, broadcast or all-zero."""
    if not mac:
        return False
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    return not is_multicast(mac)


def oui_key(mac: str, hex_digits: int = 6) -> str:
    """Upper-case prefix in IEEE CSV form, e.g. ``A491B1`` for 6 digits."""
    return mac.replace(":", "")[:hex_digits].upper()


def mask_mac(mac: str) -> str:
    """Keep the vendor half, hide the device-specific half."""
    return mac[:8] + ":••:••:••"
