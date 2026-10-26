"""Offline vendor lookup from the IEEE registration-authority CSV files.

``lanwatch update-oui`` downloads oui.csv (MA-L, 24-bit), mam.csv (MA-M,
28-bit) and oui36.csv (MA-S, 36-bit) into the data directory. Lookups never
touch the network.
"""

from __future__ import annotations

import csv
import ssl
import urllib.request
from pathlib import Path

from .mac import is_locally_administered, oui_key

IEEE_SOURCES = {
    "oui.csv": "https://standards-oui.ieee.org/oui/oui.csv",
    "mam.csv": "https://standards-oui.ieee.org/oui28/mam.csv",
    "oui36.csv": "https://standards-oui.ieee.org/oui36/oui36.csv",
}


class OuiDatabase:
    def __init__(self) -> None:
        # prefix length in hex digits -> {prefix: organisation}
        self._tables: dict[int, dict[str, str]] = {}

    def __len__(self) -> int:
        return sum(len(t) for t in self._tables.values())

    def load_csv(self, path: Path) -> int:
        count = 0
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                prefix = (row.get("Assignment") or "").strip().upper()
                org = (row.get("Organization Name") or "").strip()
                if not prefix or not org:
                    continue
                self._tables.setdefault(len(prefix), {})[prefix] = org
                count += 1
        return count

    def lookup(self, mac: str) -> str | None:
        # A locally administered address is not assigned by the IEEE, so any
        # "match" would be a coincidence. Say so instead of guessing.
        if is_locally_administered(mac):
            return None
        for digits in sorted(self._tables, reverse=True):  # longest prefix first
            hit = self._tables[digits].get(oui_key(mac, digits))
            if hit:
                return hit
        return None


def load_from_dir(data_dir: Path) -> OuiDatabase:
    db = OuiDatabase()
    for name in IEEE_SOURCES:
        path = data_dir / name
        if path.exists():
            db.load_csv(path)
    return db


def download(data_dir: Path, timeout: float = 60.0) -> dict[str, int]:
    """Fetch the IEEE CSVs. Uses the Windows certificate store via ssl defaults."""
    data_dir.mkdir(parents=True, exist_ok=True)
    ctx = ssl.create_default_context()
    sizes: dict[str, int] = {}
    for name, url in IEEE_SOURCES.items():
        req = urllib.request.Request(url, headers={"User-Agent": "lan-watch/0.1 (offline OUI cache)"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
        if not body.startswith(b"Registry,"):
            raise ValueError(f"{url} did not return the expected CSV header")
        tmp = data_dir / (name + ".part")
        tmp.write_bytes(body)
        tmp.replace(data_dir / name)
        sizes[name] = len(body)
    return sizes
