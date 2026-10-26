import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_bytes(name: str) -> bytes:
    return bytes.fromhex((FIXTURES / name).read_text().strip())


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def fixture_json(name: str):
    return json.loads(fixture_text(name))


@pytest.fixture
def home_snapshot():
    from lanwatch.netinfo import parse_snapshot

    return parse_snapshot(fixture_json("snapshot_home.json"))


@pytest.fixture
def vpn_snapshot():
    from lanwatch.netinfo import parse_snapshot

    return parse_snapshot(fixture_json("snapshot_vpn.json"))


@pytest.fixture
def confirmed(home_snapshot):
    from lanwatch.safety import build_confirmation

    return build_confirmation(home_snapshot, "a4:91:b1:12:34:56", "192.168.50.0/24", allow_active=True)
