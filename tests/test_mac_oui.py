from conftest import FIXTURES

from lanwatch.mac import is_locally_administered, is_multicast, is_usable_unicast, mask_mac, normalize_mac, oui_key
from lanwatch.oui import OuiDatabase


def test_normalize_accepts_common_forms():
    assert normalize_mac("A4-91-B1-12-34-56") == "a4:91:b1:12:34:56"
    assert normalize_mac("a4:91:b1:12:34:56") == "a4:91:b1:12:34:56"
    assert normalize_mac("a491.b112.3456") == "a4:91:b1:12:34:56"
    assert normalize_mac(bytes.fromhex("a491b1123456")) == "a4:91:b1:12:34:56"
    assert normalize_mac("not-a-mac") is None
    assert normalize_mac("") is None
    assert normalize_mac(b"\x00" * 5) is None


def test_locally_administered_bit():
    # second hex digit 2, 6, A, E => randomised / private address
    for first in ("02", "06", "0a", "0e", "da", "f6"):
        assert is_locally_administered(f"{first}:00:00:00:00:01"), first
    for first in ("00", "a4", "3c", "f4"):
        assert not is_locally_administered(f"{first}:00:00:00:00:01"), first


def test_unicast_filters():
    assert is_multicast("01:00:5e:00:00:fb")
    assert not is_usable_unicast("ff:ff:ff:ff:ff:ff")
    assert not is_usable_unicast("00:00:00:00:00:00")
    assert not is_usable_unicast("01:00:5e:7f:ff:fa")
    assert is_usable_unicast("a4:91:b1:12:34:56")


def test_mask_keeps_vendor_half():
    assert mask_mac("a4:91:b1:12:34:56") == "a4:91:b1:••:••:••"
    assert oui_key("a4:91:b1:12:34:56") == "A491B1"


def test_oui_longest_prefix_and_laa():
    db = OuiDatabase()
    assert db.load_csv(FIXTURES / "oui_sample.csv") == 6
    assert db.lookup("a4:91:b1:12:34:56") == "Example Router Co"
    assert db.lookup("70:b3:d5:12:3f:00") == "Tiny Sensor Ltd"      # MA-S beats MA-L
    assert db.lookup("70:b3:d5:99:00:00") == "IEEE Registration Authority"
    assert db.lookup("da:a1:19:5e:22:07") is None                    # LAA never gets a vendor
    assert db.lookup("00:11:22:33:44:55") is None
