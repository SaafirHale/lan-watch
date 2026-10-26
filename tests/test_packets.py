import ipaddress

import pytest
from conftest import fixture_bytes, fixture_text

from lanwatch.listen import observations_from_packet
from lanwatch.packets import dhcp, dns, netbios, ssdp

NET = ipaddress.IPv4Network("192.168.50.0/24")


def test_mdns_response_with_compression():
    msg = dns.parse(fixture_bytes("mdns_response.hex"))
    assert msg.is_response and len(msg.records) == 4
    assert dns.mdns_hostnames(msg) == {"192.168.50.31": "Living-Room-TV"}
    assert dns.mdns_services(msg) == ["Living Room TV._googlecast._tcp"]
    srv = next(r for r in msg.records if r.rtype == dns.TYPE_SRV)
    assert srv.data == {"priority": 0, "weight": 0, "port": 8009, "target": "Living-Room-TV.local"}
    txt = next(r for r in msg.records if r.rtype == dns.TYPE_TXT)
    assert txt.data == ["md=Chromecast", "fn=Living Room TV"]


def test_mdns_query_yields_no_hostnames():
    msg = dns.parse(fixture_bytes("mdns_query.hex"))
    assert not msg.is_response and msg.questions == [("_airplay._tcp.local", dns.TYPE_PTR)]
    assert dns.mdns_hostnames(msg) == {}


def test_pointer_loop_is_rejected():
    with pytest.raises(dns.MalformedPacket):
        dns.parse(fixture_bytes("mdns_pointer_loop.hex"))


@pytest.mark.parametrize("cut", [5, 13, 30, 60, 100])
def test_truncated_packets_raise_cleanly(cut):
    data = fixture_bytes("mdns_response.hex")[:cut]
    with pytest.raises(dns.MalformedPacket):
        dns.parse(data)


def test_ptr_query_and_response():
    q = dns.build_ptr_query("192.168.50.31", 0xBEEF)
    assert q[:2] == b"\xbe\xef" and b"\x0231\x0250\x03168\x03192\x07in-addr\x04arpa\x00" in q
    resp = dns.parse(fixture_bytes("ptr_response.hex"))
    assert resp.id == 0xBEEF and dns.ptr_answer(resp) == "living-room-tv.lan"


def test_ssdp_notify():
    ann = ssdp.parse(fixture_text("ssdp_notify.txt").encode())
    assert ann.kind == "NOTIFY" and ann.nts == "ssdp:alive"
    assert ann.server.startswith("Linux/3.8.13+")
    assert ann.location == "http://192.168.50.31:8008/ssdp/device-desc.xml"
    assert ssdp.parse(b"GET / HTTP/1.1\r\n\r\n") is None


def test_dhcp_request():
    info = dhcp.parse(fixture_bytes("dhcp_request.hex"))
    assert info.op == 1 and info.message_type == "REQUEST"
    assert info.mac == "da:a1:19:5e:22:07"
    assert info.hostname == "Pixel-8" and info.requested_ip == "192.168.50.44"
    assert info.vendor_class == "android-dhcp-14" and info.client_ip is None
    assert dhcp.parse(b"\x01" * 100) is None


def test_netbios_name_encoding_roundtrip():
    enc = netbios.encode_name("DESKTOP-7Q2LM", 0x00)
    assert len(enc) == 34
    assert netbios.decode_name(enc[1:33]) == ("DESKTOP-7Q2LM", 0x00)
    assert netbios.encode_name("*")[1:33] == b"CK" + b"AA" * 15


def test_netbios_registration():
    reg = netbios.parse_registration(fixture_bytes("netbios_registration.hex"))
    assert (reg.name, reg.suffix, reg.ip, reg.is_group) == ("DESKTOP-7Q2LM", 0, "192.168.50.20", False)


def test_netbios_node_status():
    status = netbios.parse_node_status(fixture_bytes("netbios_nodestatus.hex"))
    assert status.workstation_name == "DESKTOP-7Q2LM"
    assert ("WORKGROUP", 0, True) in status.names
    assert status.mac == "3c:7c:3f:1a:2b:4d"
    query = netbios.build_node_status_query(0x1234)
    assert query[:2] == b"\x12\x34" and query.endswith(b"\x00\x21\x00\x01")


def test_listener_turns_packets_into_observations():
    obs = observations_from_packet("mdns", fixture_bytes("mdns_response.hex"), "192.168.50.31", NET)
    assert [(o.source, o.ip, o.hostname) for o in obs] == [("mdns", "192.168.50.31", "Living-Room-TV")]
    obs = observations_from_packet("dhcp", fixture_bytes("dhcp_request.hex"), "0.0.0.0", NET)
    assert [(o.mac, o.ip, o.hostname, o.model_hint) for o in obs] == [("da:a1:19:5e:22:07", "192.168.50.44", "Pixel-8", "android-dhcp-14")]
    obs = observations_from_packet("ssdp", fixture_text("ssdp_notify.txt").encode(), "192.168.50.31", NET)
    assert obs[0].model_hint.startswith("Linux/3.8.13+")
    obs = observations_from_packet("netbios", fixture_bytes("netbios_registration.hex"), "192.168.50.20", NET)
    assert obs[0].hostname == "DESKTOP-7Q2LM"


def test_listener_ignores_offnet_and_garbage():
    other = ipaddress.IPv4Network("10.1.1.0/24")
    assert observations_from_packet("mdns", fixture_bytes("mdns_response.hex"), "192.168.50.31", other) == []
    assert observations_from_packet("mdns", fixture_bytes("mdns_pointer_loop.hex"), "192.168.50.9", NET) == []
    assert observations_from_packet("netbios", b"\x00" * 7, "192.168.50.9", NET) == []


def test_hostile_names_are_cleaned():
    from lanwatch.models import Observation

    o = Observation("mdns", ip="192.168.50.9", hostname="evil\x1b[31m<script>" + "x" * 200)
    assert "\x1b" not in o.hostname and len(o.hostname) == 63
