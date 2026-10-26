# Builds byte-exact wire-format fixtures by hand with struct (independent of the parsers under test).
import pathlib
import struct
import sys

out = pathlib.Path(sys.argv[1])


def ip(s):
    return bytes(int(x) for x in s.split("."))


def labels(*parts):
    return b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"


# --- mDNS response: PTR, SRV, TXT, A with name compression
pkt = bytearray(struct.pack("!6H", 0, 0x8400, 0, 4, 0, 0))
off_service = len(pkt)
pkt += labels("_googlecast", "_tcp", "local")
off_local = off_service + 1 + len("_googlecast") + 1 + len("_tcp")
pkt += struct.pack("!HHIH", 12, 1, 120, 0)
rd = len(pkt)
off_instance = len(pkt)
pkt += bytes([14]) + b"Living Room TV" + struct.pack("!H", 0xC000 | off_service)
struct.pack_into("!H", pkt, rd - 2, len(pkt) - rd)
pkt += struct.pack("!H", 0xC000 | off_instance) + struct.pack("!HHIH", 33, 0x8001, 120, 0)
rd = len(pkt)
pkt += struct.pack("!HHH", 0, 0, 8009)
off_host = len(pkt)
pkt += bytes([14]) + b"Living-Room-TV" + struct.pack("!H", 0xC000 | off_local)
struct.pack_into("!H", pkt, rd - 2, len(pkt) - rd)
pkt += struct.pack("!H", 0xC000 | off_instance) + struct.pack("!HHIH", 16, 0x8001, 4500, 0)
rd = len(pkt)
for t in (b"md=Chromecast", b"fn=Living Room TV"):
    pkt += bytes([len(t)]) + t
struct.pack_into("!H", pkt, rd - 2, len(pkt) - rd)
pkt += struct.pack("!H", 0xC000 | off_host) + struct.pack("!HHIH", 1, 0x8001, 120, 4) + ip("192.168.50.31")
(out / "mdns_response.hex").write_text(bytes(pkt).hex())

# --- mDNS query
q = struct.pack("!6H", 0, 0, 1, 0, 0, 0) + labels("_airplay", "_tcp", "local") + struct.pack("!HH", 12, 1)
(out / "mdns_query.hex").write_text(q.hex())

# --- DHCPREQUEST from a locally administered MAC
mac = bytes.fromhex("daa1195e2207")
b = bytearray(236)
b[0], b[1], b[2] = 1, 1, 6
struct.pack_into("!I", b, 4, 0x3903F326)
b[28:34] = mac
b += b"\x63\x82\x53\x63"
b += bytes([53, 1, 3])
b += bytes([61, 7, 1]) + mac
b += bytes([50, 4]) + ip("192.168.50.44")
b += bytes([12, 7]) + b"Pixel-8"
b += bytes([60, 15]) + b"android-dhcp-14"
b += bytes([55, 4, 1, 3, 6, 15])
b += bytes([255]) + b"\x00" * 8
(out / "dhcp_request.hex").write_text(bytes(b).hex())


def nb_encode(name, suffix):
    raw = name.upper().encode().ljust(15, b" ") + bytes([suffix])
    return bytes([32]) + bytes(c for x in raw for c in (0x41 + (x >> 4), 0x41 + (x & 15))) + b"\x00"


# --- NetBIOS name registration broadcast
reg = struct.pack("!6H", 0x80F1, 0x2910, 1, 0, 0, 1)
reg += nb_encode("DESKTOP-7Q2LM", 0x00) + struct.pack("!HH", 0x20, 1)
reg += struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 0x20, 1, 300000, 6) + struct.pack("!H", 0) + ip("192.168.50.20")
(out / "netbios_registration.hex").write_text(reg.hex())

# --- NetBIOS node status response
ns = struct.pack("!6H", 0x1234, 0x8400, 0, 1, 0, 0)
ns += bytes([32]) + b"CK" + b"AA" * 15 + b"\x00"
names = [("DESKTOP-7Q2LM", 0x00, 0x0400), ("WORKGROUP", 0x00, 0x8400), ("DESKTOP-7Q2LM", 0x20, 0x0400)]
rdata = bytes([len(names)])
for n, suf, fl in names:
    rdata += n.encode().ljust(15, b" ") + bytes([suf]) + struct.pack("!H", fl)
rdata += bytes.fromhex("3c7c3f1a2b4d") + b"\x00" * 40
ns += struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata
(out / "netbios_nodestatus.hex").write_text(ns.hex())

# --- DNS PTR response from the router
qn = labels("31", "50", "168", "192", "in-addr", "arpa")
pr = struct.pack("!6H", 0xBEEF, 0x8180, 1, 1, 0, 0) + qn + struct.pack("!HH", 12, 1)
target = labels("living-room-tv", "lan")
pr += struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 12, 1, 0, len(target)) + target
(out / "ptr_response.hex").write_text(pr.hex())

# --- malformed: compression pointer pointing at itself
bad = struct.pack("!6H", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c"
(out / "mdns_pointer_loop.hex").write_text(bad.hex())
print("ok", sorted(p.name for p in out.iterdir()))
