#!/usr/bin/env python3
"""Writes examples/sample.pcap (no scapy needed): SYN flood, ARP replies,
blacklisted HTTP requests, a SYN-ACK, IPv6 noise and a truncated frame."""
import struct, sys

def eth(ethertype, body):
    return b"\x00" * 6 + b"\x11" * 6 + struct.pack("!H", ethertype) + body

def tcp_frame(src, dst, dport, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", 40000, dport, 0, 0, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     bytes(src), bytes(dst)) + tcp
    return eth(0x0800, ip)

def arp_reply():
    return eth(0x0806, struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + b"\x00" * 20)

frames = []
for i in range(300):                       # SYN flood from 300 spoofed sources
    frames.append(tcp_frame((10, 1, i // 256, i % 256), (10, 0, 0, 1), 80, 0x02))
frames.append(tcp_frame((10, 0, 0, 1), (10, 1, 0, 1), 40000, 0x12))   # SYN-ACK (not counted)
for _ in range(3):
    frames.append(arp_reply())
frames.append(tcp_frame((192, 168, 1, 5), (142, 250, 1, 1), 80, 0x18,
                        b"GET / HTTP/1.1\r\nHost: www.google.co.uk\r\n\r\n"))
frames.append(tcp_frame((192, 168, 1, 5), (31, 13, 1, 1), 80, 0x18,
                        b"GET / HTTP/1.1\r\nhost: WWW.FACEBOOK.COM\r\n\r\n"))
frames.append(tcp_frame((192, 168, 1, 5), (1, 2, 3, 4), 80, 0x18,
                        b"GET / HTTP/1.1\r\nHost: www.google.co.uk.evil.net\r\n\r\n"))  # near miss
frames.append(eth(0x86DD, b"\x00" * 40))   # IPv6, ignored
frames.append(frames[0][:30])              # truncated frame -> malformed

out = sys.argv[1] if len(sys.argv) > 1 else "examples/sample.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, fr in enumerate(frames):
        f.write(struct.pack("<IIII", i, 0, len(fr), len(fr)) + fr)
print(f"wrote {out} ({len(frames)} frames)")
