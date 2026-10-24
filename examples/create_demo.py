#!/usr/bin/env python3
"""Create the small, synthetic PCAP used by the README example."""

from pathlib import Path
import socket
import struct


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x42, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def tls_client_hello(host: str) -> bytes:
    name = host.encode("ascii")
    sni = struct.pack("!H", 3 + len(name)) + b"\0" + struct.pack("!H", len(name)) + name
    sni_ext = struct.pack("!HH", 0, len(sni)) + sni
    alpn_body = b"\0\3\2h2"
    alpn_ext = struct.pack("!HH", 16, len(alpn_body)) + alpn_body
    extensions = sni_ext + alpn_ext
    body = b"\x03\x03" + bytes(range(32)) + b"\0" + b"\0\2\x13\x01" + b"\x01\0"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def ethernet_ipv4(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    ip = b"\x45\0" + struct.pack("!H", 20 + len(payload)) + b"\0\0\0\0\x40" + bytes((protocol,))
    ip += b"\0\0" + socket.inet_aton(src) + socket.inet_aton(dst)
    return b"\x02\0\0\0\0\2\x02\0\0\0\0\1\x08\0" + ip + payload


def udp(src: int, dst: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src, dst, 8 + len(payload), 0) + payload


def tcp(src: int, dst: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack("!HHII", src, dst, seq, 0) + b"\x50\x18" + struct.pack("!HHH", 4096, 0, 0)
    return header + payload


def pcap_record(sec: int, packet: bytes) -> bytes:
    return struct.pack("<IIII", sec, 0, len(packet), len(packet)) + packet


def main() -> None:
    packets = [
        ethernet_ipv4("192.0.2.10", "192.0.2.53", 17, udp(53000, 53, dns_query("updates.example.net"))),
        ethernet_ipv4("192.0.2.10", "198.51.100.20", 6, tcp(51000, 443, 1000, tls_client_hello("updates.example.net"))),
    ]
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    target = Path(__file__).with_name("demo.pcap")
    target.write_bytes(header + pcap_record(1_800_000_000, packets[0]) + pcap_record(1_800_000_001, packets[1]))
    print(f"Wrote {target} ({target.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
