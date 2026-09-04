"""Data models for the Python DPI implementation.

The structures in this module mirror the active C++ implementation in
``src/dpi_mt.cpp`` and its parser/PCAP headers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes


@dataclass
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_length: int = 0
    payload_data: Optional[bytes] = None


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> "FiveTuple":
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def to_string(self) -> str:
        protocol_name = {
            6: "TCP",
            17: "UDP",
        }.get(self.protocol, "?")
        return (
            f"{ip_to_string(self.src_ip)}:{self.src_port} -> "
            f"{ip_to_string(self.dst_ip)}:{self.dst_port} ({protocol_name})"
        )


class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


@dataclass
class FlowEntry:
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False


@dataclass
class Packet:
    id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int
    payload_offset: int
    payload_length: int


def ip_to_int(ip: str) -> int:
    """Convert dotted IPv4 text using the C++ octet-shift representation."""
    result = 0
    octet = 0
    shift = 0

    for character in ip:
        if character == ".":
            result |= octet << shift
            shift += 8
            octet = 0
        elif "0" <= character <= "9":
            octet = octet * 10 + (ord(character) - ord("0"))

    return result | (octet << shift)


def ip_to_string(value: int) -> str:
    """Format an IPv4 integer using the C++ low-byte-first representation."""
    return ".".join(str((value >> shift) & 0xFF) for shift in (0, 8, 16, 24))


def tuple_hash(tuple_: FiveTuple) -> int:
    """Reproduce the active C++ FiveTupleHash mixing on a 64-bit size_t."""
    mask = (1 << 64) - 1
    h = 0
    for field in (
        tuple_.src_ip,
        tuple_.dst_ip,
        tuple_.src_port,
        tuple_.dst_port,
        tuple_.protocol,
    ):
        mixed = (field + 0x9E3779B9 + (h << 6) + (h >> 2)) & mask
        h = (h ^ mixed) & mask
    return h


def app_type_to_string(app: AppType) -> str:
    """Return the exact display string produced by C++ appTypeToString."""
    return {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }.get(app, "Unknown")


__all__ = [
    "AppType",
    "FiveTuple",
    "FlowEntry",
    "Packet",
    "ParsedPacket",
    "PcapGlobalHeader",
    "PcapPacketHeader",
    "RawPacket",
    "app_type_to_string",
    "ip_to_int",
    "ip_to_string",
    "tuple_hash",
]
