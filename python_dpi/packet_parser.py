"""Ethernet, IPv4, TCP, and UDP parsing matching the active C++ parser."""

from __future__ import annotations

import sys
from typing import Optional

from .models import ParsedPacket, RawPacket, ip_to_string


ETHERNET_HEADER_LENGTH = 14
MIN_IPV4_HEADER_LENGTH = 20
MIN_TCP_HEADER_LENGTH = 20
UDP_HEADER_LENGTH = 8

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

PROTOCOL_ICMP = 1
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806


class PacketParser:
    """Parse raw Ethernet frames into the existing ParsedPacket model."""

    @staticmethod
    def parse(raw: RawPacket, parsed: ParsedPacket) -> bool:
        parsed.__init__()
        parsed.timestamp_sec = raw.header.ts_sec
        parsed.timestamp_usec = raw.header.ts_usec

        data = raw.data
        length = len(data)
        offset = 0

        ethernet_result = PacketParser._parse_ethernet(data, length, parsed)
        if ethernet_result is None:
            return False
        offset = ethernet_result

        if parsed.ether_type == ETHERTYPE_IPV4:
            ipv4_result = PacketParser._parse_ipv4(data, length, parsed, offset)
            if ipv4_result is None:
                return False
            offset = ipv4_result

            if parsed.protocol == PROTOCOL_TCP:
                tcp_result = PacketParser._parse_tcp(data, length, parsed, offset)
                if tcp_result is None:
                    return False
                offset = tcp_result
            elif parsed.protocol == PROTOCOL_UDP:
                udp_result = PacketParser._parse_udp(data, length, parsed, offset)
                if udp_result is None:
                    return False
                offset = udp_result

        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_data = data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload_data = None

        return True

    @staticmethod
    def _parse_ethernet(
        data: bytes, length: int, parsed: ParsedPacket
    ) -> Optional[int]:
        if length < ETHERNET_HEADER_LENGTH:
            return None

        parsed.dest_mac = PacketParser.macToString(data[0:6])
        parsed.src_mac = PacketParser.macToString(data[6:12])
        parsed.ether_type = int.from_bytes(data[12:14], byteorder="big")
        return ETHERNET_HEADER_LENGTH

    @staticmethod
    def _parse_ipv4(
        data: bytes, length: int, parsed: ParsedPacket, offset: int
    ) -> Optional[int]:
        if length < offset + MIN_IPV4_HEADER_LENGTH:
            return None

        ip_data = data[offset:]
        version_ihl = ip_data[0]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if parsed.ip_version != 4:
            return None

        ip_header_length = ihl * 4
        if (
            ip_header_length < MIN_IPV4_HEADER_LENGTH
            or length < offset + ip_header_length
        ):
            return None

        parsed.ttl = ip_data[8]
        parsed.protocol = ip_data[9]
        parsed.src_ip = PacketParser.ipToString(
            int.from_bytes(ip_data[12:16], byteorder=sys.byteorder)
        )
        parsed.dest_ip = PacketParser.ipToString(
            int.from_bytes(ip_data[16:20], byteorder=sys.byteorder)
        )
        parsed.has_ip = True
        return offset + ip_header_length

    @staticmethod
    def _parse_tcp(
        data: bytes, length: int, parsed: ParsedPacket, offset: int
    ) -> Optional[int]:
        if length < offset + MIN_TCP_HEADER_LENGTH:
            return None

        tcp_data = data[offset:]
        parsed.src_port = int.from_bytes(tcp_data[0:2], byteorder="big")
        parsed.dest_port = int.from_bytes(tcp_data[2:4], byteorder="big")
        parsed.seq_number = int.from_bytes(tcp_data[4:8], byteorder="big")
        parsed.ack_number = int.from_bytes(tcp_data[8:12], byteorder="big")

        data_offset = (tcp_data[12] >> 4) & 0x0F
        tcp_header_length = data_offset * 4
        parsed.tcp_flags = tcp_data[13]

        if (
            tcp_header_length < MIN_TCP_HEADER_LENGTH
            or length < offset + tcp_header_length
        ):
            return None

        parsed.has_tcp = True
        return offset + tcp_header_length

    @staticmethod
    def _parse_udp(
        data: bytes, length: int, parsed: ParsedPacket, offset: int
    ) -> Optional[int]:
        if length < offset + UDP_HEADER_LENGTH:
            return None

        udp_data = data[offset:]
        parsed.src_port = int.from_bytes(udp_data[0:2], byteorder="big")
        parsed.dest_port = int.from_bytes(udp_data[2:4], byteorder="big")
        parsed.has_udp = True
        return offset + UDP_HEADER_LENGTH

    @staticmethod
    def macToString(mac: bytes) -> str:
        return ":".join(f"{value:02x}" for value in mac[:6])

    @staticmethod
    def ipToString(ip: int) -> str:
        return ip_to_string(ip)

    @staticmethod
    def protocolToString(protocol: int) -> str:
        if protocol == PROTOCOL_ICMP:
            return "ICMP"
        if protocol == PROTOCOL_TCP:
            return "TCP"
        if protocol == PROTOCOL_UDP:
            return "UDP"
        return f"Unknown({protocol})"

    @staticmethod
    def tcpFlagsToString(flags: int) -> str:
        names = []
        if flags & TCP_SYN:
            names.append("SYN")
        if flags & TCP_ACK:
            names.append("ACK")
        if flags & TCP_FIN:
            names.append("FIN")
        if flags & TCP_RST:
            names.append("RST")
        if flags & TCP_PSH:
            names.append("PSH")
        if flags & TCP_URG:
            names.append("URG")
        return " ".join(names) if names else "none"

    # Snake-case aliases for Python callers while retaining C++ method names.
    mac_to_string = macToString
    ip_to_string = ipToString
    protocol_to_string = protocolToString
    tcp_flags_to_string = tcpFlagsToString


__all__ = [
    "ETHERTYPE_ARP",
    "ETHERTYPE_IPV4",
    "ETHERTYPE_IPV6",
    "ETHERNET_HEADER_LENGTH",
    "MIN_IPV4_HEADER_LENGTH",
    "MIN_TCP_HEADER_LENGTH",
    "PROTOCOL_ICMP",
    "PROTOCOL_TCP",
    "PROTOCOL_UDP",
    "TCP_ACK",
    "TCP_FIN",
    "TCP_PSH",
    "TCP_RST",
    "TCP_SYN",
    "TCP_URG",
    "UDP_HEADER_LENGTH",
    "PacketParser",
]
