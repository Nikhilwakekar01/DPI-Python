import struct
import unittest
from pathlib import Path

from python_dpi.models import ParsedPacket, RawPacket, PcapPacketHeader, ip_to_int
from python_dpi.packet_parser import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_SYN,
    TCP_URG,
    PacketParser,
)
from python_dpi.pcap_reader import PcapReader


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_PCAP = PROJECT_ROOT / "test_dpi.pcap"


class PacketParserTests(unittest.TestCase):
    def raw(self, data: bytes) -> RawPacket:
        return RawPacket(
            PcapPacketHeader(ts_sec=10, ts_usec=20, incl_len=len(data), orig_len=len(data)),
            data,
        )

    def parse(self, data: bytes) -> tuple[bool, ParsedPacket]:
        parsed = ParsedPacket()
        result = PacketParser.parse(self.raw(data), parsed)
        return result, parsed

    def ethernet(self, ether_type: int = ETHERTYPE_IPV4) -> bytes:
        destination = bytes.fromhex("aabbccddeeff")
        source = bytes.fromhex("001122334455")
        return destination + source + struct.pack(">H", ether_type)

    def ipv4(
        self,
        protocol: int,
        source: str = "192.168.1.10",
        destination: str = "10.0.0.1",
        ihl_words: int = 5,
        options: bytes = b"",
    ) -> bytes:
        header_length = ihl_words * 4
        self.assertEqual(len(options), header_length - 20)
        return struct.pack(
            ">BBHHHBBH4s4s",
            (4 << 4) | ihl_words,
            0,
            0,
            0,
            0,
            64,
            protocol,
            0,
            bytes(int(part) for part in source.split(".")),
            bytes(int(part) for part in destination.split(".")),
        ) + options

    def tcp(
        self,
        source_port: int = 12345,
        destination_port: int = 443,
        data_offset_words: int = 5,
        flags: int = TCP_SYN | TCP_ACK,
        options: bytes = b"",
    ) -> bytes:
        header_length = data_offset_words * 4
        self.assertEqual(len(options), header_length - 20)
        return struct.pack(
            ">HHIIBBHHH",
            source_port,
            destination_port,
            0x01020304,
            0x05060708,
            data_offset_words << 4,
            flags,
            65535,
            0,
            0,
        ) + options

    def udp(self, source_port: int = 5353, destination_port: int = 53, payload_length: int = 0) -> bytes:
        return struct.pack(">HHHH", source_port, destination_port, 8 + payload_length, 0)

    def test_tcp_packet_fields_and_payload(self):
        payload = b"hello"
        data = self.ethernet() + self.ipv4(PROTOCOL_TCP) + self.tcp(flags=TCP_SYN | TCP_ACK | TCP_PSH) + payload
        result, parsed = self.parse(data)

        self.assertTrue(result)
        self.assertEqual(parsed.timestamp_sec, 10)
        self.assertEqual(parsed.timestamp_usec, 20)
        self.assertEqual(parsed.dest_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed.src_mac, "00:11:22:33:44:55")
        self.assertEqual(parsed.ether_type, ETHERTYPE_IPV4)
        self.assertTrue(parsed.has_ip)
        self.assertEqual(parsed.ip_version, 4)
        self.assertEqual(parsed.src_ip, "192.168.1.10")
        self.assertEqual(parsed.dest_ip, "10.0.0.1")
        self.assertEqual(parsed.protocol, PROTOCOL_TCP)
        self.assertEqual(parsed.ttl, 64)
        self.assertTrue(parsed.has_tcp)
        self.assertFalse(parsed.has_udp)
        self.assertEqual(parsed.src_port, 12345)
        self.assertEqual(parsed.dest_port, 443)
        self.assertEqual(parsed.seq_number, 0x01020304)
        self.assertEqual(parsed.ack_number, 0x05060708)
        self.assertEqual(parsed.tcp_flags, TCP_SYN | TCP_ACK | TCP_PSH)
        self.assertEqual(parsed.payload_length, len(payload))
        self.assertEqual(parsed.payload_data, payload)

    def test_udp_packet_fields_and_payload(self):
        payload = b"dns"
        data = self.ethernet() + self.ipv4(PROTOCOL_UDP) + self.udp(payload_length=len(payload)) + payload
        result, parsed = self.parse(data)

        self.assertTrue(result)
        self.assertTrue(parsed.has_ip)
        self.assertFalse(parsed.has_tcp)
        self.assertTrue(parsed.has_udp)
        self.assertEqual(parsed.src_ip, "192.168.1.10")
        self.assertEqual(parsed.dest_ip, "10.0.0.1")
        self.assertEqual(parsed.src_port, 5353)
        self.assertEqual(parsed.dest_port, 53)
        self.assertEqual(parsed.payload_length, len(payload))
        self.assertEqual(parsed.payload_data, payload)

    def test_ipv4_options_advance_payload_offset(self):
        payload = b"x"
        data = (
            self.ethernet()
            + self.ipv4(PROTOCOL_UDP, ihl_words=6, options=b"\x01\x02\x03\x04")
            + self.udp(payload_length=1)
            + payload
        )
        result, parsed = self.parse(data)

        self.assertTrue(result)
        self.assertEqual(parsed.payload_length, 1)
        self.assertEqual(parsed.payload_data, payload)

    def test_tcp_options_advance_payload_offset(self):
        payload = b"x"
        data = self.ethernet() + self.ipv4(PROTOCOL_TCP) + self.tcp(
            data_offset_words=6,
            options=b"\x01\x01\x01\x01",
        ) + payload
        result, parsed = self.parse(data)

        self.assertTrue(result)
        self.assertTrue(parsed.has_tcp)
        self.assertEqual(parsed.payload_length, 1)
        self.assertEqual(parsed.payload_data, payload)

    def test_empty_payload(self):
        data = self.ethernet() + self.ipv4(PROTOCOL_TCP) + self.tcp()
        result, parsed = self.parse(data)

        self.assertTrue(result)
        self.assertEqual(parsed.payload_length, 0)
        self.assertIsNone(parsed.payload_data)

    def test_non_ipv4_ether_types_are_accepted_without_ip_parsing(self):
        for ether_type in (ETHERTYPE_IPV6, ETHERTYPE_ARP):
            result, parsed = self.parse(self.ethernet(ether_type) + b"payload")
            self.assertTrue(result)
            self.assertFalse(parsed.has_ip)
            self.assertEqual(parsed.ether_type, ether_type)
            self.assertEqual(parsed.payload_data, b"payload")

    def test_non_tcp_udp_ipv4_is_accepted(self):
        result, parsed = self.parse(self.ethernet() + self.ipv4(PROTOCOL_ICMP) + b"icmp")
        self.assertTrue(result)
        self.assertTrue(parsed.has_ip)
        self.assertFalse(parsed.has_tcp)
        self.assertFalse(parsed.has_udp)
        self.assertEqual(parsed.payload_data, b"icmp")

    def test_formatting_helpers(self):
        self.assertEqual(PacketParser.macToString(bytes.fromhex("001122aabbcc")), "00:11:22:aa:bb:cc")
        self.assertEqual(PacketParser.ipToString(ip_to_int("192.168.1.10")), "192.168.1.10")
        self.assertEqual(PacketParser.protocolToString(PROTOCOL_ICMP), "ICMP")
        self.assertEqual(PacketParser.protocolToString(PROTOCOL_TCP), "TCP")
        self.assertEqual(PacketParser.protocolToString(PROTOCOL_UDP), "UDP")
        self.assertEqual(PacketParser.protocolToString(99), "Unknown(99)")
        self.assertEqual(PacketParser.tcpFlagsToString(0), "none")
        self.assertEqual(PacketParser.tcpFlagsToString(TCP_SYN | TCP_ACK | TCP_FIN | TCP_PSH | TCP_URG), "SYN ACK FIN PSH URG")

    def test_malformed_packets_return_false(self):
        result, _ = self.parse(b"")
        self.assertFalse(result)
        result, _ = self.parse(b"\x00" * 13)
        self.assertFalse(result)

        result, _ = self.parse(self.ethernet() + b"\x45" + b"\x00" * 18)
        self.assertFalse(result)

        invalid_version = bytes([(6 << 4) | 5]) + b"\x00" * 19
        result, _ = self.parse(self.ethernet() + invalid_version)
        self.assertFalse(result)

        invalid_ihl = bytes([(4 << 4) | 4]) + b"\x00" * 19
        result, _ = self.parse(self.ethernet() + invalid_ihl)
        self.assertFalse(result)

        result, _ = self.parse(self.ethernet() + self.ipv4(PROTOCOL_TCP) + b"\x00" * 19)
        self.assertFalse(result)

        invalid_tcp_offset = bytearray(self.tcp())
        invalid_tcp_offset[12] = 4 << 4
        result, _ = self.parse(self.ethernet() + self.ipv4(PROTOCOL_TCP) + invalid_tcp_offset)
        self.assertFalse(result)

        result, _ = self.parse(self.ethernet() + self.ipv4(PROTOCOL_UDP) + b"\x00" * 7)
        self.assertFalse(result)

    def test_existing_test_pcap(self):
        reader = PcapReader()
        self.assertTrue(reader.open(TEST_PCAP))
        total = 0
        parsed_count = 0
        tcp_count = 0
        udp_count = 0
        payload_offsets = []

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break
            total += 1
            parsed = ParsedPacket()
            if PacketParser.parse(raw, parsed):
                parsed_count += 1
                payload_offsets.append(raw.data.find(parsed.payload_data) if parsed.payload_data else len(raw.data))
                if parsed.has_tcp:
                    tcp_count += 1
                if parsed.has_udp:
                    udp_count += 1
                if parsed.has_ip:
                    self.assertTrue(parsed.src_ip)
                    self.assertTrue(parsed.dest_ip)

        reader.close()
        self.assertEqual(total, 77)
        self.assertGreater(parsed_count, 0)
        self.assertGreater(tcp_count, 0)
        self.assertGreater(udp_count, 0)
        self.assertEqual(parsed_count, tcp_count + udp_count)
        self.assertTrue(all(0 <= offset <= 65535 for offset in payload_offsets))


if __name__ == "__main__":
    unittest.main()
