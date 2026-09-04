import unittest

from python_dpi.models import (
    AppType,
    FiveTuple,
    FlowEntry,
    Packet,
    ParsedPacket,
    PcapGlobalHeader,
    PcapPacketHeader,
    RawPacket,
    app_type_to_string,
    ip_to_int,
    ip_to_string,
    tuple_hash,
)


class ModelsTests(unittest.TestCase):
    def test_app_type_values_and_strings(self):
        expected = {
            "UNKNOWN": 0,
            "HTTP": 1,
            "HTTPS": 2,
            "DNS": 3,
            "TLS": 4,
            "QUIC": 5,
            "GOOGLE": 6,
            "FACEBOOK": 7,
            "YOUTUBE": 8,
            "TWITTER": 9,
            "INSTAGRAM": 10,
            "NETFLIX": 11,
            "AMAZON": 12,
            "MICROSOFT": 13,
            "APPLE": 14,
            "WHATSAPP": 15,
            "TELEGRAM": 16,
            "TIKTOK": 17,
            "SPOTIFY": 18,
            "ZOOM": 19,
            "DISCORD": 20,
            "GITHUB": 21,
            "CLOUDFLARE": 22,
            "APP_COUNT": 23,
        }
        self.assertEqual({member.name: member.value for member in AppType}, expected)
        self.assertEqual(app_type_to_string(AppType.TWITTER), "Twitter/X")
        self.assertEqual(app_type_to_string(AppType.APP_COUNT), "Unknown")

    def test_five_tuple_directionality_reverse_and_string(self):
        tuple_ = FiveTuple(ip_to_int("192.168.1.10"), ip_to_int("10.0.0.1"), 54321, 443, 6)
        reverse = tuple_.reverse()

        self.assertEqual(tuple_, tuple_)
        self.assertNotEqual(tuple_, reverse)
        self.assertEqual(
            tuple_.to_string(),
            "192.168.1.10:54321 -> 10.0.0.1:443 (TCP)",
        )
        self.assertEqual(
            reverse.to_string(),
            "10.0.0.1:443 -> 192.168.1.10:54321 (TCP)",
        )

    def test_tuple_hash_is_deterministic_and_directional(self):
        tuple_ = FiveTuple(ip_to_int("192.168.1.10"), ip_to_int("10.0.0.1"), 54321, 443, 6)
        reverse = tuple_.reverse()
        equivalent = FiveTuple(
            tuple_.src_ip,
            tuple_.dst_ip,
            tuple_.src_port,
            tuple_.dst_port,
            tuple_.protocol,
        )

        self.assertEqual(tuple_hash(tuple_), tuple_hash(tuple_))
        self.assertEqual(tuple_hash(tuple_), tuple_hash(equivalent))
        self.assertNotEqual(tuple_hash(tuple_), tuple_hash(reverse))

    def test_ip_conversion_matches_cpp_representation(self):
        value = ip_to_int("192.168.1.10")
        self.assertEqual(value, 10 << 24 | 1 << 16 | 168 << 8 | 192)
        self.assertEqual(ip_to_string(value), "192.168.1.10")
        self.assertEqual(ip_to_int(ip_to_string(value)), value)

    def test_pcap_headers_and_raw_packet(self):
        global_header = PcapGlobalHeader(0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        packet_header = PcapPacketHeader(123, 456, 4, 4)
        raw = RawPacket(packet_header, b"\x01\x02\x03\x04")

        self.assertEqual(global_header.snaplen, 65535)
        self.assertEqual(raw.header.ts_sec, 123)
        self.assertEqual(raw.header.ts_usec, 456)
        self.assertEqual(raw.data, b"\x01\x02\x03\x04")
        self.assertIsInstance(raw.data, bytes)

    def test_packet_fields(self):
        tuple_ = FiveTuple(1, 2, 1000, 443, 6)
        packet = Packet(7, 10, 20, tuple_, b"payload", 0x18, 54, 7)

        self.assertEqual(packet.id, 7)
        self.assertEqual(packet.ts_sec, 10)
        self.assertEqual(packet.ts_usec, 20)
        self.assertEqual(packet.data, b"payload")
        self.assertEqual(packet.tcp_flags, 0x18)
        self.assertEqual(packet.payload_offset, 54)
        self.assertEqual(packet.payload_length, 7)

    def test_flow_entry_defaults_and_mutation(self):
        tuple_ = FiveTuple(1, 2, 1000, 443, 6)
        flow = FlowEntry(tuple_)

        self.assertEqual(flow.app_type, AppType.UNKNOWN)
        self.assertEqual(flow.sni, "")
        self.assertEqual(flow.packets, 0)
        self.assertEqual(flow.bytes, 0)
        self.assertFalse(flow.blocked)
        self.assertFalse(flow.classified)

        flow.app_type = AppType.YOUTUBE
        flow.sni = "www.youtube.com"
        flow.packets += 1
        flow.bytes += 100
        flow.blocked = True
        flow.classified = True

        self.assertEqual(flow.app_type, AppType.YOUTUBE)
        self.assertEqual(flow.packets, 1)
        self.assertEqual(flow.bytes, 100)
        self.assertTrue(flow.blocked)
        self.assertTrue(flow.classified)

    def test_parsed_packet_matches_cpp_fields(self):
        parsed = ParsedPacket(
            timestamp_sec=1,
            timestamp_usec=2,
            src_mac="00:11:22:33:44:55",
            dest_mac="aa:bb:cc:dd:ee:ff",
            ether_type=0x0800,
            has_ip=True,
            ip_version=4,
            src_ip="192.168.1.10",
            dest_ip="10.0.0.1",
            protocol=6,
            ttl=64,
            has_tcp=True,
            has_udp=False,
            src_port=54321,
            dest_port=443,
            tcp_flags=0x18,
            seq_number=100,
            ack_number=200,
            payload_length=4,
            payload_data=b"test",
        )

        self.assertTrue(parsed.has_ip)
        self.assertTrue(parsed.has_tcp)
        self.assertFalse(parsed.has_udp)
        self.assertEqual(parsed.payload_data, b"test")
        self.assertEqual(parsed.payload_length, 4)


if __name__ == "__main__":
    unittest.main()
