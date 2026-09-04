import struct
import unittest

from python_dpi.fast_path import FastPath
from python_dpi.models import AppType, FiveTuple, Packet
from python_dpi.rules import Rules


class FastPathTests(unittest.TestCase):
    def tls_payload(self, hostname: str | None = "example.com") -> bytes:
        extensions = b""
        if hostname is not None:
            name = hostname.encode("ascii")
            sni_data = struct.pack(">H", len(name) + 3) + b"\x00" + struct.pack(">H", len(name)) + name
            extensions = struct.pack(">HH", 0, len(sni_data)) + sni_data
        body = (
            b"\x03\x03"
            + bytes(range(32))
            + b"\x00"
            + b"\x00\x02\x00\x2f"
            + b"\x01\x00"
            + struct.pack(">H", len(extensions))
            + extensions
        )
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake

    def packet(self, destination_port: int, payload: bytes, source_port: int = 1000) -> Packet:
        tuple_ = FiveTuple(1, 2, source_port, destination_port, 6)
        return Packet(
            id=1,
            ts_sec=10,
            ts_usec=20,
            tuple=tuple_,
            data=payload,
            tcp_flags=0,
            payload_offset=0,
            payload_length=len(payload),
        )

    def test_new_and_existing_flow_updates(self):
        fast_path = FastPath(Rules())
        packet = self.packet(999, b"payload")

        self.assertTrue(fast_path.process_packet(packet))
        self.assertTrue(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)

        self.assertEqual(flow.packets, 2)
        self.assertEqual(flow.bytes, 14)
        self.assertEqual(fast_path.processed, 2)
        self.assertEqual(fast_path.forwarded, 2)
        self.assertEqual(fast_path.dropped, 0)

    def test_valid_tls_sni_classifies_and_forwards(self):
        fast_path = FastPath(Rules())
        packet = self.packet(443, self.tls_payload("youtube.com"))

        self.assertTrue(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertEqual(flow.sni, "youtube.com")
        self.assertEqual(flow.app_type, AppType.YOUTUBE)
        self.assertTrue(flow.classified)
        self.assertEqual(fast_path.forwarded_packets, [packet])

    def test_invalid_tls_falls_back_to_https_without_classifying(self):
        fast_path = FastPath(Rules())
        packet = self.packet(443, b"not-tls-payload")

        self.assertTrue(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertEqual(flow.app_type, AppType.HTTPS)
        self.assertFalse(flow.classified)
        self.assertEqual(flow.sni, "")

    def test_valid_http_host_classifies_and_forwards(self):
        fast_path = FastPath(Rules())
        payload = b"GET / HTTP/1.1\r\nHost: facebook.com\r\n\r\n"
        packet = self.packet(80, payload)

        self.assertTrue(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertEqual(flow.sni, "facebook.com")
        self.assertEqual(flow.app_type, AppType.FACEBOOK)
        self.assertTrue(flow.classified)

    def test_invalid_http_falls_back_to_http_without_classifying(self):
        fast_path = FastPath(Rules())
        packet = self.packet(80, b"not an HTTP request")

        self.assertTrue(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertEqual(flow.app_type, AppType.HTTP)
        self.assertFalse(flow.classified)

    def test_dns_is_classified_by_port_without_dns_extractor(self):
        fast_path = FastPath(Rules())
        packet = self.packet(53, b"not a DNS payload")

        self.assertTrue(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertEqual(flow.app_type, AppType.DNS)
        self.assertTrue(flow.classified)
        self.assertEqual(flow.sni, "")

    def test_unknown_domain_becomes_https_and_is_classified(self):
        fast_path = FastPath(Rules())
        packet = self.packet(443, self.tls_payload("unrecognized.example"))

        self.assertTrue(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertEqual(flow.app_type, AppType.HTTPS)
        self.assertTrue(flow.classified)
        self.assertEqual(flow.sni, "unrecognized.example")

    def test_source_ip_rule_drops_packet(self):
        rules = Rules()
        rules.block_ip("1.0.0.0")
        fast_path = FastPath(rules)
        packet = self.packet(999, b"payload")

        self.assertFalse(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertTrue(flow.blocked)
        self.assertEqual(fast_path.dropped, 1)
        self.assertEqual(fast_path.forwarded_packets, [])

    def test_application_rule_drops_classified_application(self):
        rules = Rules()
        rules.block_app("YouTube")
        fast_path = FastPath(rules)
        packet = self.packet(443, self.tls_payload("youtube.com"))

        self.assertFalse(fast_path.process_packet(packet))
        flow = fast_path.flow_tracker.get_or_create(packet.tuple)
        self.assertTrue(flow.blocked)
        self.assertEqual(fast_path.app_counts[AppType.YOUTUBE], 1)

    def test_domain_rule_drops_classified_domain(self):
        rules = Rules()
        rules.block_domain("facebook")
        fast_path = FastPath(rules)
        packet = self.packet(80, b"GET / HTTP/1.1\r\nHost: facebook.com\r\n\r\n")

        self.assertFalse(fast_path.process_packet(packet))
        self.assertTrue(fast_path.flow_tracker.get_or_create(packet.tuple).blocked)

    def test_already_classified_flow_is_not_reclassified(self):
        fast_path = FastPath(Rules())
        tuple_ = self.packet(53, b"dns").tuple
        first = self.packet(53, b"dns")
        second = Packet(
            id=2,
            ts_sec=11,
            ts_usec=21,
            tuple=tuple_,
            data=self.tls_payload("youtube.com"),
            tcp_flags=0,
            payload_offset=0,
            payload_length=len(self.tls_payload("youtube.com")),
        )

        self.assertTrue(fast_path.process_packet(first))
        self.assertTrue(fast_path.process_packet(second))
        flow = fast_path.flow_tracker.get_or_create(tuple_)
        self.assertEqual(flow.app_type, AppType.DNS)
        self.assertEqual(flow.sni, "")
        self.assertTrue(flow.classified)
        self.assertEqual(flow.packets, 2)

    def test_reverse_flow_is_separate(self):
        fast_path = FastPath(Rules())
        forward = self.packet(443, b"bad")
        reverse_tuple = forward.tuple.reverse()
        reverse = Packet(
            id=2,
            ts_sec=10,
            ts_usec=20,
            tuple=reverse_tuple,
            data=b"bad",
            tcp_flags=0,
            payload_offset=0,
            payload_length=3,
        )

        fast_path.process_packet(forward)
        fast_path.process_packet(reverse)
        self.assertEqual(len(fast_path.flow_tracker), 2)
        self.assertEqual(fast_path.flow_tracker.get_or_create(forward.tuple).packets, 1)
        self.assertEqual(fast_path.flow_tracker.get_or_create(reverse_tuple).packets, 1)


if __name__ == "__main__":
    unittest.main()
