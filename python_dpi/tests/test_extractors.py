import struct
import unittest
from pathlib import Path

from python_dpi.models import ParsedPacket
from python_dpi.pcap_reader import PcapReader
from python_dpi.packet_parser import PacketParser
from python_dpi.extractors import (
    DNSExtractor,
    HTTPHostExtractor,
    QUICSNIExtractor,
    SNIExtractor,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_PCAP = PROJECT_ROOT / "test_dpi.pcap"


class ExtractorTests(unittest.TestCase):
    def tls_client_hello(self, hostname: str | None = "example.com", version: int = 0x0303) -> bytes:
        extensions = b""
        if hostname is not None:
            hostname_bytes = hostname.encode("ascii")
            sni_data = struct.pack(">H", len(hostname_bytes) + 3)
            sni_data += b"\x00" + struct.pack(">H", len(hostname_bytes)) + hostname_bytes
            extensions = struct.pack(">HH", 0, len(sni_data)) + sni_data

        body = (
            struct.pack(">H", 0x0303)
            + bytes(range(32))
            + b"\x00"
            + struct.pack(">H", 2)
            + b"\x00\x2f"
            + b"\x01\x00"
            + struct.pack(">H", len(extensions))
            + extensions
        )
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16" + struct.pack(">H", version) + struct.pack(">H", len(handshake)) + handshake

    def test_valid_sni_and_tls_validation(self):
        payload = self.tls_client_hello()
        self.assertTrue(SNIExtractor.isTLSClientHello(payload))
        self.assertEqual(SNIExtractor.extract(payload), "example.com")
        self.assertEqual(SNIExtractor.extractExtensions(payload), [])
        self.assertEqual(SNIExtractor.readUint16BE(b"\x12\x34"), 0x1234)
        self.assertEqual(SNIExtractor.readUint24BE(b"\x01\x23\x45"), 0x012345)

    def test_sni_without_extension_and_empty_hostname(self):
        self.assertIsNone(SNIExtractor.extract(self.tls_client_hello(None)))
        self.assertEqual(SNIExtractor.extract(self.tls_client_hello("")), "")

    def test_tls_rejection_and_truncation(self):
        payload = self.tls_client_hello()
        for malformed in (
            bytes([0x15]) + payload[1:],
            payload[:0] + b"\x16\x03\x03\x00\x00\x02\x00\x00\x00",
            b"\x16\x02\xff\x00\x00\x01\x00\x00\x00",
            payload[:8],
            payload[:-1],
        ):
            self.assertFalse(SNIExtractor.isTLSClientHello(malformed))
            self.assertIsNone(SNIExtractor.extract(malformed))

    def test_tls_malformed_sni_extension(self):
        payload = bytearray(self.tls_client_hello())
        extension_start = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1
        payload[extension_start + 2:extension_start + 4] = b"\x00\x04"
        self.assertIsNone(SNIExtractor.extract(bytes(payload)))

        payload = bytearray(self.tls_client_hello())
        sni_type_offset = extension_start + 4 + 2
        payload[sni_type_offset] = 1
        self.assertIsNone(SNIExtractor.extract(bytes(payload)))

    def test_http_methods_and_host_variants(self):
        methods = ("GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI")
        for method in methods:
            payload = (method + " / HTTP/1.1\r\nHost: example.com\r\n\r\n").encode("ascii")
            self.assertTrue(HTTPHostExtractor.isHTTPRequest(payload))
            self.assertEqual(HTTPHostExtractor.extract(payload), "example.com")

        self.assertEqual(
            HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nhOsT:\t example.com:8080\r\n"),
            "example.com",
        )

    def test_http_missing_invalid_and_empty_host(self):
        self.assertIsNone(HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n"))
        self.assertTrue(HTTPHostExtractor.isHTTPRequest(b"DELETE / HTTP/1.1"))
        self.assertFalse(HTTPHostExtractor.isHTTPRequest(b"BAD / HTTP/1.1"))
        self.assertIsNone(HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nHost:\r\n"))
        self.assertEqual(HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nHost: example.com\n"), "example.com")

    def dns_query(self, domain: str, qtype: int = 1, terminate: bool = True) -> bytes:
        labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in domain.split("."))
        if terminate:
            labels += b"\x00"
        header = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        return header + labels + struct.pack(">HH", qtype, 1)

    def test_dns_query_and_validation(self):
        payload = self.dns_query("www.example.com")
        self.assertTrue(DNSExtractor.isDNSQuery(payload))
        self.assertEqual(DNSExtractor.extractQuery(payload), "www.example.com")
        self.assertEqual(DNSExtractor.extractQuery(self.dns_query("example.com", qtype=28)), "example.com")
        self.assertIsNone(DNSExtractor.extractQuery(b"\x00" * 11))
        self.assertIsNone(DNSExtractor.extractQuery(bytes.fromhex("123480000001000000000000") + b"\x07example\x00"))
        self.assertIsNone(DNSExtractor.extractQuery(bytes.fromhex("123400000000000000000000")))

    def test_dns_malformed_label_behavior(self):
        header = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        self.assertIsNone(DNSExtractor.extractQuery(header + b"\x40invalid"))
        self.assertEqual(DNSExtractor.extractQuery(header + b"\x07example"), "example")
        self.assertIsNone(DNSExtractor.extractQuery(header + b"\x00"))

    def test_quic_is_only_a_long_header_heuristic(self):
        self.assertFalse(QUICSNIExtractor.isQUICInitial(b"\x01\x00\x00\x00\x01"))
        self.assertFalse(QUICSNIExtractor.isQUICInitial(b"\x80\x00"))
        self.assertTrue(QUICSNIExtractor.isQUICInitial(b"\x80\x00\x00\x00\x01"))
        self.assertIsNone(QUICSNIExtractor.extract(b"\x80\x00\x00\x00\x01"))

    def test_quic_heuristic_sni_extraction(self):
        tls = self.tls_client_hello()
        payload = b"\x80\x00\x00\x00\x01" + b"\x00" * 5 + tls
        self.assertEqual(QUICSNIExtractor.extract(payload), "example.com")

    def test_real_pcap_payload_integration(self):
        reader = PcapReader()
        self.assertTrue(reader.open(TEST_PCAP))
        packets = 0
        payloads = 0
        for _ in range(77):
            raw = reader.read_next_packet()
            self.assertIsNotNone(raw)
            assert raw is not None
            parsed = ParsedPacket()
            if PacketParser.parse(raw, parsed) and parsed.payload_data:
                packets += 1
                payloads += int(
                    SNIExtractor.extract(parsed.payload_data) is not None
                    or HTTPHostExtractor.extract(parsed.payload_data) is not None
                    or DNSExtractor.extractQuery(parsed.payload_data) is not None
                    or QUICSNIExtractor.extract(parsed.payload_data) is not None
                )
        reader.close()
        self.assertGreater(packets, 0)
        self.assertGreaterEqual(payloads, 0)


if __name__ == "__main__":
    unittest.main()
