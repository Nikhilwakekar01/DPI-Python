import collections
import struct
import tempfile
import unittest
from pathlib import Path

from python_dpi.dpi_engine import DPIEngine, EngineConfig
from python_dpi.models import PcapGlobalHeader, PcapPacketHeader, ParsedPacket
from python_dpi.packet_parser import PacketParser
from python_dpi.pcap_reader import PcapReader


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_PCAP = PROJECT_ROOT / "test_dpi.pcap"


class DPIEngineTests(unittest.TestCase):
    def write_pcap(self, records: list[tuple[int, int, bytes]]) -> Path:
        path = Path(tempfile.mktemp(suffix=".pcap"))
        header = struct.pack("=IHH iIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        body = bytearray(header)
        for ts_sec, ts_usec, data in records:
            body.extend(struct.pack("=IIII", ts_sec, ts_usec, len(data), len(data)))
            body.extend(data)
        path.write_bytes(body)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def tls_payload(self, hostname: str) -> bytes:
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

    def ethernet_tcp_packet(self, payload: bytes, source_ip: bytes = b"\xc0\xa8\x01\x0a") -> bytes:
        ethernet = bytes.fromhex("aabbccddeeff0011223344550800")
        ipv4 = struct.pack(
            ">BBHHHBBH4s4s",
            0x45,
            0,
            20 + 20 + len(payload),
            0,
            0,
            64,
            6,
            0,
            source_ip,
            b"\x0a\x00\x00\x01",
        )
        tcp = struct.pack(">HHIIBBHHH", 12345, 443, 1, 0, 0x50, 0x18, 65535, 0, 0)
        return ethernet + ipv4 + tcp + payload

    def read_packets(self, path: Path) -> list:
        reader = PcapReader()
        self.assertTrue(reader.open(path))
        packets = []
        while True:
            packet = reader.read_next_packet()
            if packet is None:
                break
            packets.append(packet)
        reader.close()
        return packets

    def test_default_topology_and_queue_configuration(self):
        engine = DPIEngine()
        self.assertEqual(engine.config.num_lbs, 2)
        self.assertEqual(engine.config.fps_per_lb, 2)
        self.assertEqual(engine.config.queue_size, 10000)
        self.assertEqual(len(engine.load_balancers), 2)
        self.assertEqual(len(engine.fast_paths), 4)
        self.assertTrue(all(lb.num_fast_paths == 2 for lb in engine.load_balancers))
        self.assertEqual(engine.load_balancers[0].QUEUE_SIZE, 10000)
        self.assertEqual(engine.load_balancers[0].POP_TIMEOUT_MS, 100)

    def test_invalid_packets_are_skipped_and_valid_packet_is_output(self):
        source_reader = PcapReader()
        self.assertTrue(source_reader.open(TEST_PCAP))
        valid = source_reader.read_next_packet()
        self.assertIsNotNone(valid)
        assert valid is not None
        source_reader.close()
        input_path = self.write_pcap([(1, 2, b"\x00" * 13), (3, 4, valid.data)])
        output_path = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output_path.unlink, missing_ok=True)

        engine = DPIEngine()
        self.assertTrue(engine.process(input_path, output_path))
        self.assertEqual(engine.stats.total_packets, 1)
        output_packets = self.read_packets(output_path)
        self.assertEqual(len(output_packets), 1)
        self.assertEqual(output_packets[0].data, valid.data)

    def test_tls_app_blocking_drops_packet_and_preserves_header(self):
        packet = self.ethernet_tcp_packet(self.tls_payload("youtube.com"))
        input_path = self.write_pcap([(123, 456, packet)])
        output_path = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output_path.unlink, missing_ok=True)
        engine = DPIEngine()
        engine.block_app("YouTube")

        self.assertTrue(engine.process(input_path, output_path))
        self.assertEqual(engine.stats.total_packets, 1)
        self.assertEqual(engine.stats.dropped, 1)
        self.assertEqual(engine.stats.forwarded, 0)
        self.assertEqual(self.read_packets(output_path), [])
        output_reader = PcapReader()
        self.assertTrue(output_reader.open(output_path))
        header = output_reader.get_global_header()
        self.assertEqual(header, PcapGlobalHeader(0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        output_reader.close()

    def test_forwarded_packet_preserves_timestamp_lengths_and_bytes(self):
        packet = self.ethernet_tcp_packet(b"plain")
        input_path = self.write_pcap([(123, 456, packet)])
        output_path = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output_path.unlink, missing_ok=True)
        engine = DPIEngine()

        self.assertTrue(engine.process(input_path, output_path))
        packets = self.read_packets(output_path)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].header.ts_sec, 123)
        self.assertEqual(packets[0].header.ts_usec, 456)
        self.assertEqual(packets[0].header.incl_len, len(packet))
        self.assertEqual(packets[0].header.orig_len, len(packet))
        self.assertEqual(packets[0].data, packet)
        self.assertEqual(engine.stats.forwarded, 1)

    def test_real_pcap_integration_completes_and_output_is_readable(self):
        output_path = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output_path.unlink, missing_ok=True)
        engine = DPIEngine()

        self.assertTrue(engine.process(TEST_PCAP, output_path))
        output_packets = self.read_packets(output_path)
        self.assertEqual(engine.stats.forwarded, len(output_packets))
        self.assertEqual(engine.stats.forwarded + engine.stats.dropped, engine.stats.total_packets)
        self.assertGreater(engine.stats.total_packets, 0)

    def test_worker_threads_join_after_processing(self):
        output_path = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output_path.unlink, missing_ok=True)
        engine = DPIEngine()
        self.assertTrue(engine.process(TEST_PCAP, output_path))

        self.assertTrue(all(not thread.is_alive() for thread in engine._lb_threads))
        self.assertTrue(all(not thread.is_alive() for thread in engine._fp_threads))
        self.assertIsNotNone(engine._writer_thread)
        self.assertFalse(engine._writer_thread.is_alive())

    def test_output_order_is_not_used_for_correctness(self):
        input_packets = self.read_packets(TEST_PCAP)
        output_path = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output_path.unlink, missing_ok=True)
        engine = DPIEngine()
        self.assertTrue(engine.process(TEST_PCAP, output_path))
        output_packets = self.read_packets(output_path)

        input_counter = collections.Counter((p.header.ts_sec, p.header.ts_usec, p.data) for p in input_packets)
        output_counter = collections.Counter((p.header.ts_sec, p.header.ts_usec, p.data) for p in output_packets)
        self.assertTrue(output_counter <= input_counter)


if __name__ == "__main__":
    unittest.main()
