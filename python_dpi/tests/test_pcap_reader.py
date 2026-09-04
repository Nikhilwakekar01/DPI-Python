import struct
import tempfile
import unittest
from pathlib import Path

from python_dpi.models import PcapGlobalHeader
from python_dpi.pcap_reader import (
    PCAP_MAGIC_NATIVE,
    PCAP_MAGIC_SWAPPED,
    PcapReader,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_PCAP = PROJECT_ROOT / "Packet_analyzer" / "test_dpi.pcap"


class PcapReaderTests(unittest.TestCase):
    def write_pcap(
        self,
        byte_order: str,
        *,
        global_header: tuple[int, int, int, int, int, int, int] | None = None,
        packet_header: tuple[int, int, int, int] | None = None,
        packet_data: bytes = b"",
    ) -> Path:
        temporary = tempfile.NamedTemporaryFile(delete=False)
        temporary.close()
        path = Path(temporary.name)

        header = global_header or (PCAP_MAGIC_NATIVE, 2, 4, 0, 0, 65535, 1)
        packet = packet_header or (1, 2, len(packet_data), len(packet_data))
        magic_format = "<" if byte_order == ">" else byte_order
        path.write_bytes(
            struct.pack(magic_format + "I", header[0])
            + struct.pack(byte_order + "HH iIII", *header[1:])
            + struct.pack(byte_order + "IIII", *packet)
            + packet_data
        )
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def test_existing_native_pcap(self):
        reader = PcapReader()
        self.assertTrue(reader.open(TEST_PCAP))
        self.assertTrue(reader.is_open())
        self.assertFalse(reader.needs_byte_swap())

        header = reader.get_global_header()
        self.assertIsNotNone(header)
        assert header is not None
        self.assertEqual(header.magic_number, PCAP_MAGIC_NATIVE)
        self.assertEqual(header.version_major, 2)
        self.assertEqual(header.version_minor, 4)
        self.assertEqual(header.snaplen, 65535)
        self.assertEqual(header.network, 1)

        first = reader.read_next_packet()
        self.assertIsNotNone(first)
        assert first is not None
        self.assertEqual(first.header.ts_sec, 1700000000)
        self.assertEqual(first.header.ts_usec, 484823)
        self.assertEqual(first.header.incl_len, 54)
        self.assertEqual(first.header.orig_len, 54)
        self.assertEqual(first.data, TEST_PCAP.read_bytes()[40:94])

        count = 1
        while reader.read_next_packet() is not None:
            count += 1
        self.assertEqual(count, 77)
        self.assertIsNone(reader.read_next_packet())
        reader.close()
        self.assertFalse(reader.is_open())

    def test_swapped_endian_pcap(self):
        packet_data = b"\x00\x01\x02\x03"
        path = self.write_pcap(
            ">",
            global_header=(PCAP_MAGIC_SWAPPED, 2, 4, -7, 9, 128, 1),
            packet_header=(123, 456, len(packet_data), 99),
            packet_data=packet_data,
        )

        reader = PcapReader()
        self.assertTrue(reader.open(path))
        self.assertTrue(reader.needs_byte_swap())
        header = reader.get_global_header()
        self.assertIsNotNone(header)
        assert header is not None
        self.assertEqual(header.magic_number, PCAP_MAGIC_SWAPPED)
        self.assertEqual(header.version_major, 2)
        self.assertEqual(header.version_minor, 4)
        self.assertEqual(header.thiszone, struct.unpack("<i", struct.pack(">i", -7))[0])
        self.assertEqual(header.sigfigs, struct.unpack("<I", struct.pack(">I", 9))[0])
        self.assertEqual(header.snaplen, 128)
        self.assertEqual(header.network, 1)

        packet = reader.read_next_packet()
        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.header.ts_sec, 123)
        self.assertEqual(packet.header.ts_usec, 456)
        self.assertEqual(packet.header.incl_len, 4)
        self.assertEqual(packet.header.orig_len, 99)
        self.assertEqual(packet.data, packet_data)
        reader.close()

    def test_native_file_is_not_swapped(self):
        packet_data = b"data"
        path = self.write_pcap(
            "<",
            global_header=(PCAP_MAGIC_NATIVE, 2, 4, -3, 5, 64, 1),
            packet_header=(11, 12, 4, 8),
            packet_data=packet_data,
        )

        reader = PcapReader()
        self.assertTrue(reader.open(path))
        self.assertFalse(reader.needs_byte_swap())
        packet = reader.read_next_packet()
        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.header.ts_sec, 11)
        self.assertEqual(packet.header.orig_len, 8)
        self.assertEqual(packet.data, packet_data)
        reader.close()

    def test_invalid_magic_closes_reader(self):
        path = self.write_pcap(
            "<",
            global_header=(0x12345678, 2, 4, 0, 0, 64, 1),
        )
        reader = PcapReader()
        self.assertFalse(reader.open(path))
        self.assertFalse(reader.is_open())
        self.assertIsNone(reader.get_global_header())

    def test_truncated_global_header(self):
        path = Path(tempfile.mktemp())
        path.write_bytes(b"\xd4\xc3\xb2")
        self.addCleanup(path.unlink, missing_ok=True)

        reader = PcapReader()
        self.assertFalse(reader.open(path))
        self.assertFalse(reader.is_open())

    def test_truncated_packet_header(self):
        path = self.write_pcap("<", packet_data=b"")
        path.write_bytes(path.read_bytes()[:24] + b"\x00" * 15)

        reader = PcapReader()
        self.assertTrue(reader.open(path))
        self.assertIsNone(reader.read_next_packet())
        reader.close()

    def test_truncated_packet_payload(self):
        path = self.write_pcap(
            "<",
            packet_header=(1, 2, 5, 5),
            packet_data=b"1234",
        )
        reader = PcapReader()
        self.assertTrue(reader.open(path))
        self.assertIsNone(reader.read_next_packet())
        reader.close()

    def test_nonexistent_path(self):
        reader = PcapReader()
        self.assertFalse(reader.open(PROJECT_ROOT / "does-not-exist.pcap"))
        self.assertFalse(reader.is_open())

    def test_read_before_open_returns_none(self):
        reader = PcapReader()
        self.assertIsNone(reader.read_next_packet())

    def test_reopening_closes_previous_file(self):
        first = self.write_pcap("<", packet_data=b"one")
        second = self.write_pcap("<", packet_data=b"two")
        reader = PcapReader()

        self.assertTrue(reader.open(first))
        self.assertTrue(reader.open(second))
        packet = reader.read_next_packet()
        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.data, b"two")


if __name__ == "__main__":
    unittest.main()
