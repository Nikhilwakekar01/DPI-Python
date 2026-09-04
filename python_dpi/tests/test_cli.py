import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from python_dpi.pcap_reader import PcapReader


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_PCAP = PROJECT_ROOT / "Packet_analyzer" / "test_dpi.pcap"


class CLITests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "python_dpi", *arguments],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_missing_arguments_returns_nonzero(self):
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_input_returns_nonzero(self):
        output = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output.unlink, missing_ok=True)
        result = self.run_cli("does-not-exist.pcap", str(output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed", result.stderr.lower())

    def test_valid_input_creates_readable_output(self):
        output = Path(tempfile.mktemp(suffix=".pcap"))
        self.addCleanup(output.unlink, missing_ok=True)
        result = self.run_cli(str(TEST_PCAP), str(output))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.exists())
        self.assertIn("Processed packets:", result.stdout)
        self.assertIn("Forwarded:", result.stdout)

        reader = PcapReader()
        self.assertTrue(reader.open(output))
        self.assertIsNotNone(reader.get_global_header())
        packet_count = 0
        while reader.read_next_packet() is not None:
            packet_count += 1
        reader.close()
        self.assertGreater(packet_count, 0)


if __name__ == "__main__":
    unittest.main()
