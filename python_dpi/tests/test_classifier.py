import unittest
from pathlib import Path

from python_dpi.classifier import classify_domain
from python_dpi.extractors import DNSExtractor, HTTPHostExtractor, SNIExtractor
from python_dpi.models import AppType
from python_dpi.packet_parser import PacketParser
from python_dpi.models import ParsedPacket
from python_dpi.pcap_reader import PcapReader


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_PCAP = PROJECT_ROOT / "Packet_analyzer" / "test_dpi.pcap"


class ClassifierTests(unittest.TestCase):
    def test_empty_and_unknown_domains(self):
        self.assertEqual(classify_domain(""), AppType.UNKNOWN)
        self.assertEqual(classify_domain("example.com"), AppType.HTTPS)

    def test_all_known_application_mappings(self):
        cases = {
            AppType.GOOGLE: "www.google.com",
            AppType.YOUTUBE: "www.youtube.com",
            AppType.FACEBOOK: "www.facebook.com",
            AppType.INSTAGRAM: "cdninstagram.example",
            AppType.WHATSAPP: "www.whatsapp.com",
            AppType.TWITTER: "www.twitter.com",
            AppType.NETFLIX: "nflxvideo.example",
            AppType.AMAZON: "www.amazonaws.com",
            AppType.MICROSOFT: "login.microsoft.net",
            AppType.APPLE: "www.icloud.com",
            AppType.TELEGRAM: "t.me/example",
            AppType.TIKTOK: "www.tiktok.com",
            AppType.SPOTIFY: "scdn.co/assets",
            AppType.ZOOM: "zoom.us",
            AppType.DISCORD: "discordapp.com",
            AppType.GITHUB: "githubusercontent.org",
            AppType.CLOUDFLARE: "cf-edge.example",
        }
        for expected, domain in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(classify_domain(domain), expected)

    def test_case_insensitive_and_substring_matching(self):
        self.assertEqual(classify_domain("YOUTUBE.COM"), AppType.YOUTUBE)
        self.assertEqual(classify_domain("MiXeD-FaCeBoOk-Value"), AppType.FACEBOOK)
        self.assertEqual(classify_domain("foo-youtube-bar"), AppType.YOUTUBE)
        self.assertEqual(classify_domain("prefixcloudflareSuffix"), AppType.CLOUDFLARE)

    def test_exact_precedence_from_cpp(self):
        self.assertEqual(classify_domain("youtube.ggpht.example"), AppType.GOOGLE)
        self.assertEqual(classify_domain("google.youtube.example"), AppType.GOOGLE)
        self.assertEqual(classify_domain("meta.com.instagram.example"), AppType.FACEBOOK)
        self.assertEqual(classify_domain("facebook.whatsapp.example"), AppType.FACEBOOK)

    def test_classifier_does_not_apply_port_logic(self):
        self.assertEqual(classify_domain(""), AppType.UNKNOWN)
        self.assertEqual(classify_domain("unknown.example:443"), AppType.HTTPS)
        self.assertEqual(classify_domain("unknown.example:80"), AppType.HTTPS)

    def test_real_pcap_extracted_values_are_classifiable(self):
        reader = PcapReader()
        self.assertTrue(reader.open(TEST_PCAP))
        inspected = 0
        classified = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break
            parsed = ParsedPacket()
            if not PacketParser.parse(raw, parsed) or not parsed.payload_data:
                continue
            inspected += 1
            values = (
                SNIExtractor.extract(parsed.payload_data),
                HTTPHostExtractor.extract(parsed.payload_data),
                DNSExtractor.extractQuery(parsed.payload_data),
            )
            for value in values:
                if value is not None:
                    self.assertIsInstance(classify_domain(value), AppType)
                    classified += 1

        reader.close()
        self.assertGreater(inspected, 0)
        self.assertGreaterEqual(classified, 0)


if __name__ == "__main__":
    unittest.main()
