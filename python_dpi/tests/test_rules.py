import unittest

from python_dpi.models import AppType, ip_to_int
from python_dpi.rules import Rules


class RulesTests(unittest.TestCase):
    def test_source_ip_rules_use_exact_cpp_ip_representation(self):
        rules = Rules()
        source_ip = ip_to_int("192.168.1.10")

        self.assertFalse(rules.is_blocked(source_ip, AppType.UNKNOWN, ""))
        rules.block_ip("192.168.1.10")
        rules.block_ip("192.168.1.10")
        self.assertTrue(rules.is_blocked(source_ip, AppType.UNKNOWN, ""))
        self.assertFalse(rules.is_blocked(ip_to_int("192.168.1.11"), AppType.UNKNOWN, ""))
        self.assertFalse(rules.is_blocked(ip_to_int("192.168.1.0/24"), AppType.UNKNOWN, ""))

    def test_application_rules_use_display_names(self):
        rules = Rules()
        rules.block_app("YouTube")
        rules.block_app("YouTube")

        self.assertTrue(rules.is_blocked(0, AppType.YOUTUBE, ""))
        self.assertFalse(rules.is_blocked(0, AppType.FACEBOOK, ""))
        rules.block_app("Unknown app")
        self.assertFalse(rules.is_blocked(0, AppType.FACEBOOK, ""))

    def test_domain_rules_are_case_sensitive_substrings(self):
        rules = Rules()
        rules.block_domain("youtube")
        rules.block_domain("youtube")

        self.assertTrue(rules.is_blocked(0, AppType.UNKNOWN, "www.youtube.com"))
        self.assertTrue(rules.is_blocked(0, AppType.UNKNOWN, "foo-youtube-bar"))
        self.assertFalse(rules.is_blocked(0, AppType.UNKNOWN, "www.YouTube.com"))
        self.assertFalse(rules.is_blocked(0, AppType.UNKNOWN, "example.com"))

    def test_empty_domain_rule_matches_every_sni(self):
        rules = Rules()
        rules.block_domain("")
        self.assertTrue(rules.is_blocked(0, AppType.UNKNOWN, ""))
        self.assertTrue(rules.is_blocked(0, AppType.UNKNOWN, "example.com"))

    def test_rule_check_order_is_ip_then_app_then_domain(self):
        rules = Rules()
        rules.block_ip("192.168.1.10")
        rules.block_app("YouTube")
        rules.block_domain("youtube")

        self.assertTrue(rules.is_blocked(ip_to_int("192.168.1.10"), AppType.YOUTUBE, "youtube"))
        self.assertTrue(rules.is_blocked(0, AppType.YOUTUBE, "other"))
        self.assertTrue(rules.is_blocked(0, AppType.UNKNOWN, "youtube"))
        self.assertFalse(rules.is_blocked(0, AppType.UNKNOWN, "other"))

    def test_only_active_rule_api_is_exposed(self):
        rules = Rules()
        self.assertFalse(hasattr(rules, "block_port"))
        self.assertFalse(hasattr(rules, "unblock_ip"))
        self.assertFalse(hasattr(rules, "save_rules"))
        self.assertFalse(hasattr(rules, "load_rules"))
        self.assertFalse(hasattr(rules, "should_block"))

    def test_cpp_style_aliases(self):
        rules = Rules()
        rules.blockIP("10.0.0.1")
        rules.blockApp("Facebook")
        rules.blockDomain("example")

        self.assertTrue(rules.isBlocked(ip_to_int("10.0.0.1"), AppType.UNKNOWN, ""))
        self.assertTrue(rules.isBlocked(0, AppType.FACEBOOK, ""))
        self.assertTrue(rules.isBlocked(0, AppType.UNKNOWN, "example.com"))


if __name__ == "__main__":
    unittest.main()
