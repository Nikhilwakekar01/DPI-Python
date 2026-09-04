import unittest

from python_dpi.flow_tracker import FlowTracker
from python_dpi.models import AppType, FiveTuple, Packet


class FlowTrackerTests(unittest.TestCase):
    def tuple(self, source: int = 1, destination: int = 2) -> FiveTuple:
        return FiveTuple(source, destination, 1000, 443, 6)

    def packet(self, tuple_: FiveTuple, data: bytes) -> Packet:
        return Packet(
            id=1,
            ts_sec=10,
            ts_usec=20,
            tuple=tuple_,
            data=data,
            tcp_flags=0,
            payload_offset=54,
            payload_length=len(data),
        )

    def test_new_flow_has_active_cpp_defaults(self):
        tracker = FlowTracker()
        flow = tracker.get_or_create(self.tuple())

        self.assertEqual(len(tracker), 1)
        self.assertEqual(flow.tuple, self.tuple())
        self.assertEqual(flow.app_type, AppType.UNKNOWN)
        self.assertEqual(flow.sni, "")
        self.assertEqual(flow.packets, 0)
        self.assertEqual(flow.bytes, 0)
        self.assertFalse(flow.blocked)
        self.assertFalse(flow.classified)

    def test_existing_flow_updates_packet_and_byte_counts(self):
        tracker = FlowTracker()
        tuple_ = self.tuple()

        first = tracker.update(self.packet(tuple_, b"abc"))
        second = tracker.update(self.packet(tuple_, b"12345"))

        self.assertIs(first, second)
        self.assertEqual(len(tracker), 1)
        self.assertEqual(second.packets, 2)
        self.assertEqual(second.bytes, 8)

    def test_reverse_tuple_is_a_separate_directional_flow(self):
        tracker = FlowTracker()
        forward = self.tuple()
        reverse = forward.reverse()

        tracker.update(self.packet(forward, b"forward"))
        tracker.update(self.packet(reverse, b"reverse"))

        self.assertEqual(len(tracker), 2)
        self.assertEqual(tracker.get_or_create(forward).packets, 1)
        self.assertEqual(tracker.get_or_create(reverse).packets, 1)
        self.assertIsNot(tracker.get_or_create(forward), tracker.get_or_create(reverse))

    def test_classification_and_sni_state_are_stored_on_flow(self):
        tracker = FlowTracker()
        flow = tracker.update(self.packet(self.tuple(), b"payload"))

        flow.app_type = AppType.YOUTUBE
        flow.sni = "www.youtube.com"
        flow.classified = True
        flow.blocked = True

        same_flow = tracker.get_or_create(self.tuple())
        self.assertIs(same_flow, flow)
        self.assertEqual(same_flow.app_type, AppType.YOUTUBE)
        self.assertEqual(same_flow.sni, "www.youtube.com")
        self.assertTrue(same_flow.classified)
        self.assertTrue(same_flow.blocked)

    def test_tracker_does_not_add_inactive_connection_features(self):
        tracker = FlowTracker()
        flow = tracker.get_or_create(self.tuple())

        self.assertFalse(hasattr(flow, "last_seen"))
        self.assertFalse(hasattr(flow, "first_seen"))
        self.assertFalse(hasattr(tracker, "cleanup_stale"))
        self.assertFalse(hasattr(tracker, "reverse_lookup"))


if __name__ == "__main__":
    unittest.main()
