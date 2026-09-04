import unittest

from python_dpi.fast_path import FastPath
from python_dpi.load_balancer import LoadBalancer
from python_dpi.models import FiveTuple, Packet, tuple_hash
from python_dpi.rules import Rules


class LoadBalancerTests(unittest.TestCase):
    def make_fast_paths(self, count: int) -> list[FastPath]:
        return [FastPath(Rules()) for _ in range(count)]

    def packet(self, tuple_: FiveTuple) -> Packet:
        return Packet(1, 10, 20, tuple_, b"data", 0, 0, 4)

    def test_number_of_fast_paths_and_constants(self):
        fast_paths = self.make_fast_paths(4)
        balancer = LoadBalancer(2, fast_paths)

        self.assertEqual(balancer.id, 2)
        self.assertEqual(balancer.num_fast_paths, 4)
        self.assertEqual(balancer.fast_paths, fast_paths)
        self.assertEqual(balancer.QUEUE_SIZE, 10000)
        self.assertEqual(balancer.POP_TIMEOUT_MS, 100)

    def test_same_tuple_always_selects_same_fast_path(self):
        fast_paths = self.make_fast_paths(4)
        balancer = LoadBalancer(0, fast_paths)
        tuple_ = FiveTuple(1, 2, 1000, 443, 6)

        selected = [balancer.select_fast_path(self.packet(tuple_)) for _ in range(20)]
        self.assertTrue(all(worker is selected[0] for worker in selected))
        self.assertEqual(balancer.select_index(tuple_), tuple_hash(tuple_) % 4)

    def test_different_tuples_can_select_different_fast_paths(self):
        fast_paths = self.make_fast_paths(4)
        balancer = LoadBalancer(0, fast_paths)
        selected = {
            balancer.select_index(FiveTuple(source, source + 1, 1000 + source, 443, 6))
            for source in range(1, 30)
        }
        self.assertGreater(len(selected), 1)

    def test_reverse_tuple_uses_directional_hashing(self):
        fast_paths = self.make_fast_paths(4)
        balancer = LoadBalancer(0, fast_paths)
        tuple_ = FiveTuple(1, 2, 1000, 443, 6)
        reverse = tuple_.reverse()

        self.assertEqual(balancer.select_index(tuple_), tuple_hash(tuple_) % 4)
        self.assertEqual(balancer.select_index(reverse), tuple_hash(reverse) % 4)
        self.assertNotEqual(balancer.select_index(tuple_), balancer.select_index(reverse))

    def test_mapping_is_deterministic_without_builtin_hash(self):
        fast_paths = self.make_fast_paths(3)
        balancer = LoadBalancer(0, fast_paths)
        tuple_ = FiveTuple(0xC0A8010A, 0x0A000001, 54321, 443, 6)

        expected = tuple_hash(tuple_) % 3
        self.assertEqual([balancer.select_index(tuple_) for _ in range(10)], [expected] * 10)

    def test_dispatch_preserves_packet_and_selected_worker(self):
        fast_paths = self.make_fast_paths(2)
        balancer = LoadBalancer(0, fast_paths)
        packet = self.packet(FiveTuple(1, 2, 1000, 443, 6))

        selected = balancer.dispatch(packet)

        self.assertIs(selected, balancer.dispatches[0][0])
        self.assertIs(packet, balancer.dispatches[0][1])
        self.assertEqual(balancer.dispatched, 1)
        self.assertEqual(selected.processed, 0)

    def test_single_fast_path_always_selects_zero(self):
        fast_path = self.make_fast_paths(1)[0]
        balancer = LoadBalancer(0, [fast_path])
        self.assertEqual(balancer.select_index(FiveTuple(1, 2, 1, 2, 17)), 0)
        self.assertIs(balancer.select_fast_path(self.packet(FiveTuple(9, 8, 7, 6, 6))), fast_path)

    def test_zero_fast_paths_preserve_modulo_failure(self):
        balancer = LoadBalancer(0, [])
        with self.assertRaises(ZeroDivisionError):
            balancer.select_index(FiveTuple(1, 2, 1, 2, 6))
        with self.assertRaises(ZeroDivisionError):
            balancer.dispatch(self.packet(FiveTuple(1, 2, 1, 2, 6)))

    def test_no_round_robin_state_is_used(self):
        fast_paths = self.make_fast_paths(3)
        balancer = LoadBalancer(0, fast_paths)
        tuple_ = FiveTuple(1, 2, 1, 2, 6)
        first = balancer.select_index(tuple_)
        second_tuple = FiveTuple(3, 4, 3, 4, 6)
        balancer.select_index(second_tuple)
        self.assertEqual(balancer.select_index(tuple_), first)


if __name__ == "__main__":
    unittest.main()
