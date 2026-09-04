"""Synchronous active LoadBalancer selection from src/dpi_mt.cpp."""

from __future__ import annotations

from .fast_path import FastPath
from .models import Packet, FiveTuple, tuple_hash


class LoadBalancer:
    """Select a FastPath using deterministic directional FiveTuple hashing."""

    QUEUE_SIZE = 10000
    POP_TIMEOUT_MS = 100

    def __init__(self, load_balancer_id: int, fast_paths: list[FastPath]) -> None:
        self.id = load_balancer_id
        self.fast_paths = list(fast_paths)
        self.num_fast_paths = len(self.fast_paths)
        self.dispatched = 0
        self.dispatches: list[tuple[FastPath, Packet]] = []

    def select_index(self, tuple_: FiveTuple) -> int:
        """Return the active C++ hash modulo assignment index."""
        return tuple_hash(tuple_) % self.num_fast_paths

    def select_fast_path(self, packet: Packet) -> FastPath:
        return self.fast_paths[self.select_index(packet.tuple)]

    def dispatch(self, packet: Packet) -> FastPath:
        """Record one queue dispatch and return its selected FastPath.

        The active C++ method pushes into the selected FastPath queue. This
        synchronous abstraction records that handoff without starting workers.
        """
        fast_path = self.select_fast_path(packet)
        self.dispatches.append((fast_path, packet))
        self.dispatched += 1
        return fast_path


__all__ = ["LoadBalancer"]
