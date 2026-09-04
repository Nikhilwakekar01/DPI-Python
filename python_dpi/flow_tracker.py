"""Minimal active-engine flow map behavior from dpi_mt.cpp."""

from __future__ import annotations

from .models import FlowEntry, FiveTuple, Packet


class FlowTracker:
    """Own directional FiveTuple-to-FlowEntry state for one fast path."""

    def __init__(self) -> None:
        self.flows: dict[FiveTuple, FlowEntry] = {}

    def get_or_create(self, tuple_: FiveTuple) -> FlowEntry:
        flow = self.flows.get(tuple_)
        if flow is None:
            flow = FlowEntry(tuple_)
            self.flows[tuple_] = flow
        return flow

    def update(self, packet: Packet) -> FlowEntry:
        """Apply the active C++ per-packet flow count and byte update."""
        flow = self.get_or_create(packet.tuple)
        flow.packets += 1
        flow.bytes += len(packet.data)
        return flow

    def __len__(self) -> int:
        return len(self.flows)


__all__ = ["FlowTracker"]
