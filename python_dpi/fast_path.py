"""Synchronous active FastPath behavior from src/dpi_mt.cpp."""

from __future__ import annotations

from collections import defaultdict

from .classifier import classify_domain
from .extractors import HTTPHostExtractor, SNIExtractor
from .flow_tracker import FlowTracker
from .models import AppType, Packet, FlowEntry
from .rules import Rules


class FastPath:
    """Process packets using the active C++ classification and rule order."""

    def __init__(self, rules: Rules, flow_tracker: FlowTracker | None = None) -> None:
        self.rules = rules
        self.flow_tracker = flow_tracker or FlowTracker()
        self.processed = 0
        self.forwarded = 0
        self.dropped = 0
        self.app_counts: dict[AppType, int] = defaultdict(int)
        self.detected_snis: dict[str, AppType] = {}
        self.forwarded_packets: list[Packet] = []

    def process_packet(self, packet: Packet) -> bool:
        """Process one packet and return True when the active path forwards it."""
        self.processed += 1
        flow = self.flow_tracker.update(packet)

        if not flow.classified:
            self._classify_flow(packet, flow)

        if not flow.blocked:
            flow.blocked = self.rules.is_blocked(
                packet.tuple.src_ip,
                flow.app_type,
                flow.sni,
            )

        self.app_counts[flow.app_type] += 1
        if flow.sni:
            self.detected_snis[flow.sni] = flow.app_type

        if flow.blocked:
            self.dropped += 1
            return False

        self.forwarded += 1
        self.forwarded_packets.append(packet)
        return True

    def _classify_flow(self, packet: Packet, flow: FlowEntry) -> None:
        payload = packet.data[
            packet.payload_offset:packet.payload_offset + packet.payload_length
        ]

        if packet.tuple.dst_port == 443 and packet.payload_length > 5:
            sni = SNIExtractor.extract(payload, packet.payload_length)
            if sni is not None:
                flow.sni = sni
                flow.app_type = classify_domain(sni)
                flow.classified = True
                return

        if packet.tuple.dst_port == 80 and packet.payload_length > 10:
            host = HTTPHostExtractor.extract(payload, packet.payload_length)
            if host is not None:
                flow.sni = host
                flow.app_type = classify_domain(host)
                flow.classified = True
                return

        if packet.tuple.dst_port == 53 or packet.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        if packet.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif packet.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP

    process = process_packet


__all__ = ["FastPath"]
