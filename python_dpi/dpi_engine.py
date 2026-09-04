"""Active dpi_mt.cpp orchestration implemented with Python threads."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import struct
import threading
import time
from pathlib import Path
from typing import Optional

from .fast_path import FastPath
from .flow_tracker import FlowTracker
from .load_balancer import LoadBalancer
from .models import AppType, Packet, ParsedPacket, ip_to_int, tuple_hash
from .packet_parser import PacketParser
from .pcap_reader import PcapReader
from .rules import Rules


@dataclass
class EngineConfig:
    num_lbs: int = 2
    fps_per_lb: int = 2
    queue_size: int = 10000


@dataclass
class EngineStats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded: int = 0
    dropped: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    app_counts: dict[AppType, int] = field(default_factory=dict)
    detected_snis: dict[str, AppType] = field(default_factory=dict)


class _BoundedQueue:
    """Private TSQueue equivalent used only by the active engine."""

    def __init__(self, max_size: int) -> None:
        self._items: deque[Packet] = deque()
        self._max_size = max_size
        self._shutdown = False
        self._condition = threading.Condition()

    def push(self, item: Packet) -> None:
        with self._condition:
            self._condition.wait_for(
                lambda: len(self._items) < self._max_size or self._shutdown
            )
            if self._shutdown:
                return
            self._items.append(item)
            self._condition.notify_all()

    def pop(self, timeout_ms: int) -> Optional[Packet]:
        with self._condition:
            ready = self._condition.wait_for(
                lambda: bool(self._items) or self._shutdown,
                timeout_ms / 1000.0,
            )
            if not ready or not self._items:
                return None
            item = self._items.popleft()
            self._condition.notify_all()
            return item

    def shutdown(self) -> None:
        with self._condition:
            self._shutdown = True
            self._condition.notify_all()

    def size(self) -> int:
        with self._condition:
            return len(self._items)


class DPIEngine:
    """End-to-end active dpi_mt.cpp pipeline."""

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig()
        self.rules = Rules()
        self.stats = EngineStats()
        self.fast_paths: list[FastPath] = []
        self.load_balancers: list[LoadBalancer] = []
        self._lb_queues: list[_BoundedQueue] = []
        self._fp_queues: list[_BoundedQueue] = []
        self._lb_threads: list[threading.Thread] = []
        self._fp_threads: list[threading.Thread] = []
        self._writer_thread: threading.Thread | None = None
        self._output_queue = _BoundedQueue(self.config.queue_size)
        self._running = False
        self._output_running = False
        self.initialize()

    def initialize(self) -> bool:
        total_fast_paths = self.config.num_lbs * self.config.fps_per_lb
        self.fast_paths = [FastPath(self.rules, FlowTracker()) for _ in range(total_fast_paths)]
        self.load_balancers = []
        self._lb_queues = []
        self._fp_queues = [_BoundedQueue(self.config.queue_size) for _ in self.fast_paths]
        self._output_queue = _BoundedQueue(self.config.queue_size)

        for lb_id in range(self.config.num_lbs):
            start = lb_id * self.config.fps_per_lb
            workers = self.fast_paths[start:start + self.config.fps_per_lb]
            self.load_balancers.append(LoadBalancer(lb_id, workers))
            self._lb_queues.append(_BoundedQueue(self.config.queue_size))
        return True

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rules.block_app(app)

    def block_domain(self, domain: str) -> None:
        self.rules.block_domain(domain)

    def process(self, input_file: str | Path, output_file: str | Path) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        try:
            output = open(output_file, "wb")
        except OSError:
            reader.close()
            return False

        try:
            header = reader.get_global_header()
            if header is None:
                return False
            output.write(
                struct.pack(
                    "=IHH iIII",
                    header.magic_number,
                    header.version_major,
                    header.version_minor,
                    header.thiszone,
                    header.sigfigs,
                    header.snaplen,
                    header.network,
                )
            )

            self.stats = EngineStats()
            self._running = True
            self._output_running = True
            self._start_workers(output)

            packet_id = 0
            while True:
                raw = reader.read_next_packet()
                if raw is None:
                    break

                parsed = ParsedPacket()
                if not PacketParser.parse(raw, parsed):
                    continue
                if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                    continue

                packet = self._create_packet(raw, parsed, packet_id)
                packet_id += 1
                self.stats.total_packets += 1
                self.stats.total_bytes += len(packet.data)
                if parsed.has_tcp:
                    self.stats.tcp_packets += 1
                elif parsed.has_udp:
                    self.stats.udp_packets += 1

                lb_index = tuple_hash(packet.tuple) % len(self.load_balancers)
                self._lb_queues[lb_index].push(packet)

            # This delay is intentionally retained from the C++ implementation.
            time.sleep(0.5)
        finally:
            reader.close()
            self._stop_workers()
            output.close()
            self._collect_fast_path_stats()

        return True

    def _create_packet(self, raw, parsed: ParsedPacket, packet_id: int) -> Packet:
        tuple_ = (
            ip_to_int(parsed.src_ip),
            ip_to_int(parsed.dest_ip),
            parsed.src_port,
            parsed.dest_port,
            parsed.protocol,
        )
        from .models import FiveTuple

        flow_tuple = FiveTuple(*tuple_)
        payload_offset = 14
        data = raw.data
        if len(data) > 14:
            ip_ihl = data[14] & 0x0F
            payload_offset += ip_ihl * 4
            if parsed.has_tcp and payload_offset + 12 < len(data):
                tcp_offset = (data[payload_offset + 12] >> 4) & 0x0F
                payload_offset += tcp_offset * 4
            elif parsed.has_udp:
                payload_offset += 8

        payload_length = len(data) - payload_offset if payload_offset < len(data) else 0
        return Packet(
            id=packet_id,
            ts_sec=raw.header.ts_sec,
            ts_usec=raw.header.ts_usec,
            tuple=flow_tuple,
            data=data,
            tcp_flags=parsed.tcp_flags,
            payload_offset=payload_offset,
            payload_length=payload_length,
        )

    def _start_workers(self, output) -> None:
        self._lb_threads = []
        self._fp_threads = []

        for index, lb in enumerate(self.load_balancers):
            thread = threading.Thread(
                target=self._run_load_balancer,
                args=(index, lb),
                name=f"lb-{index}",
            )
            thread.start()
            self._lb_threads.append(thread)

        for index, fast_path in enumerate(self.fast_paths):
            thread = threading.Thread(
                target=self._run_fast_path,
                args=(index, fast_path),
                name=f"fp-{index}",
            )
            thread.start()
            self._fp_threads.append(thread)

        self._writer_thread = threading.Thread(
            target=self._run_writer,
            args=(output,),
            name="output-writer",
        )
        self._writer_thread.start()

    def _run_load_balancer(self, index: int, load_balancer: LoadBalancer) -> None:
        while self._running:
            packet = self._lb_queues[index].pop(100)
            if packet is None:
                continue
            fast_path = load_balancer.dispatch(packet)
            fp_index = self.fast_paths.index(fast_path)
            self._fp_queues[fp_index].push(packet)

    def _run_fast_path(self, index: int, fast_path: FastPath) -> None:
        while self._running:
            packet = self._fp_queues[index].pop(100)
            if packet is None:
                continue
            if fast_path.process_packet(packet):
                self._output_queue.push(packet)

    def _run_writer(self, output) -> None:
        while self._output_running or self._output_queue.size() > 0:
            packet = self._output_queue.pop(50)
            if packet is None:
                continue
            output.write(
                struct.pack(
                    "=IIII",
                    packet.ts_sec,
                    packet.ts_usec,
                    len(packet.data),
                    len(packet.data),
                )
            )
            output.write(packet.data)

    def _stop_workers(self) -> None:
        self._running = False
        for queue in self._lb_queues:
            queue.shutdown()
        for thread in self._lb_threads:
            thread.join()

        for queue in self._fp_queues:
            queue.shutdown()
        for thread in self._fp_threads:
            thread.join()

        self._output_running = False
        self._output_queue.shutdown()
        if self._writer_thread is not None:
            self._writer_thread.join()

    def _collect_fast_path_stats(self) -> None:
        self.stats.forwarded = sum(fp.forwarded for fp in self.fast_paths)
        self.stats.dropped = sum(fp.dropped for fp in self.fast_paths)
        for fast_path in self.fast_paths:
            for app, count in fast_path.app_counts.items():
                self.stats.app_counts[app] = self.stats.app_counts.get(app, 0) + count
            self.stats.detected_snis.update(fast_path.detected_snis)


__all__ = ["DPIEngine", "EngineConfig", "EngineStats"]
