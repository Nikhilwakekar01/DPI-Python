from __future__ import annotations

import ipaddress

import pydivert

from python_dpi.fast_path import FastPath
from python_dpi.models import (
    AppType,
    FiveTuple,
    Packet,
)
from python_dpi.rules import Rules


# ============================================================
# RULES
# ============================================================

rules = Rules()

# TEST RULE:
# Google domain ko block karega.
rules.block_domain("otel.cline.bot")


# ============================================================
# DPI FAST PATH
# ============================================================

fast_path = FastPath(rules)


# ============================================================
# STATISTICS
# ============================================================

total_seen = 0
non_ipv4 = 0
non_tcp_udp = 0
parse_errors = 0


# ============================================================
# HELPERS
# ============================================================

def ipv4_to_int_from_bytes(data: bytes) -> int:
    """Convert network-order IPv4 bytes to the C++ compatible integer."""
    return (
        data[0]
        | (data[1] << 8)
        | (data[2] << 16)
        | (data[3] << 24)
    )


def parse_win_divert_packet(raw: bytes, packet_id: int) -> Packet | None:
    """
    Convert a WinDivert network-layer IPv4 TCP/UDP packet
    into the existing Python DPI Packet model.

    WinDivert gives us the IP packet directly, without Ethernet.
    """

    # --------------------------------------------------------
    # Minimum IPv4 header
    # --------------------------------------------------------

    if len(raw) < 20:
        return None

    version = raw[0] >> 4

    if version != 4:
        return None

    ihl = (raw[0] & 0x0F) * 4

    if ihl < 20 or len(raw) < ihl:
        return None

    # --------------------------------------------------------
    # IPv4 addresses
    # --------------------------------------------------------

    src_ip = ipv4_to_int_from_bytes(raw[12:16])
    dst_ip = ipv4_to_int_from_bytes(raw[16:20])

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    protocol = raw[9]

    if protocol not in (6, 17):
        return None

    # --------------------------------------------------------
    # Transport header
    # --------------------------------------------------------

    transport_offset = ihl

    if len(raw) < transport_offset + 4:
        return None

    src_port = int.from_bytes(
        raw[transport_offset:transport_offset + 2],
        "big",
    )

    dst_port = int.from_bytes(
        raw[transport_offset + 2:transport_offset + 4],
        "big",
    )

    tcp_flags = 0

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if protocol == 6:

        if len(raw) < transport_offset + 20:
            return None

        tcp_header_length = (
            ((raw[transport_offset + 12] >> 4) & 0x0F) * 4
        )

        if tcp_header_length < 20:
            return None

        if len(raw) < transport_offset + tcp_header_length:
            return None

        tcp_flags = raw[transport_offset + 13]

        payload_offset = transport_offset + tcp_header_length

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    else:

        if len(raw) < transport_offset + 8:
            return None

        payload_offset = transport_offset + 8

    # --------------------------------------------------------
    # Payload
    # --------------------------------------------------------

    payload_length = len(raw) - payload_offset

    if payload_length < 0:
        return None

    # --------------------------------------------------------
    # Five Tuple
    # --------------------------------------------------------

    tuple_ = FiveTuple(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )

    # --------------------------------------------------------
    # Existing Packet model
    # --------------------------------------------------------

    return Packet(
        id=packet_id,
        ts_sec=0,
        ts_usec=0,
        tuple=tuple_,
        data=raw,
        tcp_flags=tcp_flags,
        payload_offset=payload_offset,
        payload_length=payload_length,
    )


# ============================================================
# MAIN LIVE DPI
# ============================================================

print("====================================")
print("       LIVE PYTHON DPI")
print("====================================")
print("Monitoring IPv4 TCP/UDP traffic...")
print("YouTube blocking rule: youtube.com")
print("Press Ctrl+C to stop.\n")


packet_id = 0

try:

    # Only capture IPv4 TCP/UDP.
    with pydivert.WinDivert("ip and (tcp or udp)") as w:

        for divert_packet in w:

            total_seen += 1

            try:

                raw = bytes(divert_packet.raw)

                packet = parse_win_divert_packet(
                    raw,
                    packet_id,
                )

                packet_id += 1

                # ------------------------------------------------
                # Packet is IPv6 / malformed / non TCP-UDP
                # ------------------------------------------------

                if packet is None:

                    # Fail open.
                    w.send(divert_packet)
                    continue

                # ------------------------------------------------
                # Existing FastPath
                # ------------------------------------------------

                before_dropped = fast_path.dropped
                before_forwarded = fast_path.forwarded

                should_forward = fast_path.process_packet(packet)

                # ------------------------------------------------
                # New drop
                # ------------------------------------------------

                if fast_path.dropped > before_dropped:

                    flow = fast_path.flow_tracker.flows.get(
                        packet.tuple
                    )

                    if flow is not None:

                        print(
                            f"[DROP] "
                            f"{flow.sni or 'unknown'} | "
                            f"{flow.app_type.name} | "
                            f"{packet.tuple.to_string()}"
                        )

                    continue

                # ------------------------------------------------
                # Forward
                # ------------------------------------------------

                if should_forward:

                    # Print newly detected SNI/application.
                    flow = fast_path.flow_tracker.flows.get(
                        packet.tuple
                    )

                    if flow is not None and flow.classified:

                        # Only print when this packet contains
                        # useful classification information.
                        if flow.sni:

                            print(
                                f"[DETECTED] "
                                f"{flow.sni} | "
                                f"{flow.app_type.name}"
                            )

                    w.send(divert_packet)

                else:

                    # Safety fallback.
                    continue

            except Exception as exc:

                parse_errors += 1

                print(
                    f"Packet processing error: {exc}"
                )

                # Fail open.
                w.send(divert_packet)


except KeyboardInterrupt:

    print("\nStopping DPI...")


# ============================================================
# SUMMARY
# ============================================================

print("\n========== SUMMARY ==========")

print(f"Packets seen : {total_seen}")
print(f"Processed    : {fast_path.processed}")
print(f"Forwarded    : {fast_path.forwarded}")
print(f"Dropped      : {fast_path.dropped}")
print(f"Parse errors : {parse_errors}")

print("\nDetected applications:")

for app, count in sorted(
    fast_path.app_counts.items(),
    key=lambda item: item[0].name,
):

    print(f"  {app.name}: {count}")

print("\nDetected SNIs:")

for sni, app in sorted(
    fast_path.detected_snis.items()
):

    print(f"  {sni} -> {app.name}")

print("=============================")