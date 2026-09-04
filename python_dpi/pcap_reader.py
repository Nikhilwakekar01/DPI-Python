"""Classic PCAP reader matching the active C++ implementation."""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import BinaryIO, Optional

from .models import PcapGlobalHeader, PcapPacketHeader, RawPacket


PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
GLOBAL_HEADER_SIZE = 24
PACKET_HEADER_SIZE = 16


class PcapReader:
    """Read classic Ethernet PCAP files without interpreting packet payloads."""

    def __init__(self) -> None:
        self._file: Optional[BinaryIO] = None
        self._global_header: Optional[PcapGlobalHeader] = None
        self._needs_byte_swap = False

    def open(self, filename: str | Path) -> bool:
        """Open and validate a PCAP file, returning False on C++-style failure."""
        self.close()

        try:
            file = open(filename, "rb")
        except OSError:
            return False

        raw_header = file.read(GLOBAL_HEADER_SIZE)
        if len(raw_header) != GLOBAL_HEADER_SIZE:
            file.close()
            return False

        native_format = "<" if sys.byteorder == "little" else ">"
        fields = struct.unpack(native_format + "IHH iIII", raw_header)
        magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network = fields

        if magic_number == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
        elif magic_number == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            version_major = self.maybe_swap16(version_major)
            version_minor = self.maybe_swap16(version_minor)
            snaplen = self.maybe_swap32(snaplen)
            network = self.maybe_swap32(network)
        else:
            file.close()
            self._needs_byte_swap = False
            return False

        self._file = file
        self._global_header = PcapGlobalHeader(
            magic_number=magic_number,
            version_major=version_major,
            version_minor=version_minor,
            thiszone=thiszone,
            sigfigs=sigfigs,
            snaplen=snaplen,
            network=network,
        )
        return True

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
        self._file = None
        self._needs_byte_swap = False

    def read_next_packet(self) -> Optional[RawPacket]:
        """Read one packet, returning None at EOF or on a read/length failure."""
        if self._file is None or self._global_header is None:
            return None

        raw_header = self._file.read(PACKET_HEADER_SIZE)
        if len(raw_header) != PACKET_HEADER_SIZE:
            return None

        native_format = "<" if sys.byteorder == "little" else ">"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            native_format + "IIII", raw_header
        )

        if self._needs_byte_swap:
            ts_sec = self.maybe_swap32(ts_sec)
            ts_usec = self.maybe_swap32(ts_usec)
            incl_len = self.maybe_swap32(incl_len)
            orig_len = self.maybe_swap32(orig_len)

        if incl_len > self._global_header.snaplen or incl_len > 65535:
            return None

        data = self._file.read(incl_len)
        if len(data) != incl_len:
            return None

        return RawPacket(
            header=PcapPacketHeader(
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                incl_len=incl_len,
                orig_len=orig_len,
            ),
            data=data,
        )

    def get_global_header(self) -> Optional[PcapGlobalHeader]:
        return self._global_header

    def is_open(self) -> bool:
        return self._file is not None and not self._file.closed

    def needs_byte_swap(self) -> bool:
        return self._needs_byte_swap

    def maybe_swap16(self, value: int) -> int:
        if not self._needs_byte_swap:
            return value
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8)

    def maybe_swap32(self, value: int) -> int:
        if not self._needs_byte_swap:
            return value
        return (
            ((value & 0xFF000000) >> 24)
            | ((value & 0x00FF0000) >> 8)
            | ((value & 0x0000FF00) << 8)
            | ((value & 0x000000FF) << 24)
        )

    # C++-style method names retained for direct API correspondence.
    def readNextPacket(self) -> Optional[RawPacket]:
        return self.read_next_packet()

    def getGlobalHeader(self) -> Optional[PcapGlobalHeader]:
        return self.get_global_header()

    def isOpen(self) -> bool:
        return self.is_open()

    def needsByteSwap(self) -> bool:
        return self.needs_byte_swap()

    def maybeSwap16(self, value: int) -> int:
        return self.maybe_swap16(value)

    def maybeSwap32(self, value: int) -> int:
        return self.maybe_swap32(value)

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


__all__ = [
    "GLOBAL_HEADER_SIZE",
    "PACKET_HEADER_SIZE",
    "PCAP_MAGIC_NATIVE",
    "PCAP_MAGIC_SWAPPED",
    "PcapReader",
]
