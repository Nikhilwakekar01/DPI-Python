"""TLS, HTTP, DNS, and simplified QUIC extractors matching the C++ code."""

from __future__ import annotations

from typing import Optional


class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @staticmethod
    def readUint16BE(data: bytes) -> int:
        return (data[0] << 8) | data[1]

    @staticmethod
    def readUint24BE(data: bytes) -> int:
        return (data[0] << 16) | (data[1] << 8) | data[2]

    @staticmethod
    def isTLSClientHello(payload: bytes, length: Optional[int] = None) -> bool:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if length < 9:
            return False
        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False

        version = SNIExtractor.readUint16BE(payload[1:3])
        if version < 0x0300 or version > 0x0304:
            return False

        record_length = SNIExtractor.readUint16BE(payload[3:5])
        if record_length > length - 5:
            return False
        return payload[5] == SNIExtractor.HANDSHAKE_CLIENT_HELLO

    @staticmethod
    def extract(payload: bytes, length: Optional[int] = None) -> Optional[str]:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if not SNIExtractor.isTLSClientHello(payload, length):
            return None

        offset = 5
        if offset + 4 > length:
            return None
        _handshake_length = SNIExtractor.readUint24BE(payload[offset + 1:offset + 4])
        offset += 4

        offset += 2 + 32
        if offset >= length:
            return None

        session_id_length = payload[offset]
        offset += 1 + session_id_length

        if offset + 2 > length:
            return None
        cipher_suites_length = SNIExtractor.readUint16BE(payload[offset:offset + 2])
        offset += 2 + cipher_suites_length

        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        if offset + 2 > length:
            return None
        extensions_length = SNIExtractor.readUint16BE(payload[offset:offset + 2])
        offset += 2
        extensions_end = min(offset + extensions_length, length)

        while offset + 4 <= extensions_end:
            extension_type = SNIExtractor.readUint16BE(payload[offset:offset + 2])
            extension_length = SNIExtractor.readUint16BE(payload[offset + 2:offset + 4])
            offset += 4

            if offset + extension_length > extensions_end:
                break

            if extension_type == SNIExtractor.EXTENSION_SNI:
                if extension_length < 5:
                    break
                sni_list_length = SNIExtractor.readUint16BE(payload[offset:offset + 2])
                if sni_list_length < 3:
                    break
                sni_type = payload[offset + 2]
                sni_length = SNIExtractor.readUint16BE(payload[offset + 3:offset + 5])
                if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME:
                    break
                if sni_length > extension_length - 5:
                    break
                return payload[offset + 5:offset + 5 + sni_length].decode("latin-1")

            offset += extension_length

        return None

    @staticmethod
    def extractExtensions(
        payload: bytes, length: Optional[int] = None
    ) -> list[tuple[int, str]]:
        # The repository implementation is explicitly abbreviated and returns empty.
        return []

    read_uint16_be = readUint16BE
    read_uint24_be = readUint24BE
    is_tls_client_hello = isTLSClientHello
    extract_extensions = extractExtensions


class HTTPHostExtractor:
    @staticmethod
    def isHTTPRequest(payload: bytes, length: Optional[int] = None) -> bool:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if length < 4:
            return False
        methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
        return any(payload[:4] == method for method in methods)

    @staticmethod
    def extract(payload: bytes, length: Optional[int] = None) -> Optional[str]:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if not HTTPHostExtractor.isHTTPRequest(payload, length):
            return None

        for index in range(max(0, length - 6)):
            if index + 4 >= length:
                break
            if (
                payload[index] in (ord("H"), ord("h"))
                and payload[index + 1] in (ord("O"), ord("o"))
                and payload[index + 2] in (ord("S"), ord("s"))
                and payload[index + 3] in (ord("T"), ord("t"))
                and payload[index + 4] == ord(":")
            ):
                start = index + 5
                while start < length and payload[start] in (ord(" "), ord("\t")):
                    start += 1
                end = start
                while end < length and payload[end] not in (ord("\r"), ord("\n")):
                    end += 1
                if end > start:
                    host = payload[start:end].decode("latin-1")
                    colon_position = host.find(":")
                    if colon_position != -1:
                        host = host[:colon_position]
                    return host
        return None

    is_http_request = isHTTPRequest


class DNSExtractor:
    @staticmethod
    def isDNSQuery(payload: bytes, length: Optional[int] = None) -> bool:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if length < 12:
            return False
        if payload[2] & 0x80:
            return False
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount != 0

    @staticmethod
    def extractQuery(payload: bytes, length: Optional[int] = None) -> Optional[str]:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if not DNSExtractor.isDNSQuery(payload, length):
            return None

        offset = 12
        domain = ""
        while offset < length:
            label_length = payload[offset]
            if label_length == 0:
                break
            if label_length > 63:
                break
            offset += 1
            if offset + label_length > length:
                break
            if domain:
                domain += "."
            domain += payload[offset:offset + label_length].decode("latin-1")
            offset += label_length

        return domain if domain else None

    is_dns_query = isDNSQuery
    extract_query = extractQuery


class QUICSNIExtractor:
    @staticmethod
    def isQUICInitial(payload: bytes, length: Optional[int] = None) -> bool:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if length < 5:
            return False
        return (payload[0] & 0x80) != 0

    @staticmethod
    def extract(payload: bytes, length: Optional[int] = None) -> Optional[str]:
        payload = bytes(payload)
        length = len(payload) if length is None else min(length, len(payload))
        if not QUICSNIExtractor.isQUICInitial(payload, length):
            return None

        for index in range(length):
            if index + 50 >= length:
                break
            if payload[index] != 0x01 or index < 5:
                continue
            result = SNIExtractor.extract(payload[index - 5:], length - index + 5)
            if result is not None:
                return result
        return None

    is_quic_initial = isQUICInitial


__all__ = [
    "DNSExtractor",
    "HTTPHostExtractor",
    "QUICSNIExtractor",
    "SNIExtractor",
]
