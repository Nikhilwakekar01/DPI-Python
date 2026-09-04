"""Blocking rules matching the local Rules class in active dpi_mt.cpp."""

from __future__ import annotations

from threading import Lock

from .models import AppType, app_type_to_string, ip_to_int


class Rules:
    """Thread-safe source-IP, application, and domain substring rules."""

    def __init__(self) -> None:
        self._mutex = Lock()
        self._blocked_ips: set[int] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: list[str] = []

    def block_ip(self, ip: str) -> None:
        with self._mutex:
            self._blocked_ips.add(ip_to_int(ip))

    def block_app(self, app: str) -> None:
        with self._mutex:
            for value in range(AppType.APP_COUNT.value):
                app_type = AppType(value)
                if app_type_to_string(app_type) == app:
                    self._blocked_apps.add(app_type)
                    return

    def block_domain(self, domain: str) -> None:
        with self._mutex:
            self._blocked_domains.append(domain)

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        with self._mutex:
            if src_ip in self._blocked_ips:
                return True
            if app in self._blocked_apps:
                return True
            for domain in self._blocked_domains:
                if domain in sni:
                    return True
            return False

    # C++-style aliases retained for direct correspondence.
    blockIP = block_ip
    blockApp = block_app
    blockDomain = block_domain
    isBlocked = is_blocked


__all__ = ["Rules"]
