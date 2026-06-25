from __future__ import annotations

import socket
from pathlib import Path
from urllib.parse import urlparse

from .exceptions import OfflineGuardError


class OfflineGuard:
    """Application-level checks that prevent accidental remote runtime behavior."""

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict

    def reject_remote_input(self, value: str) -> None:
        parsed = urlparse(value)
        if parsed.scheme in {"http", "https", "ftp"}:
            raise OfflineGuardError("remote input sources are not allowed")

    def validate_local_model_path(self, value: str) -> Path:
        parsed = urlparse(value)
        if parsed.scheme:
            raise OfflineGuardError("remote model identifiers are not allowed")
        path = Path(value)
        if not path.is_absolute():
            raise OfflineGuardError("model paths must be absolute local paths")
        if not path.exists():
            raise OfflineGuardError("model path does not exist")
        return path

    def dns_appears_configured(self) -> bool:
        return Path("/etc/resolv.conf").exists()

    def default_route_appears_configured(self) -> bool:
        route = Path("/proc/net/route")
        if not route.exists():
            return False
        return "00000000" in route.read_text(encoding="utf-8", errors="ignore")

    def self_test(self) -> dict:
        result = {"strict": self.strict, "outbound_socket_blocked": None}
        if not self.strict:
            result["outbound_socket_blocked"] = False
            return result
        try:
            with socket.create_connection(("203.0.113.1", 9), timeout=0.25):
                result["outbound_socket_blocked"] = False
        except OSError:
            result["outbound_socket_blocked"] = True
        return result

