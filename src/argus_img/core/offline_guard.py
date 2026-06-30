from __future__ import annotations

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

    def _any_interface_up(self) -> bool:
        """Passively check whether any non-loopback network interface is UP."""
        net_dir = Path("/sys/class/net")
        if not net_dir.exists():
            # Non-Linux (e.g. macOS): conservatively report unknown as True.
            return True
        for iface in net_dir.iterdir():
            if iface.name == "lo":
                continue
            state_file = iface / "operstate"
            try:
                if state_file.read_text(encoding="utf-8").strip() == "up":
                    return True
            except OSError:
                continue
        return False

    def self_test(self) -> dict:
        """Return passive network-isolation indicators — never makes outbound connections."""
        dns = self.dns_appears_configured()
        route = self.default_route_appears_configured()
        iface_up = self._any_interface_up()
        # outbound_socket_blocked: True when all passive indicators suggest no
        # outbound path.  False when any indicator suggests connectivity exists.
        # None when the check cannot be performed (non-Linux without /proc/net).
        if not self.strict:
            outbound_blocked = None
        else:
            outbound_blocked = not (dns or route or iface_up)
        return {
            "strict": self.strict,
            "dns_configured": dns,
            "default_route_present": route,
            "interface_up": iface_up,
            "outbound_socket_blocked": outbound_blocked,
        }

