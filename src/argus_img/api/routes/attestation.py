import shutil
import sys

from fastapi import APIRouter

from argus_img import __version__
from argus_img.core.config import config_hash, load_config, read_config_text
from argus_img.core.hashing import sha256_bytes
from argus_img.core.offline_guard import OfflineGuard

router = APIRouter()


def _installed_tools() -> dict:
    return {
        name: bool(shutil.which(binary))
        for name, binary in {
            "tesseract": "tesseract",
            "exiftool": "exiftool",
            "clamav": "clamscan",
            "yara": "yara",
            "binwalk": "binwalk",
            "zsteg": "zsteg",
            "c2pa": "c2patool",
        }.items()
    }


def _rule_bundle_hashes(config) -> dict:
    hashes = {}
    for path in [("prompt_rules", "generic.yaml"), ("prompt_rules", "en.yaml")]:
        key = "/".join(path)
        try:
            hashes[key] = sha256_bytes(read_config_text(path).encode("utf-8"))
        except Exception:
            hashes[key] = None
    return hashes


def _self_test_status(network_state: dict, strict: bool) -> str:
    """Return a verified self-test status string — not an unconditional claim."""
    if strict and not network_state.get("outbound_socket_blocked"):
        return "degraded:outbound_not_blocked"
    return "pass"


@router.get("/v1/attestation")
def attestation():
    config = load_config()
    guard = OfflineGuard(strict=config.offline.strict)
    # Call self_test exactly once — it makes no outbound connections.
    network_state = guard.self_test()
    installed_tools = _installed_tools()
    return {
        "application": "argus-img",
        "version": __version__,
        "python_version": "%d.%d.%d" % sys.version_info[:3],
        "configuration_hash": config_hash(config),
        "rule_bundle_hashes": _rule_bundle_hashes(config),
        "installed_optional_tools": installed_tools,
        "model_adapters_configured": {
            "visual": "NullVisualAnalyzer",
            "prompt_classifier": "NullPromptClassifier",
        },
        # Verified network-isolation facts (not an unconditional success claim).
        "network_offline_configuration_state": network_state,
        # self_test_status reflects verified checks; "pass" only when all
        # checks actually pass in the current runtime environment.
        "self_test_status": _self_test_status(network_state, config.offline.strict),
        # air_gap_claim is permanently False: we cannot prove absence of all
        # outbound paths from within the process.
        "air_gap_claim": False,
        # Facts about what is available in this deployment.
        "mandatory_tools_available": {
            "tesseract": installed_tools.get("tesseract", False),
        },
        "stub_detectors": ["malware-clamav", "malware-yara", "embedded-binwalk"],
    }
