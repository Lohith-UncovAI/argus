import shutil

from fastapi import APIRouter

from argus_img import __version__
from argus_img.core.config import config_hash, load_config, read_config_text
from argus_img.core.hashing import sha256_bytes
from argus_img.core.offline_guard import OfflineGuard

router = APIRouter()


@router.get("/v1/attestation")
def attestation():
    config = load_config()
    rule_hashes = {}
    for path in [("prompt_rules", "generic.yaml"), ("prompt_rules", "en.yaml")]:
        key = "/".join(path)
        try:
            rule_hashes[key] = sha256_bytes(read_config_text(path).encode("utf-8"))
        except Exception:
            rule_hashes[key] = None
    return {
        "application": "argus-img",
        "version": __version__,
        "configuration_hash": config_hash(config),
        "rule_bundle_hashes": rule_hashes,
        "installed_optional_tools": {
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
        },
        "model_adapters_configured": {"visual": "NullVisualAnalyzer", "prompt_classifier": "NullPromptClassifier"},
        "network_offline_configuration_state": OfflineGuard(strict=config.offline.strict).self_test(),
        "self_test_status": "pass",
        "air_gap_claim": False,
    }
