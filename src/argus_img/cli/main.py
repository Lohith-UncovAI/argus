from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from argus_img.core.config import config_hash, load_config
from argus_img.core.enums import ScanMode, UseProfile
from argus_img.core.models import ScanRequest
from argus_img.core.offline_guard import OfflineGuard
from argus_img.detectors.prompt.rules import PromptRuleBundle
from argus_img.orchestration.pipeline import scan_file
from argus_img.reporting.serialization import report_to_json

try:
    import typer  # type: ignore
except Exception:  # pragma: no cover - fallback is exercised when Typer is absent
    typer = None


def _scan(path: str, mode: str, profile: str, output: Optional[str], include_raw_text: bool = False) -> None:
    request = ScanRequest(
        original_filename=Path(path).name,
        mode=ScanMode(mode),
        use_profile=UseProfile(profile),
        include_raw_text=include_raw_text,
    )
    report = scan_file(Path(path), request)
    payload = report_to_json(report)
    if output:
        Path(output).write_text(payload, encoding="utf-8")
    else:
        print(payload)


def _capabilities() -> None:
    from argus_img.api.routes.capabilities import capabilities

    print(json.dumps(capabilities(), indent=2, sort_keys=True))


def _health() -> None:
    print(json.dumps({"status": "ok", "offline_mode": True, "gpu_required": False}, indent=2))


def _verify_offline() -> None:
    config = load_config()
    print(json.dumps(OfflineGuard(strict=config.offline.strict).self_test(), indent=2, sort_keys=True))


def _validate_config() -> None:
    config = load_config()
    print(json.dumps({"status": "ok", "configuration_hash": config_hash(config)}, indent=2))


def _validate_rules() -> None:
    bundle = PromptRuleBundle.load_default()
    print(json.dumps({"status": "ok", "rules": len(bundle.rules)}, indent=2))


def _argparse_main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="argus-img")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("path")
    scan.add_argument("--mode", choices=[mode.value for mode in ScanMode], default="fast")
    scan.add_argument("--profile", choices=[profile.value for profile in UseProfile], default=UseProfile.AGENT_WITH_TOOLS.value)
    scan.add_argument("--output")
    scan.add_argument("--include-raw-text", action="store_true")
    sub.add_parser("capabilities")
    sub.add_parser("health")
    sub.add_parser("verify-offline")
    sub.add_parser("validate-config")
    sub.add_parser("validate-rules")
    args = parser.parse_args(argv)
    if args.command == "scan":
        _scan(args.path, args.mode, args.profile, args.output, args.include_raw_text)
    elif args.command == "capabilities":
        _capabilities()
    elif args.command == "health":
        _health()
    elif args.command == "verify-offline":
        _verify_offline()
    elif args.command == "validate-config":
        _validate_config()
    elif args.command == "validate-rules":
        _validate_rules()


if typer is not None:
    app = typer.Typer(help="ARGUS-IMG offline image-security analyzer")

    @app.command()
    def scan(
        path: str,
        mode: str = "fast",
        profile: str = UseProfile.AGENT_WITH_TOOLS.value,
        output: Optional[str] = None,
        include_raw_text: bool = False,
    ) -> None:
        _scan(path, mode, profile, output, include_raw_text)

    @app.command()
    def capabilities() -> None:
        _capabilities()

    @app.command()
    def health() -> None:
        _health()

    @app.command("verify-offline")
    def verify_offline() -> None:
        _verify_offline()

    @app.command("validate-config")
    def validate_config() -> None:
        _validate_config()

    @app.command("validate-rules")
    def validate_rules() -> None:
        _validate_rules()


def main() -> None:
    _argparse_main()


if __name__ == "__main__":
    main()
