#!/usr/bin/env python3
"""Run a fresh ARGUS-IMG evaluation into evaluation-results/latest/.

This entrypoint intentionally treats older evaluation folders as historical
artifacts.  It creates a timestamped run directory, uses a clean ARGUS_DATA_DIR
by default, records preflight state, runs the selected suite, and writes one
canonical summary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from argus_img.api.routes.capabilities import capabilities
from argus_img.artifacts.store import ArtifactStore
from argus_img.core.config import config_hash, load_config
from argus_img.core.enums import PolicyAction, ScanMode, UseProfile
from argus_img.core.models import ScanRequest
from argus_img.detectors.prompt.rules import PromptRuleBundle
from argus_img.orchestration.pipeline import scan_file
from argus_img.reporting.serialization import report_to_json


DEFAULT_CORPUS = Path("/Users/lohith-uncovai/argus-eval-data/corpus")
HISTORICAL_INPUTS = REPO_ROOT / "evaluation-results"
KNOWN_GAPS = [
    {
        "id": "default-store-over-quota",
        "status": "operational",
        "detail": (
            "The user-level evaluation store at "
            "/Users/lohith-uncovai/argus-eval-data/argus-store was observed over the "
            "default 10 GiB quota. Fresh evaluation runs should use the clean run-local "
            "ARGUS_DATA_DIR recorded in this summary."
        ),
    },
    {
        "id": "historical-eval-artifacts",
        "status": "documentation",
        "detail": (
            "random-dataset-20260707-argus, retest-previous-fail-cases-20260707-final, "
            "and more-diverse-20260707 are historical because their UNSUPPORTED results "
            "predate the ClamAV database fix."
        ),
    },
    {
        "id": "more_046-ocr-region",
        "status": "detector-gap",
        "detail": (
            "evaluation-results/more-diverse-20260707/inputs/more_046.png remains a "
            "known OCR-region miss after the previous edge fixes."
        ),
    },
    {
        "id": "parser-worker-prevalidation-only",
        "status": "architecture-gap",
        "detail": (
            "The parser worker currently performs isolated Pillow pre-validation. "
            "Full Pillow/OpenCV/OCR artifact generation still needs to move into the worker."
        ),
    },
]


def _run(cmd: List[str], timeout: int = 20) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": cmd,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except Exception as exc:
        return {"command": cmd, "error": str(exc)}


def _sha256(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _git_sha() -> str:
    result = _run(["git", "rev-parse", "--short", "HEAD"])
    if result.get("returncode") == 0:
        return str(result.get("stdout", "unknown"))
    return "unknown"


def _tool_versions() -> Dict[str, Dict[str, Any]]:
    commands = {
        "tesseract": ["tesseract", "--version"],
        "exiftool": ["exiftool", "-ver"],
        "clamav": ["clamscan", "--version"],
        "yara": ["yara", "--version"],
        "binwalk": ["binwalk", "--version"],
        "zsteg": ["zsteg", "--version"],
        "c2pa": ["c2patool", "--version"],
    }
    versions: Dict[str, Dict[str, Any]] = {}
    for name, cmd in commands.items():
        executable = shutil.which(cmd[0])
        versions[name] = {"path": executable, "available": executable is not None}
        if executable is not None:
            result = _run(cmd)
            versions[name].update({
                "returncode": result.get("returncode"),
                "version": (result.get("stdout") or result.get("stderr") or "").splitlines()[0:3],
            })
    return versions


def _clamav_db_versions() -> Dict[str, Any]:
    candidates = [
        Path("/opt/homebrew/var/lib/clamav"),
        Path("/var/lib/clamav"),
        Path("/usr/local/share/clamav"),
    ]
    db_dir = next((path for path in candidates if path.exists()), None)
    payload: Dict[str, Any] = {"db_dir": str(db_dir) if db_dir else None, "databases": {}}
    if db_dir is None:
        return payload
    for stem in ("daily", "main", "bytecode"):
        db_file = next((db_dir / (stem + suffix) for suffix in (".cvd", ".cld") if (db_dir / (stem + suffix)).exists()), None)
        if db_file is None:
            payload["databases"][stem] = {"path": None, "exists": False}
            continue
        info = _run(["sigtool", "--info", str(db_file)]) if shutil.which("sigtool") else {}
        parsed: Dict[str, Any] = {"path": str(db_file), "exists": True, "sha256": _sha256(db_file)}
        stdout = str(info.get("stdout", ""))
        for line in stdout.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower().replace(" ", "_")
            if key in {"version", "build_time", "functionality_level", "builder", "signatures"}:
                parsed[key] = value.strip()
        payload["databases"][stem] = parsed
    return payload


def _preflight(data_dir: Path) -> Dict[str, Any]:
    was_clean = not data_dir.exists() or not any(data_dir.iterdir())
    os.environ["ARGUS_DATA_DIR"] = str(data_dir)
    config = load_config()
    store = ArtifactStore(Path(config.data_dir))
    rules = PromptRuleBundle.load_default()
    caps = capabilities()
    yara_path = Path(config.yara.rule_bundle_path) if config.yara.rule_bundle_path else None
    storage = store.storage_status(config.storage.maximum_total_store_bytes)
    optional_tools = caps.get("optional_tools", {})
    preflight = {
        "ok": True,
        "git_sha": _git_sha(),
        "configuration_hash": config_hash(config),
        "tool_versions": _tool_versions(),
        "clamav": _clamav_db_versions(),
        "capabilities": caps,
        "rules": {"status": "ok", "count": len(rules.rules)},
        "yara_bundle": {
            "path": str(yara_path) if yara_path else None,
            "exists": bool(yara_path and yara_path.exists()),
            "sha256": _sha256(yara_path) if yara_path else None,
        },
        "storage": storage,
        "effective_argus_data_dir": str(Path(config.data_dir).resolve()),
        "clean_argus_data_dir_before_run": was_clean,
        "checks": {},
    }
    checks = {
        "config_hash_present": bool(preflight["configuration_hash"]),
        "rules_loaded": len(rules.rules) > 0,
        "optional_tools_available": all(bool(value) for value in optional_tools.values()),
        "clamav_available": bool(optional_tools.get("clamav")),
        "clamav_db_present": any(
            item.get("exists") for item in preflight["clamav"].get("databases", {}).values()
        ),
        "yara_bundle_exists": bool(preflight["yara_bundle"]["exists"]),
        "storage_not_over_quota": not storage["over_quota"],
        "data_dir_clean": was_clean,
    }
    preflight["checks"] = checks
    preflight["ok"] = all(checks.values())
    return preflight


def _targeted_cases() -> List[Dict[str, Any]]:
    candidates = [
        {
            "id": "prompt-small-text-000",
            "path": DEFAULT_CORPUS / "prompt_injection" / "prompt-small-text-000.png",
            "must_not_release": True,
            "required_categories": ["prompt_injection"],
            "known_gap": False,
        },
        {
            "id": "prompt-fake-login-001",
            "path": DEFAULT_CORPUS / "prompt_injection" / "prompt-fake-login-001.png",
            "must_not_release": True,
            "required_categories": ["prompt_injection", "phishing"],
            "any_required_category": True,
            "known_gap": False,
        },
        {
            "id": "sample_029",
            "path": HISTORICAL_INPUTS / "random-dataset-20260707-argus" / "inputs" / "sample_029.png",
            "must_not_release": True,
            "required_actions": ["BLOCK", "REVIEW"],
            "known_gap": False,
        },
        {
            "id": "more_008",
            "path": HISTORICAL_INPUTS / "more-diverse-20260707" / "inputs" / "more_008.gif",
            "must_not_release": True,
            "required_actions": ["BLOCK", "REVIEW"],
            "known_gap": False,
        },
        {
            "id": "sample_003-clean",
            "path": HISTORICAL_INPUTS / "random-dataset-20260707-argus" / "inputs" / "sample_003.png",
            "must_not_release": False,
            "known_gap": False,
        },
        {
            "id": "more_046-known-gap",
            "path": HISTORICAL_INPUTS / "more-diverse-20260707" / "inputs" / "more_046.png",
            "must_not_release": False,
            "required_categories": ["prompt_injection"],
            "known_gap": True,
        },
    ]
    return [case for case in candidates if Path(case["path"]).exists()]


def _matrix_cases(limit: int, seed: int) -> List[Dict[str, Any]]:
    cases = _targeted_cases()
    files: List[Path] = []
    if DEFAULT_CORPUS.exists():
        for suffix in ("*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.bmp"):
            files.extend(DEFAULT_CORPUS.rglob(suffix))
    rng = random.Random(seed)
    rng.shuffle(files)
    existing = {Path(case["path"]).resolve() for case in cases}
    for path in files:
        if path.resolve() in existing or len(cases) >= limit:
            continue
        lower = str(path).lower()
        must_not_release = any(token in lower for token in ("prompt_injection", "privacy", "steganography", "malware"))
        cases.append({
            "id": path.stem,
            "path": path,
            "must_not_release": must_not_release,
            "known_gap": False,
        })
    return cases[:limit]


def _scan_case(case: Dict[str, Any], profile: UseProfile, mode: ScanMode, reports_dir: Path) -> Dict[str, Any]:
    path = Path(case["path"])
    request = ScanRequest(original_filename=path.name, mode=mode, use_profile=profile)
    report = scan_file(path, request)
    report_json = json.loads(report_to_json(report))
    report_path = reports_dir / (case["id"] + ".json")
    report_path.write_text(json.dumps(report_json, indent=2, sort_keys=True), encoding="utf-8")
    action = report.decision.action.value if hasattr(report.decision.action, "value") else str(report.decision.action)
    categories = sorted({finding.category for finding in report.findings})
    result = {
        "id": case["id"],
        "path": str(path),
        "report": str(report_path),
        "action": action,
        "release_grants": len(report.release_grants),
        "finding_categories": categories,
        "finding_count": len(report.findings),
        "known_gap": bool(case.get("known_gap")),
        "violations": [],
        "detection_gaps": [],
    }
    if case.get("must_not_release") and (report.release_grants or action in {"ALLOW_ORIGINAL", "ALLOW_RECONSTRUCTED_ONLY"}):
        result["violations"].append("must_not_release case allowed release")
    required_actions = set(case.get("required_actions", []))
    if required_actions and action not in required_actions:
        result["detection_gaps"].append("action %s not in %s" % (action, sorted(required_actions)))
    required_categories = set(case.get("required_categories", []))
    if required_categories:
        if case.get("any_required_category"):
            if not (required_categories & set(categories)):
                result["detection_gaps"].append("none of required categories present: %s" % sorted(required_categories))
        else:
            missing = sorted(required_categories - set(categories))
            if missing:
                result["detection_gaps"].append("missing finding categories: %s" % missing)
    return result


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_summary_markdown(path: Path, summary: Dict[str, Any]) -> None:
    lines = [
        "# ARGUS-IMG Latest Evaluation Summary",
        "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Git SHA: `{summary['git_sha']}`",
        f"- Config hash: `{summary['configuration_hash']}`",
        f"- ARGUS_DATA_DIR: `{summary['effective_argus_data_dir']}`",
        f"- Total scans: `{summary['total_scans']}`",
        f"- Actions: `{summary['actions']}`",
        f"- Release-grant violations: `{summary['release_grant_violations']}`",
        f"- Detection gaps: `{len(summary['detection_gaps'])}`",
        f"- Acceptance gate: `{summary['acceptance_gate']}`",
        "",
        "## Known Gaps",
    ]
    for gap in summary["known_gaps"]:
        lines.append(f"- `{gap['id']}` ({gap['status']}): {gap['detail']}")
    if summary["detection_gaps"]:
        lines.extend(["", "## Detection Gaps"])
        for gap in summary["detection_gaps"]:
            lines.append(f"- `{gap['id']}`: {gap['detection_gaps']}")
    if summary.get("known_detection_gaps_observed"):
        lines.extend(["", "## Known Detection Gaps Observed"])
        for gap in summary["known_detection_gaps_observed"]:
            lines.append(f"- `{gap['id']}`: {gap['detection_gaps']} (action `{gap['action']}`)")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["targeted", "matrix"], default="targeted")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--seed", type=int, default=20260708)
    parser.add_argument("--profile", choices=[profile.value for profile in UseProfile], default=UseProfile.AGENT_WITH_TOOLS.value)
    parser.add_argument("--mode", choices=[mode.value for mode in ScanMode], default=ScanMode.FAST.value)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--allow-preflight-warnings", action="store_true")
    args = parser.parse_args(argv)

    latest_dir = REPO_ROOT / "evaluation-results" / "latest"
    latest_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = latest_dir / run_id
    while run_dir.exists():
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        run_dir = latest_dir / run_id
    run_dir.mkdir(parents=True)
    reports_dir = run_dir / "reports"
    reports_dir.mkdir()
    data_dir = args.data_dir.resolve() if args.data_dir else run_dir / "argus-data"

    preflight = _preflight(data_dir)
    _write_json(run_dir / "preflight.json", preflight)
    if not preflight["ok"] and not args.allow_preflight_warnings:
        _write_json(run_dir / "summary.json", {
            "run_id": run_id,
            "acceptance_gate": "PRECHECK_FAILED",
            "preflight": preflight,
            "known_gaps": KNOWN_GAPS,
        })
        pointer_tmp = latest_dir / "current.tmp"
        pointer_tmp.write_text(str(run_dir) + "\n", encoding="utf-8")
        os.replace(pointer_tmp, latest_dir / "current")
        print("preflight failed; see %s" % (run_dir / "preflight.json"))
        return 2

    cases = _targeted_cases() if args.suite == "targeted" else _matrix_cases(args.limit, args.seed)
    results = [
        _scan_case(case, UseProfile(args.profile), ScanMode(args.mode), reports_dir)
        for case in cases
    ]
    _write_json(run_dir / "run_results.json", results)

    actions = Counter(result["action"] for result in results)
    release_violations = [result for result in results if result["violations"]]
    detection_gaps = [
        result for result in results
        if result["detection_gaps"] and not result.get("known_gap")
    ]
    known_detection_gaps = [
        result for result in results
        if result["detection_gaps"] and result.get("known_gap")
    ]
    acceptance_gate = (
        "PASS"
        if not release_violations and not detection_gaps
        else "FAIL"
    )
    summary = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "suite": args.suite,
        "git_sha": preflight["git_sha"],
        "configuration_hash": preflight["configuration_hash"],
        "tool_versions": preflight["tool_versions"],
        "clamav": preflight["clamav"],
        "yara_bundle": preflight["yara_bundle"],
        "effective_argus_data_dir": preflight["effective_argus_data_dir"],
        "storage": ArtifactStore(Path(preflight["effective_argus_data_dir"])).storage_status(
            load_config().storage.maximum_total_store_bytes
        ),
        "total_scans": len(results),
        "actions": dict(sorted(actions.items())),
        "release_grant_violations": len(release_violations),
        "release_grant_violation_details": release_violations,
        "detection_gaps": detection_gaps,
        "known_detection_gaps_observed": known_detection_gaps,
        "known_gaps": KNOWN_GAPS,
        "acceptance_gate": acceptance_gate,
    }
    _write_json(run_dir / "summary.json", summary)
    _write_summary_markdown(run_dir / "summary.md", summary)
    pointer_tmp = latest_dir / "current.tmp"
    pointer_tmp.write_text(str(run_dir) + "\n", encoding="utf-8")
    os.replace(pointer_tmp, latest_dir / "current")
    print(json.dumps({"run_dir": str(run_dir), "acceptance_gate": acceptance_gate}, indent=2))
    return 0 if acceptance_gate == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
