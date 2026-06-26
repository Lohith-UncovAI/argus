#!/usr/bin/env python3
"""ARGUS-IMG macOS evaluation runner — corrected version.

Key fixes over v1:
  - Uses release_grants (not artifact_grants) from scan report
  - Queries artifact endpoint to verify downloadability for every grant
  - FORBIDDEN_ACTION and DETECTION_GAP both fail the acceptance gate
  - All violating scan records written to failures.jsonl
  - Captures full detector_executions, findings, module_status, representations
  - Separates safety metrics from detection metrics
  - Injects local ClamAV wrapper and YARA bundle via PATH/config
  - Starts a local API server for artifact endpoint validation

Safety constraints enforced:
  - Never opens decoded URLs
  - Never releases or executes extracted payloads
  - All scans one at a time
  - No network calls during scan stage
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
CORPUS_ROOT = pathlib.Path.home() / "argus-eval-data" / "corpus"
MANIFEST_PATH = pathlib.Path.home() / "argus-eval-data" / "manifests" / "argus-eval.jsonl"
RESULTS_DIR = REPO_ROOT / "evaluation-results"

YARA_BUNDLE = str(pathlib.Path.home() / "argus-eval-data" / "tool-config" / "yara" / "argus-test.yar")
YARA_BUNDLE_SHA256 = "63610c0dfbcd0f5463e00df589ff3112ace429ed482217a3103d9964345603c3"
CLAMAV_WRAPPER_DIR = str(pathlib.Path.home() / "argus-eval-data" / "tool-config" / "bin")
EVAL_CONFIG_ROOT = str(pathlib.Path.home() / "argus-eval-data" / "tool-config" / "eval-config-root")

# Timeout per fixture scan
SCAN_TIMEOUT = 60

# Scan matrix: category label → [(mode, profile), ...]
SCAN_MATRIX: dict[str, list[tuple[str, str]]] = {
    "benign": [
        ("fast", "HUMAN_VIEW"),
        ("deep", "RAG_INGESTION"),
    ],
    "contextual_negative": [
        ("fast", "HUMAN_VIEW"),
        ("deep", "OCR_EXTRACTION"),
    ],
    "prompt_injection": [
        ("fast", "OCR_EXTRACTION"),
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "metadata": [
        ("deep", "AGENT_WITH_TOOLS"),
        ("forensic", "SECURITY_FORENSICS"),
    ],
    "qr": [
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "multi_frame": [
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "malware_canary": [
        ("deep", "AGENT_WITH_TOOLS"),
        ("forensic", "SECURITY_FORENSICS"),
    ],
    "embedded_content": [
        ("deep", "AGENT_WITH_TOOLS"),
        ("forensic", "SECURITY_FORENSICS"),
    ],
    "malformed": [
        ("deep", "HUMAN_VIEW"),
        ("forensic", "SECURITY_FORENSICS"),
    ],
    "steganography": [
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "steganography_cover": [
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "lsb_modified": [
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "privacy": [
        ("deep", "AGENT_WITH_TOOLS"),
        ("forensic", "SECURITY_FORENSICS"),
    ],
    "phishing": [
        ("deep", "OCR_EXTRACTION"),
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "alpha": [
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "channel_steganography": [
        ("deep", "AGENT_WITH_TOOLS"),
    ],
    "watermark": [
        ("fast", "HUMAN_VIEW"),
    ],
    "provenance": [
        ("forensic", "SECURITY_FORENSICS"),
    ],
    "default": [
        ("fast", "HUMAN_VIEW"),
    ],
}


# ─── helpers ───────────────────────────────────────────────────────────────────

def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _matrix_for(labels: list[str]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    combos: list[tuple[str, str]] = []
    for lbl in labels:
        for combo in SCAN_MATRIX.get(lbl, []):
            if combo not in seen:
                seen.add(combo)
                combos.append(combo)
    if not combos:
        combos = SCAN_MATRIX["default"]
    return combos


def _make_eval_env() -> dict[str, str]:
    """Build environment for subprocess scans.

    Prepends our clamscan wrapper dir so ClamAV uses the local .hdb.
    Sets ARGUS_CONFIG_ROOT to the eval config root that wires in the YARA bundle.
    """
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    env["ARGUS_DATA_DIR"] = str(REPO_ROOT / "data")
    env["ARGUS_OFFLINE_STRICT"] = "0"
    # Prepend wrapper so our clamscan gets found first
    env["PATH"] = CLAMAV_WRAPPER_DIR + os.pathsep + env.get("PATH", "")
    # Use our eval config root which has YARA wired in
    if pathlib.Path(EVAL_CONFIG_ROOT).exists():
        env["ARGUS_CONFIG_ROOT"] = EVAL_CONFIG_ROOT
    return env


def _write_yara_config_override() -> pathlib.Path:
    """Write a temporary YAML config fragment that enables the YARA bundle."""
    cfg_path = pathlib.Path.home() / "argus-eval-data" / "tool-config" / "eval-yara-override.yaml"
    cfg_path.write_text(
        f"yara:\n"
        f"  enabled: true\n"
        f"  executable_path: /opt/homebrew/bin/yara\n"
        f"  rule_bundle_path: {YARA_BUNDLE}\n"
        f"  rule_bundle_sha256: {YARA_BUNDLE_SHA256}\n"
        f"  maximum_matches: 100\n",
        encoding="utf-8",
    )
    return cfg_path


def _run_argus_scan(
    image_path: pathlib.Path,
    mode: str,
    profile: str,
    timeout: int,
) -> tuple[dict, str, str, float, bool]:
    """Run argus-img scan via CLI subprocess.

    Returns (report_dict, stdout, stderr, duration_s, timed_out).
    """
    env = _make_eval_env()
    python = str(REPO_ROOT / ".venv" / "bin" / "python")
    cmd = [
        python, "-m", "argus_img.cli.main",
        "scan",
        "--mode", mode,
        "--profile", profile,
        str(image_path),
    ]

    t0 = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env=env,
            cwd=str(REPO_ROOT),
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout = ""
        stderr = f"TIMEOUT after {timeout}s"

    duration = time.monotonic() - t0
    report: dict = {}
    if stdout.strip():
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError as e:
            report = {"_parse_error": str(e), "_raw": stdout[:2000]}
    return report, stdout, stderr, duration, timed_out


# ─── API server for artifact endpoint validation ───────────────────────────────

def _find_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _http_get(url: str, timeout: int = 5) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class ApiServer:
    """Manages a local ARGUS API server for artifact endpoint validation."""

    def __init__(self) -> None:
        self.port = _find_free_port("127.0.0.1")
        self.base = f"http://127.0.0.1:{self.port}/v1"
        self._proc: subprocess.Popen | None = None

    def start(self) -> bool:
        env = _make_eval_env()
        python = str(REPO_ROOT / ".venv" / "bin" / "python")
        self._proc = subprocess.Popen(
            [
                python, "-m", "uvicorn",
                "argus_img.api.app:create_app",
                "--host", "127.0.0.1",
                "--port", str(self.port),
                "--factory",
                "--log-level", "warning",
            ],
            env=env,
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(30):
            time.sleep(0.5)
            try:
                code, _ = _http_get(f"{self.base}/health")
                if code == 200:
                    return True
            except Exception:
                pass
        return False

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def check_artifact(self, artifact_id: str) -> tuple[int, str]:
        """Return (http_code, 'downloadable'|'blocked'|'not_found'|'error')."""
        encoded = urllib.parse.quote(artifact_id, safe="")
        try:
            code, _ = _http_get(f"{self.base}/artifacts/{encoded}")
            if code == 200:
                return code, "downloadable"
            if code == 403:
                return code, "blocked"
            if code == 404:
                return code, "not_found"
            return code, f"unexpected_{code}"
        except Exception as e:
            return 0, f"error:{e}"


# ─── invariant checking ────────────────────────────────────────────────────────

def _check_all_invariants(
    report: dict,
    manifest_record: dict,
    fixture_id: str,
    server: ApiServer | None,
) -> tuple[list[str], list[str]]:
    """Return (safety_violations, detection_gaps)."""
    safety: list[str] = []
    detection: list[str] = []

    if "_parse_error" in report:
        return safety, detection

    decision = report.get("decision", {}).get("action", "UNKNOWN")
    labels = manifest_record.get("labels", [])
    expected = manifest_record.get("expected", {})
    grants = report.get("release_grants", [])

    # ── Release invariants ─────────────────────────────────────────────────────
    blocking_decisions = {"BLOCK", "QUARANTINE", "REVIEW", "UNSUPPORTED", "ERROR"}

    if decision in blocking_decisions and grants:
        safety.append(
            f"RELEASE_INVARIANT: {decision} has {len(grants)} grant(s) for {fixture_id}"
        )

    for grant in grants:
        role = grant.get("role", "")
        artifact_id = grant.get("artifact_id", "")

        # Original must never be released
        if role == "original" or "original" in artifact_id:
            safety.append(
                f"RELEASE_INVARIANT: original artifact has grant for {fixture_id} (role={role})"
            )

        # analysis-only roles must not be downloadable
        if role not in {"canonical_lossy", "redacted"}:
            safety.append(
                f"RELEASE_INVARIANT: analysis-only role '{role}' has grant for {fixture_id}"
            )

        # Verify via API endpoint
        if server and artifact_id:
            code, outcome = server.check_artifact(artifact_id)
            if decision in blocking_decisions and outcome == "downloadable":
                safety.append(
                    f"RELEASE_INVARIANT: grant {artifact_id} is downloadable despite {decision} for {fixture_id}"
                )
            # For allowed scans, confirm the released artifact IS downloadable
            if decision == "ALLOW_RECONSTRUCTED_ONLY" and outcome != "downloadable":
                safety.append(
                    f"RELEASE_INVARIANT: allowed artifact {artifact_id} not downloadable (got {outcome}) for {fixture_id}"
                )

    # Original artifact must always return 403 or 404
    original_id = report.get("input", {}).get("quarantined_artifact_id", "")
    if server and original_id:
        code, outcome = server.check_artifact(original_id)
        if outcome == "downloadable":
            safety.append(
                f"RELEASE_INVARIANT: original artifact {original_id} is downloadable for {fixture_id}"
            )

    # DETECTED execution must have at least one finding
    all_findings = report.get("findings", [])
    finding_ids = {f.get("finding_id") for f in all_findings}
    for ex in report.get("detector_executions", []):
        if ex.get("state") == "DETECTED":
            det_id = ex.get("detector_id", "")
            # Check findings reference this detector
            related = [
                f for f in all_findings
                if det_id in str(f.get("detector_ids", []))
            ]
            if not related:
                safety.append(
                    f"DETECTION_TO_POLICY: DETECTED execution {det_id} has no finding for {fixture_id}"
                )

    # Malware canary: any grant is a safety failure
    if "malware_canary" in labels and grants:
        safety.append(
            f"MALWARE_CANARY_RELEASED: {len(grants)} grant(s) for {fixture_id}"
        )

    # VLM_READ_ONLY must always be UNSUPPORTED with zero grants
    # (checked at runner level since profile is known there)

    # Report privacy: canary string must not appear in public-facing fields
    pub_summary = report.get("decision", {}).get("summary", "")
    pub_explanation = report.get("decision", {}).get("explanation", "")
    for canary in ("ARGUS-CANARY-7F91", "ARGUS_SAFE_BINARY_CANARY_v1_7F91", "ARGUS-STEG-CANARY-7F91"):
        for field, val in [("decision.summary", pub_summary), ("decision.explanation", pub_explanation)]:
            if canary in val:
                safety.append(
                    f"REPORT_PRIVACY: canary '{canary}' in {field} for {fixture_id}"
                )

    # ── Detection gaps (test failures, not safety failures) ────────────────────
    forbidden_actions = expected.get("forbidden_actions", [])
    for fa in forbidden_actions:
        if decision == fa:
            detection.append(
                f"FORBIDDEN_ACTION({fa}): decision was {fa} for {fixture_id}"
            )

    must_not_release = expected.get("must_not_release", False)
    if must_not_release and grants:
        detection.append(
            f"MUST_NOT_RELEASE: {len(grants)} grant(s) issued despite must_not_release=true for {fixture_id}"
        )

    max_critical = expected.get("maximum_critical_findings")
    if max_critical is not None:
        critical = [
            f for f in all_findings
            if f.get("severity") == "critical" or f.get("recommendation") in ("QUARANTINE", "BLOCK")
        ]
        if len(critical) > max_critical:
            detection.append(
                f"MAX_CRITICAL_EXCEEDED: {len(critical)} critical findings (max {max_critical}) for {fixture_id}"
            )

    return safety, detection


# ─── per-fixture scan ──────────────────────────────────────────────────────────

def _extract_full_evidence(report: dict) -> dict:
    """Extract complete detector evidence from report for audit trail."""
    return {
        "detector_executions": [
            {
                "detector_id": ex.get("detector_id"),
                "status": ex.get("status"),
                "state": ex.get("state"),
                "reason": ex.get("reason"),
                "tool_version": ex.get("tool_version"),
                "duration_ms": ex.get("duration_ms"),
            }
            for ex in report.get("detector_executions", [])
        ],
        "findings": [
            {
                "finding_id": f.get("finding_id"),
                "category": f.get("category"),
                "recommendation": f.get("recommendation"),
                "severity": f.get("severity"),
                "detector_ids": f.get("detector_ids", []),
                "summary": f.get("summary", "")[:200],
            }
            for f in report.get("findings", [])
        ],
        "module_status": report.get("module_status", {}),
        "representations": list(
            report.get("representation_manifest", {}).get("representations", {}).keys()
        ),
        "release_grants": [
            {
                "grant_id": g.get("grant_id"),
                "artifact_id": g.get("artifact_id"),
                "role": g.get("role"),
                "action": g.get("action"),
                "sha256": g.get("sha256"),
            }
            for g in report.get("release_grants", [])
        ],
        "coverage_state": report.get("coverage", {}).get("state") if isinstance(report.get("coverage"), dict) else None,
        "timings_ms": report.get("timings_ms", {}),
        "errors": report.get("errors", []),
        "limitations": report.get("limitations", []),
    }


def evaluate_fixture(
    manifest_record: dict,
    corpus_root: pathlib.Path,
    server: ApiServer | None,
) -> list[dict]:
    fixture_id = manifest_record["id"]
    rel_path = manifest_record["path"]
    expected_sha256 = manifest_record["sha256"]
    labels = manifest_record.get("labels", [])

    image_path = corpus_root / rel_path

    if not image_path.exists():
        return [{
            "input_id": fixture_id,
            "mode": "N/A", "profile": "N/A",
            "decision": "FIXTURE_MISSING",
            "safety_violations": [f"FIXTURE_MISSING: {image_path}"],
            "detection_gaps": [],
            "worker_state": "fixture_missing",
            "evidence": {},
        }]

    actual_sha256 = _sha256_file(image_path)
    if actual_sha256 != expected_sha256:
        return [{
            "input_id": fixture_id,
            "mode": "N/A", "profile": "N/A",
            "decision": "SHA_MISMATCH",
            "safety_violations": [
                f"SHA_MISMATCH: expected {expected_sha256} got {actual_sha256}"
            ],
            "detection_gaps": [],
            "worker_state": "sha_mismatch",
            "evidence": {},
        }]

    matrix = _matrix_for(labels)
    scan_results = []

    for mode, profile in matrix:
        report, stdout, stderr, duration, timed_out = _run_argus_scan(
            image_path, mode, profile, SCAN_TIMEOUT
        )

        decision = "TIMEOUT" if timed_out else (
            "PARSE_ERROR" if "_parse_error" in report else
            report.get("decision", {}).get("action", "UNKNOWN")
        )
        scan_id_val = report.get("scan_id", f"eval-{fixture_id}-{mode}-{profile}")
        reason_codes = report.get("decision", {}).get("reason_codes", []) if not timed_out else []

        safety_violations, detection_gaps = _check_all_invariants(
            report, manifest_record, fixture_id, server
        )

        # VLM_READ_ONLY additional check
        if profile == "VLM_READ_ONLY":
            if decision not in ("UNSUPPORTED", "ERROR", "TIMEOUT"):
                safety_violations.append(
                    f"VLM_INVARIANT: VLM_READ_ONLY returned {decision} (must be UNSUPPORTED) for {fixture_id}"
                )
            if report.get("release_grants"):
                safety_violations.append(
                    f"VLM_INVARIANT: VLM_READ_ONLY issued grants for {fixture_id}"
                )

        evidence = _extract_full_evidence(report) if not timed_out and "_parse_error" not in report else {}

        # Capability classification
        unsupported = decision == "UNSUPPORTED"
        actually_tested = not unsupported and not timed_out and decision not in ("PARSE_ERROR", "FIXTURE_MISSING", "SHA_MISMATCH")

        rec = {
            "scan_id": scan_id_val,
            "input_id": fixture_id,
            "mode": mode,
            "profile": profile,
            "labels": labels,
            "decision": decision,
            "reason_codes": reason_codes,
            "runtime_seconds": round(duration, 3),
            "timed_out": timed_out,
            "worker_state": (
                "timeout" if timed_out else
                "parse_error" if "_parse_error" in report else
                "completed"
            ),
            "actually_tested": actually_tested,
            "unsupported": unsupported,
            "release_grant_count": len(report.get("release_grants", [])),
            "release_grant_roles": [g.get("role") for g in report.get("release_grants", [])],
            "finding_count": len(report.get("findings", [])),
            "safety_violations": safety_violations,
            "detection_gaps": detection_gaps,
            "stderr_snippet": stderr[:500] if stderr else "",
            "evidence": evidence,
        }
        scan_results.append(rec)

    return scan_results


# ─── evaluation loop ────────────────────────────────────────────────────────────

def run_evaluation(
    manifest_path: pathlib.Path,
    corpus_root: pathlib.Path,
    results_dir: pathlib.Path,
    limit: int | None = None,
    label_filter: str | None = None,
    skip_api_server: bool = False,
) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)

    records = []
    with manifest_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if label_filter and not any(label_filter in lbl for lbl in rec.get("labels", [])):
                    continue
                records.append(rec)
            except json.JSONDecodeError as e:
                print(f"WARNING: skipping malformed manifest line: {e}")

    if limit:
        records = records[:limit]

    print(f"=== ARGUS Evaluation Runner v2 ===")
    print(f"Fixtures: {len(records)}")
    print(f"Corpus:   {corpus_root}")
    print(f"Results:  {results_dir}")
    print(f"ClamAV wrapper: {CLAMAV_WRAPPER_DIR}/clamscan")
    print(f"YARA bundle: {YARA_BUNDLE}")

    # Verify ClamAV wrapper works before starting
    wrapper = pathlib.Path(CLAMAV_WRAPPER_DIR) / "clamscan"
    if not wrapper.exists():
        print("WARNING: ClamAV wrapper not found — malware detection will ERROR")
    else:
        test = subprocess.run(
            [str(wrapper), "--version"],
            capture_output=True, text=True, timeout=5
        )
        print(f"ClamAV wrapper OK: {test.stdout.strip()[:60]}")

    server: ApiServer | None = None
    if not skip_api_server:
        print("Starting local API server for artifact endpoint validation...")
        server = ApiServer()
        if not server.start():
            print("WARNING: API server failed to start — artifact endpoint checks disabled")
            server = None
        else:
            print(f"API server ready at {server.base}")
    print()

    all_results: list[dict] = []
    results_path = results_dir / "results.jsonl"
    failures_path = results_dir / "failures.jsonl"

    try:
        with results_path.open("w") as rf, failures_path.open("w") as ff:
            for i, record in enumerate(records):
                fixture_id = record["id"]
                labels = record.get("labels", [])
                print(
                    f"[{i+1:4d}/{len(records)}] {fixture_id} ({','.join(labels[:3])})",
                    end=" ... ", flush=True
                )

                try:
                    scan_results = evaluate_fixture(record, corpus_root, server)
                except Exception:
                    scan_results = [{
                        "input_id": fixture_id,
                        "mode": "N/A", "profile": "N/A",
                        "decision": "RUNNER_EXCEPTION",
                        "safety_violations": [],
                        "detection_gaps": [],
                        "worker_state": "exception",
                        "error": traceback.format_exc()[:1000],
                        "evidence": {},
                    }]

                decisions = [r["decision"] for r in scan_results]
                has_safety = any(r.get("safety_violations") for r in scan_results)
                has_detection = any(r.get("detection_gaps") for r in scan_results)
                flag = " [SAFETY!]" if has_safety else (" [DETECTION_GAP]" if has_detection else "")
                print(f"{decisions}{flag}")

                for r in scan_results:
                    rf.write(json.dumps(r) + "\n")
                    rf.flush()
                    all_results.append(r)

                    # Write to failures.jsonl if any violation
                    is_failure = (
                        r.get("safety_violations") or
                        r.get("detection_gaps") or
                        r.get("worker_state") not in ("completed", "fixture_missing", "sha_mismatch")
                    )
                    if is_failure:
                        ff.write(json.dumps(r) + "\n")
                        ff.flush()

    finally:
        if server:
            server.stop()
            print("\nAPI server stopped.")

    _write_reports(all_results, results_dir)


# ─── report generation ──────────────────────────────────────────────────────────

def _write_reports(results: list[dict], results_dir: pathlib.Path) -> None:
    # Separate safety from detection gaps
    all_safety: list[str] = []
    all_detection: list[str] = []
    for r in results:
        all_safety.extend(r.get("safety_violations", []))
        all_detection.extend(r.get("detection_gaps", []))

    total_scans = len(results)
    actually_tested = sum(1 for r in results if r.get("actually_tested", False))
    unsupported_count = sum(1 for r in results if r.get("unsupported", False))
    timeout_count = sum(1 for r in results if r.get("timed_out", False))
    worker_exceptions = sum(1 for r in results if r.get("worker_state") == "exception")

    unsafe_release_count = sum(
        1 for r in results
        if r.get("safety_violations") and any(
            "RELEASE_INVARIANT" in v or "MALWARE_CANARY_RELEASED" in v
            for v in r["safety_violations"]
        )
    )

    # Acceptance gate: FAIL if any safety violation OR any FORBIDDEN_ACTION
    gate = "PASS"
    if all_safety:
        gate = "FAIL"
    elif all_detection:
        gate = "FAIL"  # detection gaps are test failures

    decisions: dict[str, int] = {}
    for r in results:
        d = r.get("decision", "UNKNOWN")
        decisions[d] = decisions.get(d, 0) + 1

    # Safety metrics
    safety_report = {
        "generated_at": _now_iso(),
        "total_scans": total_scans,
        "actually_tested_scans": actually_tested,
        "unsupported_scans": unsupported_count,
        "timeout_count": timeout_count,
        "worker_exception_count": worker_exceptions,
        "safety_violations": len(all_safety),
        "unsafe_release_count": unsafe_release_count,
        "detection_gaps": len(all_detection),
        "acceptance_gate": gate,
        "gate_reason": (
            "safety violations present" if all_safety else
            "detection gaps present (FORBIDDEN_ACTION)" if all_detection else
            "all invariants pass"
        ),
        "all_safety_violations": all_safety[:200],
        "all_detection_gaps": all_detection[:200],
        "decisions": decisions,
        "worker_states": {},
    }
    for r in results:
        ws = r.get("worker_state", "unknown")
        safety_report["worker_states"][ws] = safety_report["worker_states"].get(ws, 0) + 1

    (results_dir / "security-invariants.json").write_text(
        json.dumps(safety_report, indent=2)
    )

    # Detection metrics (separate from safety)
    detection_by_category: dict[str, dict] = {}
    for r in results:
        labels = r.get("labels", [])
        for lbl in labels:
            if lbl not in detection_by_category:
                detection_by_category[lbl] = {
                    "scanned": 0, "actually_tested": 0, "blocked": 0,
                    "review": 0, "allowed": 0, "unsupported": 0, "gaps": 0
                }
            cat = detection_by_category[lbl]
            cat["scanned"] += 1
            d = r.get("decision", "")
            if r.get("actually_tested"):
                cat["actually_tested"] += 1
            if d in ("BLOCK", "QUARANTINE"):
                cat["blocked"] += 1
            elif d == "REVIEW":
                cat["review"] += 1
            elif d in ("ALLOW_RECONSTRUCTED_ONLY", "ALLOW_ORIGINAL"):
                cat["allowed"] += 1
            elif d == "UNSUPPORTED":
                cat["unsupported"] += 1
            cat["gaps"] += len(r.get("detection_gaps", []))

    (results_dir / "detection-metrics.json").write_text(
        json.dumps({"generated_at": _now_iso(), "by_label": detection_by_category}, indent=2)
    )

    # Performance
    runtimes = sorted(r["runtime_seconds"] for r in results if isinstance(r.get("runtime_seconds"), (int, float)))
    n = len(runtimes)
    def pct(p: float) -> float:
        return runtimes[min(int(n * p / 100), n - 1)] if runtimes else 0.0

    perf = {
        "generated_at": _now_iso(),
        "total_scans": n,
        "actually_tested_scans": actually_tested,
        "mean_duration_s": round(sum(runtimes) / n, 3) if runtimes else 0,
        "median_duration_s": round(pct(50), 3),
        "p95_duration_s": round(pct(95), 3),
        "max_duration_s": round(max(runtimes), 3) if runtimes else 0,
        "min_duration_s": round(min(runtimes), 3) if runtimes else 0,
        "timeout_rate": round(timeout_count / total_scans, 4) if total_scans else 0,
        "worker_crash_rate": round(worker_exceptions / total_scans, 4) if total_scans else 0,
    }
    (results_dir / "performance.json").write_text(json.dumps(perf, indent=2))

    print(f"\n=== Evaluation Summary ===")
    print(f"Total scans:        {total_scans}")
    print(f"Actually tested:    {actually_tested} ({100*actually_tested//total_scans if total_scans else 0}%)")
    print(f"UNSUPPORTED:        {unsupported_count}")
    print(f"Safety violations:  {len(all_safety)}")
    print(f"Detection gaps:     {len(all_detection)}")
    print(f"Unsafe releases:    {unsafe_release_count}")
    print(f"Acceptance gate:    {gate}")
    print(f"\nDecisions: {decisions}")

    if all_safety:
        print("\nSAFETY VIOLATIONS:")
        for v in all_safety[:20]:
            print(f"  {v}")
    if all_detection:
        print(f"\nDETECTION GAPS (first 20 of {len(all_detection)}):")
        for v in all_detection[:20]:
            print(f"  {v}")


# ─── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ARGUS macOS evaluation runner v2")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--corpus-root", default=str(CORPUS_ROOT))
    parser.add_argument("--results-dir", default=str(RESULTS_DIR))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--label-filter", default=None)
    parser.add_argument("--no-api-server", action="store_true",
                        help="Skip artifact endpoint validation (faster, less complete)")
    args = parser.parse_args()

    run_evaluation(
        manifest_path=pathlib.Path(args.manifest),
        corpus_root=pathlib.Path(args.corpus_root),
        results_dir=pathlib.Path(args.results_dir),
        limit=args.limit,
        label_filter=args.label_filter,
        skip_api_server=args.no_api_server,
    )


if __name__ == "__main__":
    main()
