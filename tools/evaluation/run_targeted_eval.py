#!/usr/bin/env python3
"""Targeted category-by-category evaluation runner — corrected version.

Fixes over v1:
  - Uses release_grants (not artifact_grants) from scan report
  - acceptance_gate FAILS on FORBIDDEN_ACTION and DETECTION_GAP
  - failures.jsonl contains all records with security_violations
  - Full detector evidence captured per scan
  - ClamAV wrapper injected via PATH so local .hdb is active
  - Separates safety_violations from detection_gaps in each record
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
import hashlib
import socket
import traceback
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
CORPUS_ROOT = pathlib.Path.home() / "argus-eval-data" / "corpus"
MANIFEST_PATH = pathlib.Path.home() / "argus-eval-data" / "manifests" / "argus-eval.jsonl"
RESULTS_DIR = REPO_ROOT / "evaluation-results"
CLAMAV_WRAPPER_DIR = str(pathlib.Path.home() / "argus-eval-data" / "tool-config" / "bin")

TARGETED_SCANS = [
    # (label_filter, mode, profile, max_fixtures)
    ("prompt_injection", "fast", "OCR_EXTRACTION", 30),
    ("prompt_injection", "deep", "AGENT_WITH_TOOLS", 30),
    ("multi_frame", "deep", "AGENT_WITH_TOOLS", 15),
    ("qr", "deep", "AGENT_WITH_TOOLS", 15),
    ("malformed", "deep", "HUMAN_VIEW", 8),
    ("privacy", "deep", "AGENT_WITH_TOOLS", 10),
    ("phishing", "deep", "OCR_EXTRACTION", 8),
    ("alpha", "deep", "AGENT_WITH_TOOLS", 10),
    ("channel_steganography", "deep", "AGENT_WITH_TOOLS", 10),
    ("contextual_negative", "fast", "HUMAN_VIEW", 20),
    ("watermark", "fast", "HUMAN_VIEW", 6),
    ("malware_canary", "deep", "AGENT_WITH_TOOLS", 2),
    ("embedded_content", "deep", "AGENT_WITH_TOOLS", 2),
    ("steganography_cover", "deep", "AGENT_WITH_TOOLS", 5),
    ("lsb_modified", "deep", "AGENT_WITH_TOOLS", 5),
    ("provenance", "forensic", "SECURITY_FORENSICS", 5),
]


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


EVAL_CONFIG_ROOT = str(pathlib.Path.home() / "argus-eval-data" / "tool-config" / "eval-config-root")


def _make_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    env["ARGUS_OFFLINE_STRICT"] = "0"
    env["ARGUS_DATA_DIR"] = str(REPO_ROOT / "data")
    env["PATH"] = CLAMAV_WRAPPER_DIR + os.pathsep + env.get("PATH", "")
    if pathlib.Path(EVAL_CONFIG_ROOT).exists():
        env["ARGUS_CONFIG_ROOT"] = EVAL_CONFIG_ROOT
    return env


def _run_scan(image_path: pathlib.Path, mode: str, profile: str, timeout: int = 60) -> dict:
    env = _make_env()
    python = str(REPO_ROOT / ".venv" / "bin" / "python")
    cmd = [
        python, "-m", "argus_img.cli.main",
        "scan", "--mode", mode, "--profile", profile, str(image_path)
    ]
    t0 = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout, env=env, cwd=str(REPO_ROOT)
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        stdout, stderr, timed_out = "", f"TIMEOUT after {timeout}s", True

    duration = time.monotonic() - t0
    report: dict = {}
    if stdout.strip():
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError as e:
            report = {"_parse_error": str(e)}
    return {"report": report, "duration": duration, "timed_out": timed_out, "stderr": stderr[:500]}


def _extract_evidence(report: dict) -> dict:
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
                "summary": f.get("summary", "")[:200],
            }
            for f in report.get("findings", [])
        ],
        "module_status": report.get("module_status", {}),
        "release_grants": [
            {
                "grant_id": g.get("grant_id"),
                "artifact_id": g.get("artifact_id"),
                "role": g.get("role"),
                "action": g.get("action"),
            }
            for g in report.get("release_grants", [])
        ],
    }


def _check_invariants(
    report: dict,
    manifest_rec: dict,
    fid: str,
    labels: list[str],
    profile: str,
    decision: str,
) -> tuple[list[str], list[str]]:
    """Returns (safety_violations, detection_gaps)."""
    safety: list[str] = []
    detection: list[str] = []

    grants = report.get("release_grants", [])
    expected = manifest_rec.get("expected", {})
    all_findings = report.get("findings", [])
    blocking = {"BLOCK", "QUARANTINE", "REVIEW", "UNSUPPORTED", "ERROR"}

    # Never release under a blocking decision
    if grants and decision in blocking:
        safety.append(f"RELEASE_INVARIANT: {decision} with {len(grants)} grant(s) for {fid}")

    # Original role must never be granted
    for g in grants:
        role = g.get("role", "")
        artifact_id = g.get("artifact_id", "")
        if role == "original" or (role not in {"canonical_lossy", "redacted"} and grants):
            safety.append(f"RELEASE_INVARIANT: non-released role '{role}' has grant for {fid}")

    # DETECTED execution must pair with at least one finding
    for ex in report.get("detector_executions", []):
        if ex.get("state") == "DETECTED":
            det_id = ex.get("detector_id", "")
            related = [
                f for f in all_findings
                if det_id in str(f.get("detector_ids", []))
            ]
            if not related:
                safety.append(
                    f"DETECTION_TO_POLICY: DETECTED execution {det_id} has no finding for {fid}"
                )

    # Malware canary must never be released
    if "malware_canary" in labels and grants:
        safety.append(f"MALWARE_CANARY_RELEASED: {len(grants)} grant(s) for {fid}")

    # VLM_READ_ONLY invariant
    if profile == "VLM_READ_ONLY" and decision not in ("UNSUPPORTED", "ERROR", "TIMEOUT"):
        safety.append(f"VLM_INVARIANT: VLM_READ_ONLY returned {decision} (must be UNSUPPORTED) for {fid}")

    # Detection gaps (test failures):
    # Forbidden actions from expected manifest
    for fa in expected.get("forbidden_actions", []):
        if decision == fa:
            detection.append(f"FORBIDDEN_ACTION({fa}): decision was {fa} for {fid}")

    # Plain visible prompt injection in OCR_EXTRACTION must not be allowed
    if "plain_text" in labels and "prompt_injection" in labels and profile == "OCR_EXTRACTION":
        if decision in ("ALLOW_ORIGINAL", "ALLOW_RECONSTRUCTED_ONLY"):
            detection.append(f"DETECTION_GAP: plain prompt allowed ({decision}) for {fid}")

    # must_not_release from expected manifest
    if expected.get("must_not_release") and grants:
        detection.append(f"MUST_NOT_RELEASE: {len(grants)} grant(s) for {fid}")

    return safety, detection


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    records_by_label: dict[str, list[dict]] = {}
    with MANIFEST_PATH.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                for lbl in rec.get("labels", []):
                    records_by_label.setdefault(lbl, []).append(rec)
            except json.JSONDecodeError:
                pass

    all_results: list[dict] = []
    all_safety: list[str] = []
    all_detection: list[str] = []
    scan_count = 0

    print("=== Targeted ARGUS Evaluation v2 ===\n")
    print(f"ClamAV wrapper: {CLAMAV_WRAPPER_DIR}/clamscan")

    # Verify ClamAV wrapper before starting
    wrapper_path = pathlib.Path(CLAMAV_WRAPPER_DIR) / "clamscan"
    if wrapper_path.exists():
        try:
            r = subprocess.run(
                [str(wrapper_path), "--version"],
                capture_output=True, text=True, timeout=5
            )
            print(f"ClamAV: {r.stdout.strip()[:60]}")
        except Exception as e:
            print(f"ClamAV wrapper check failed: {e}")
    else:
        print("WARNING: ClamAV wrapper missing — malware detection will ERROR")
    print()

    results_path = RESULTS_DIR / "targeted-results.jsonl"
    failures_path = RESULTS_DIR / "targeted-failures.jsonl"

    with results_path.open("w") as rf, failures_path.open("w") as ff:
        for label_filter, mode, profile, max_count in TARGETED_SCANS:
            candidates = records_by_label.get(label_filter, [])[:max_count]
            print(f"\n-- {label_filter} | {mode} | {profile} ({len(candidates)} fixtures) --")

            for rec in candidates:
                fid = rec["id"]
                rel = rec["path"]
                expected_sha = rec["sha256"]
                labels = rec.get("labels", [])

                image_path = CORPUS_ROOT / rel
                if not image_path.exists():
                    print(f"  MISSING: {fid}")
                    continue

                actual_sha = _sha256(image_path)
                if actual_sha != expected_sha:
                    print(f"  SHA_MISMATCH: {fid}")
                    continue

                try:
                    scan = _run_scan(image_path, mode, profile)
                except Exception:
                    scan = {
                        "report": {"_parse_error": traceback.format_exc()[:500]},
                        "duration": 0, "timed_out": False, "stderr": ""
                    }

                report = scan["report"]
                duration = scan["duration"]
                timed_out = scan["timed_out"]

                decision = (
                    "TIMEOUT" if timed_out
                    else "PARSE_ERROR" if "_parse_error" in report
                    else report.get("decision", {}).get("action", "UNKNOWN")
                    if isinstance(report.get("decision"), dict) else "UNKNOWN"
                )
                reason_codes = (
                    report.get("decision", {}).get("reason_codes", [])
                    if isinstance(report.get("decision"), dict) else []
                )
                grants = report.get("release_grants", [])

                safety_violations, detection_gaps = _check_invariants(
                    report, rec, fid, labels, profile, decision
                )
                all_safety.extend(safety_violations)
                all_detection.extend(detection_gaps)

                actually_tested = (
                    not timed_out
                    and "_parse_error" not in report
                    and decision not in ("UNSUPPORTED", "PARSE_ERROR", "FIXTURE_MISSING")
                )

                evidence = _extract_evidence(report) if not timed_out and "_parse_error" not in report else {}

                result_rec = {
                    "scan_id": report.get("scan_id", f"eval-{fid}"),
                    "input_id": fid,
                    "mode": mode,
                    "profile": profile,
                    "labels": labels,
                    "decision": decision,
                    "reason_codes": reason_codes,
                    "runtime_seconds": round(duration, 3),
                    "timed_out": timed_out,
                    "actually_tested": actually_tested,
                    "unsupported": decision == "UNSUPPORTED",
                    "release_grant_count": len(grants),
                    "release_grant_roles": [g.get("role") for g in grants],
                    "finding_count": len(report.get("findings", [])),
                    "safety_violations": safety_violations,
                    "detection_gaps": detection_gaps,
                    "worker_state": "timeout" if timed_out else ("completed" if not "_parse_error" in report else "parse_error"),
                    "stderr_snippet": scan["stderr"][:200],
                    "evidence": evidence,
                }
                all_results.append(result_rec)
                scan_count += 1

                rf.write(json.dumps(result_rec) + "\n")
                rf.flush()

                # Write all violation records to failures.jsonl
                if safety_violations or detection_gaps or timed_out:
                    ff.write(json.dumps(result_rec) + "\n")
                    ff.flush()

                has_safety = bool(safety_violations)
                has_detection = bool(detection_gaps)
                icon = "[SAFETY!]" if has_safety else ("[DETECTION_GAP]" if has_detection else "OK")
                print(f"  [{icon}] {fid}: {decision} ({duration:.1f}s) grants={len(grants)}")
                for v in safety_violations:
                    print(f"    SAFETY: {v}")
                for v in detection_gaps:
                    print(f"    DETECT: {v}")

    # Build summary
    decision_counts: dict[str, int] = {}
    for r in all_results:
        d = r["decision"]
        decision_counts[d] = decision_counts.get(d, 0) + 1

    actually_tested_count = sum(1 for r in all_results if r.get("actually_tested"))
    unsupported_count = sum(1 for r in all_results if r.get("unsupported"))
    timeout_count = sum(1 for r in all_results if r.get("timed_out"))

    unsafe_release_count = sum(
        1 for r in all_results
        if r.get("safety_violations") and any(
            "RELEASE_INVARIANT" in v or "MALWARE_CANARY" in v
            for v in r["safety_violations"]
        )
    )

    # Gate FAILS on any safety violation OR any detection gap
    gate = "FAIL" if (all_safety or all_detection) else "PASS"
    gate_reason = (
        f"safety violations present ({len(all_safety)})" if all_safety
        else f"detection gaps (FORBIDDEN_ACTION) present ({len(all_detection)})" if all_detection
        else "all invariants pass"
    )

    inv_report = {
        "generated_at": _now_iso(),
        "total_scans": scan_count,
        "actually_tested_scans": actually_tested_count,
        "unsupported_scans": unsupported_count,
        "timeout_count": timeout_count,
        "safety_violations": len(all_safety),
        "detection_gaps": len(all_detection),
        "unsafe_release_count": unsafe_release_count,
        "acceptance_gate": gate,
        "gate_reason": gate_reason,
        "all_safety_violations": all_safety[:200],
        "all_detection_gaps": all_detection[:200],
        "decisions": decision_counts,
    }
    (RESULTS_DIR / "security-invariants.json").write_text(json.dumps(inv_report, indent=2))

    # Performance
    runtimes = sorted(r["runtime_seconds"] for r in all_results)
    n = len(runtimes)
    def pct(p: float) -> float:
        return runtimes[min(int(n * p / 100), n - 1)] if runtimes else 0.0

    perf = {
        "generated_at": _now_iso(),
        "total_scans": n,
        "actually_tested_scans": actually_tested_count,
        "mean_duration_s": round(sum(runtimes) / n, 3) if runtimes else 0,
        "median_duration_s": round(pct(50), 3),
        "p95_duration_s": round(pct(95), 3),
        "max_duration_s": round(max(runtimes), 3) if runtimes else 0,
        "min_duration_s": round(min(runtimes), 3) if runtimes else 0,
        "timeout_rate": round(timeout_count / n, 4) if n else 0,
    }
    (RESULTS_DIR / "performance.json").write_text(json.dumps(perf, indent=2))

    print(f"\n=== Summary ===")
    print(f"Total scans:        {scan_count}")
    print(f"Actually tested:    {actually_tested_count} ({100*actually_tested_count//scan_count if scan_count else 0}%)")
    print(f"UNSUPPORTED:        {unsupported_count}")
    print(f"Safety violations:  {len(all_safety)}")
    print(f"Detection gaps:     {len(all_detection)}")
    print(f"Unsafe releases:    {unsafe_release_count}")
    print(f"Acceptance gate:    {gate} — {gate_reason}")
    print(f"Decisions:          {decision_counts}")

    if all_safety:
        print(f"\nSAFETY VIOLATIONS ({len(all_safety)}):")
        for v in all_safety[:30]:
            print(f"  {v}")
    if all_detection:
        print(f"\nDETECTION GAPS ({len(all_detection)}):")
        for v in all_detection[:30]:
            print(f"  {v}")

    print(f"\nResults:  {results_path}")
    print(f"Failures: {failures_path}")
    print(f"Invariants: {RESULTS_DIR / 'security-invariants.json'}")


if __name__ == "__main__":
    main()
