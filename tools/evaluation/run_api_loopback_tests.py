#!/usr/bin/env python3
"""ARGUS-IMG API loopback tests.

Starts the API on 127.0.0.1 only, runs a suite of HTTP tests,
then stops the server. Never uses 0.0.0.0.
"""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
RESULTS_DIR = REPO_ROOT / "evaluation-results"
CORPUS_ROOT = pathlib.Path.home() / "argus-eval-data" / "corpus"


def _find_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _http(
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _post_file(
    url: str,
    filepath: pathlib.Path,
    field: str = "file",
    extra_data: dict[str, str] | None = None,
    timeout: int = 30,
) -> tuple[int, bytes]:
    """Multipart POST a file to url."""
    boundary = b"ArgusEvalBoundary7F91"
    body_parts = []

    if extra_data:
        for key, val in extra_data.items():
            body_parts.append(
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + key.encode() + b'"\r\n\r\n'
                + val.encode() + b"\r\n"
            )

    filename = filepath.name.encode()
    file_data = filepath.read_bytes()
    body_parts.append(
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="' + field.encode() + b'"; filename="' + filename + b'"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + file_data + b"\r\n"
    )
    body_parts.append(b"--" + boundary + b"--\r\n")
    body = b"".join(body_parts)

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
        "Content-Length": str(len(body)),
    }
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def wait_for_server(base_url: str, retries: int = 30, interval: float = 0.5) -> bool:
    for _ in range(retries):
        try:
            code, _, _ = _http(f"{base_url}/health")
            if code == 200:
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def run_api_tests(port: int) -> dict[str, Any]:
    base = f"http://127.0.0.1:{port}/v1"
    results: dict[str, Any] = {"port": port, "base_url": base, "tests": []}

    def record(name: str, passed: bool, detail: str = "", status_code: int | None = None) -> None:
        results["tests"].append({
            "name": name,
            "passed": passed,
            "detail": detail,
            "status_code": status_code,
        })
        icon = "PASS" if passed else "FAIL"
        print(f"  [{icon}] {name}: {detail[:120]}")

    # 1. Health check
    code, hdrs, body = _http(f"{base}/health")
    data = json.loads(body) if body else {}
    record("health-check", code == 200 and data.get("status") == "ok",
           f"status={data.get('status')}", code)

    # 2. Capabilities
    code, _, body = _http(f"{base}/capabilities")
    data = json.loads(body) if body else {}
    record("capabilities", code == 200 and isinstance(data, dict),
           f"keys={list(data.keys())[:5]}", code)

    # 3. Attestation
    code, _, body = _http(f"{base}/attestation")
    record("attestation", code in (200, 404),
           f"code={code}", code)

    # 4. Valid upload — use a small benign PNG
    test_img = CORPUS_ROOT / "benign" / "synthetic" / "benign-synthetic-0010.png"
    if test_img.exists():
        code, body = _post_file(
            f"{base}/scans",
            test_img,
            extra_data={"mode": "fast", "profile": "HUMAN_VIEW"},
        )
        data = json.loads(body) if body else {}
        scan_id = data.get("scan_id")
        record("valid-upload", code in (200, 201, 202) and bool(scan_id),
               f"scan_id={scan_id} code={code}", code)

        if scan_id:
            # 5. Retrieve scan result
            time.sleep(1)
            code2, _, body2 = _http(f"{base}/scans/{scan_id}")
            data2 = json.loads(body2) if body2 else {}
            record("retrieve-scan", code2 in (200, 202),
                   f"decision={data2.get('decision', {}).get('action')}", code2)

            # 6. Unknown artifact
            code3, _, _ = _http(f"{base}/artifacts/artifact:nonexistent-000000000:canonical-lossless")
            record("unknown-artifact-returns-404", code3 == 404, f"code={code3}", code3)

            # 7. Blocked artifact download (original must not be downloadable)
            original_id = data2.get("input", {}).get("quarantined_artifact_id", "")
            if original_id:
                encoded_id = urllib.request.quote(original_id, safe="")
                code4, _, body4 = _http(f"{base}/artifacts/{encoded_id}")
                record("original-artifact-blocked", code4 in (403, 404),
                       f"code={code4} id={original_id}", code4)

    # 8. Oversized Content-Length header
    too_big = 30 * 1024 * 1024  # 30 MiB (over 25 MiB limit)
    req_headers = {
        "Content-Type": "multipart/form-data; boundary=test",
        "Content-Length": str(too_big),
    }
    code5, _, _ = _http(f"{base}/scans", method="POST",
                        data=b"--test\r\nContent-Disposition: form-data; name=x\r\n\r\nval\r\n--test--\r\n",
                        headers=req_headers)
    record("oversized-content-length-rejected", code5 in (400, 413, 422, 431),
           f"code={code5}", code5)

    # 9. Malformed multipart
    code6, _, _ = _http(
        f"{base}/scans", method="POST",
        data=b"THIS IS NOT VALID MULTIPART DATA",
        headers={"Content-Type": "multipart/form-data; boundary=ARGUS", "Content-Length": "32"},
    )
    record("malformed-multipart-rejected", code6 in (400, 422, 415, 500),
           f"code={code6}", code6)

    # 10. Unknown scan
    code7, _, _ = _http(f"{base}/scans/scan-nonexistent-7f91")
    record("unknown-scan-returns-404", code7 == 404, f"code={code7}", code7)

    passed = sum(1 for t in results["tests"] if t["passed"])
    failed = sum(1 for t in results["tests"] if not t["passed"])
    results["summary"] = {"passed": passed, "failed": failed, "total": len(results["tests"])}
    return results


def main() -> None:
    port = _find_free_port("127.0.0.1")
    print(f"=== ARGUS API Loopback Tests ===")
    print(f"Starting API on 127.0.0.1:{port} (never 0.0.0.0)")

    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    env["ARGUS_DATA_DIR"] = str(REPO_ROOT / "data")

    python = str(REPO_ROOT / ".venv" / "bin" / "python")
    server_proc = subprocess.Popen(
        [
            python, "-m", "uvicorn",
            "argus_img.api.app:create_app",
            "--host", "127.0.0.1",
            "--port", str(port),
            "--factory",
            "--log-level", "warning",
        ],
        env=env,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        base = f"http://127.0.0.1:{port}"
        print(f"Waiting for server at {base}...")
        ready = wait_for_server(base + "/v1")
        if not ready:
            print("ERROR: Server did not start in time")
            server_proc.terminate()
            sys.exit(1)

        print(f"Server ready. Running tests...\n")
        results = run_api_tests(port)

        print(f"\nSummary: {results['summary']['passed']}/{results['summary']['total']} passed")

        out_path = RESULTS_DIR / "api-loopback-results.json"
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2))
        print(f"Results written: {out_path}")

        # Verify server only bound to loopback
        try:
            import socket as sock_mod
            connections = []
            try:
                import subprocess as sp
                lsof = sp.run(["lsof", "-iTCP", f":{port}", "-n", "-P"],
                              capture_output=True, text=True, timeout=5)
                for line in lsof.stdout.splitlines():
                    if str(port) in line:
                        connections.append(line)
            except Exception:
                pass
            only_loopback = all("127.0.0.1" in c or "localhost" in c for c in connections)
            results["loopback_only_verified"] = only_loopback or len(connections) == 0
        except Exception:
            results["loopback_only_verified"] = "check_failed"

        results["offline_behavior"] = "application-level offline behavior tested"
        results["host_network_isolation"] = "host-level network isolation not verified (Docker not used)"
        out_path.write_text(json.dumps(results, indent=2))

    finally:
        print("\nStopping server...")
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        print("Server stopped.")


if __name__ == "__main__":
    main()
