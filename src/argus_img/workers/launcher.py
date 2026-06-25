"""Control-process worker launcher.

Launches the parser worker as a disposable subprocess using the `spawn`
start method (never `fork`).  The control process:

1. Serialises a WorkerRequest to JSON.
2. Starts a fresh Python interpreter running parser_worker.py via subprocess.
3. Sends the request over stdin.
4. Reads the response from stdout with a bounded byte limit.
5. Validates the response (paths, hashes, schema, artifact ownership).
6. Returns a validated WorkerResponse or raises on failure.

The worker has no access to the control process's memory, database
connections, or credentials.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from argus_img.workers.errors import (
    WorkerCrashError,
    WorkerResponseError,
    WorkerTimeoutError,
)
from argus_img.workers.protocol import MAX_RESPONSE_BYTES, WorkerRequest, WorkerResponse
from argus_img.workers.validation import parse_and_validate_response


def _worker_env() -> dict:
    """Return a minimal environment for the worker subprocess."""
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.path.dirname(sys.executable),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "ARGUS_WORKER": "1",
        "ARGUS_NETWORK_DISABLED": "1",
    }


def launch_parser_worker(
    request: WorkerRequest,
    job_dir: Path,
    wall_clock_timeout: float = 90.0,
) -> WorkerResponse:
    """Launch a disposable parser worker and return its validated response.

    Raises:
        WorkerTimeoutError: if the worker exceeds wall_clock_timeout.
        WorkerCrashError: if the worker exits non-zero without a valid response.
        WorkerResponseError: if the response fails validation.
    """
    request_json = request.model_dump_json()
    worker_module = "argus_img.workers.parser_worker"

    process: Optional[subprocess.Popen] = None
    started = time.monotonic()
    stdout_chunks = []
    total_bytes = 0
    timed_out = False

    try:
        process = subprocess.Popen(
            [sys.executable, "-m", worker_module],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_worker_env(),
            shell=False,
            start_new_session=True,
        )

        # Send request and close stdin to signal end-of-input.
        try:
            process.stdin.write(request_json.encode("utf-8"))
            process.stdin.flush()
            process.stdin.close()
        except BrokenPipeError:
            pass

        # Read stdout with a byte ceiling and a wall-clock deadline.
        deadline = started + wall_clock_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if total_bytes >= MAX_RESPONSE_BYTES:
                break
            chunk = process.stdout.read(min(65536, MAX_RESPONSE_BYTES - total_bytes))
            if not chunk:
                break
            stdout_chunks.append(chunk)
            total_bytes += len(chunk)

        if timed_out:
            # Kill the entire process group
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                try:
                    process.kill()
                except OSError:
                    pass
            process.wait(timeout=5)
            raise WorkerTimeoutError(
                "parser worker exceeded wall-clock timeout of %.1fs" % wall_clock_timeout
            )

        process.wait(timeout=max(1.0, wall_clock_timeout - (time.monotonic() - started)))
        returncode = process.returncode

    except WorkerTimeoutError:
        raise
    except Exception as exc:
        if process is not None:
            try:
                process.kill()
                process.wait(timeout=2)
            except Exception:
                pass
        raise WorkerCrashError("failed to launch parser worker: %s" % exc) from exc

    raw_response = b"".join(stdout_chunks)

    if returncode != 0 and not raw_response:
        raise WorkerCrashError(
            "parser worker exited with code %d and no output" % returncode
        )

    if not raw_response:
        raise WorkerCrashError("parser worker produced no output (rc=%s)" % returncode)

    return parse_and_validate_response(raw_response, request.scan_id, job_dir)
