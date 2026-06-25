"""Control-process worker launcher.

Launches the parser worker as a disposable subprocess using the `spawn`
start method (never `fork`).  The control process:

1. Serialises a WorkerRequest to JSON.
2. Starts a fresh Python interpreter running parser_worker.py via subprocess.
3. Sends the request over stdin and communicates with a wall-clock timeout.
4. Drains stdout and stderr concurrently so the worker cannot hang on a full
   pipe even when stdout is silent and stderr is flooded.
5. Kills the entire process group on timeout.
6. Validates the response (paths, hashes, schema, artifact ownership).
7. Returns a validated WorkerResponse or raises on failure.

The worker has no access to the control process's memory, database
connections, or credentials.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

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

    Uses subprocess.communicate(timeout=...) so stdout and stderr are drained
    concurrently by two internal threads.  The worker cannot hang the control
    process by filling stderr while the control process is blocked reading
    stdout.

    Raises:
        WorkerTimeoutError: if the worker exceeds wall_clock_timeout.
        WorkerCrashError: if the worker exits non-zero without a valid response.
        WorkerResponseError: if the response fails validation.
    """
    request_json = request.model_dump_json().encode("utf-8")
    worker_module = "argus_img.workers.parser_worker"

    process: subprocess.Popen | None = None

    try:
        process = subprocess.Popen(
            [sys.executable, "-m", worker_module],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_worker_env(),
            shell=False,
            start_new_session=True,  # new process group for reliable kill
        )

        try:
            raw_stdout, _stderr = process.communicate(
                input=request_json,
                timeout=wall_clock_timeout,
            )
        except subprocess.TimeoutExpired:
            # Kill the entire process group — catches children spawned by the worker.
            pgid = process.pid
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.communicate(timeout=5)
            except Exception:
                pass
            raise WorkerTimeoutError(
                "parser worker exceeded wall-clock timeout of %.1fs" % wall_clock_timeout
            )

    except WorkerTimeoutError:
        raise
    except Exception as exc:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.communicate(timeout=2)
            except Exception:
                pass
        raise WorkerCrashError("failed to launch parser worker: %s" % exc) from exc

    returncode = process.returncode

    # Enforce the response size ceiling on what we actually received.
    if len(raw_stdout) > MAX_RESPONSE_BYTES:
        raise WorkerCrashError(
            "parser worker stdout exceeded %d bytes" % MAX_RESPONSE_BYTES
        )

    if returncode != 0 and not raw_stdout:
        raise WorkerCrashError(
            "parser worker exited with code %d and no output" % returncode
        )

    if not raw_stdout:
        raise WorkerCrashError("parser worker produced no output (rc=%s)" % returncode)

    return parse_and_validate_response(raw_stdout, request.scan_id, job_dir)
