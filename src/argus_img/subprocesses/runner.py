from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ToolResult:
    args: List[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    error: Optional[str] = None
    duration_ms: float = 0.0


def executable_version(executable: str, version_arg: str = "--version", timeout: float = 2.0) -> Optional[str]:
    path = shutil.which(executable)
    if not path:
        return None
    result = run_tool([path, version_arg], timeout=timeout, max_output_bytes=2048)
    if result.returncode is None:
        return None
    first = (result.stdout or result.stderr).splitlines()
    return first[0][:200] if first else None


def run_tool(
    args: List[str],
    timeout: float,
    cwd: Optional[Path] = None,
    max_output_bytes: int = 1_000_000,
    env: Optional[Dict[str, str]] = None,
) -> ToolResult:
    if not args:
        return ToolResult(args=args, returncode=None, stdout="", stderr="", error="empty command")
    executable = shutil.which(args[0]) if os.sep not in args[0] else args[0]
    if not executable or not Path(executable).exists():
        return ToolResult(args=args, returncode=None, stdout="", stderr="", error="executable_not_found")
    clean_env = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(Path(cwd or Path.cwd()).resolve()),
    }
    if env:
        clean_env.update({key: value for key, value in env.items() if key in {"PATH", "LANG", "LC_ALL", "HOME"}})
    start = time.monotonic()
    process = None
    try:
        process = subprocess.Popen(
            [executable] + args[1:],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd or Path.cwd()),
            env=clean_env,
            shell=False,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            stdout, stderr = process.communicate()
        else:
            stdout, stderr = b"", b""
    except OSError as exc:
        return ToolResult(
            args=args,
            returncode=None,
            stdout="",
            stderr="",
            error=str(exc),
            duration_ms=(time.monotonic() - start) * 1000,
        )
    duration = (time.monotonic() - start) * 1000
    stdout_text = stdout[:max_output_bytes].decode("utf-8", errors="replace")
    stderr_text = stderr[:max_output_bytes].decode("utf-8", errors="replace")
    if len(stdout) > max_output_bytes:
        stdout_text += "\n[stdout truncated]"
    if len(stderr) > max_output_bytes:
        stderr_text += "\n[stderr truncated]"
    return ToolResult(
        args=args,
        returncode=None if timed_out else process.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        timed_out=timed_out,
        duration_ms=duration,
    )

