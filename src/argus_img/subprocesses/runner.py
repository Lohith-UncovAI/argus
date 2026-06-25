from __future__ import annotations

import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from argus_img.subprocesses.limits import ToolResourceLimits


@dataclass
class ToolResult:
    args: List[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    error: Optional[str] = None
    duration_ms: float = 0.0


def _resolve_executable(command: str) -> Optional[str]:
    if os.sep in command:
        path = Path(command).resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return None
    resolved = shutil.which(command)
    if not resolved:
        return None
    path = Path(resolved).resolve()
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return None


def executable_version(executable: str, version_arg: str = "--version", timeout: float = 2.0) -> Optional[str]:
    path = _resolve_executable(executable)
    if not path:
        return None
    result = run_tool([path, version_arg], timeout=timeout, max_output_bytes=2048)
    if result.returncode is None:
        return None
    first = (result.stdout or result.stderr).splitlines()
    return first[0][:200] if first else None


def _limit_append(buffer: bytearray, chunk: bytes, max_output_bytes: int) -> bool:
    if len(buffer) >= max_output_bytes:
        return True
    remaining = max_output_bytes - len(buffer)
    buffer.extend(chunk[:remaining])
    return len(chunk) > remaining


def _resource_preexec(limits: Optional[ToolResourceLimits]):
    if limits is None or os.name != "posix":
        return None

    def apply_limits() -> None:
        try:
            import resource

            if limits.cpu_seconds is not None:
                resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
            if limits.address_space_bytes is not None:
                resource.setrlimit(resource.RLIMIT_AS, (limits.address_space_bytes, limits.address_space_bytes))
            if limits.file_size_bytes is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limits.file_size_bytes, limits.file_size_bytes))
            if limits.open_files is not None:
                resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
        except Exception:
            os._exit(127)

    return apply_limits


def run_tool(
    args: List[str],
    timeout: float,
    cwd: Optional[Path] = None,
    max_output_bytes: int = 1_000_000,
    env: Optional[Dict[str, str]] = None,
    strict_env: bool = True,
    resource_limits: Optional[ToolResourceLimits] = None,
) -> ToolResult:
    if not args:
        return ToolResult(args=args, returncode=None, stdout="", stderr="", error="empty command")
    executable = _resolve_executable(args[0])
    if not executable:
        return ToolResult(args=args, returncode=None, stdout="", stderr="", error="executable_not_found")
    resolved_args = [executable] + args[1:]
    cwd_path = Path(cwd or Path.cwd()).resolve()
    start = time.monotonic()
    process = None
    timed_out = False
    stdout = b""
    stderr = b""
    try:
        with tempfile.TemporaryDirectory(prefix="argus-tool-home-") as home:
            clean_env = {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": home,
                "PATH": str(Path(executable).parent),
            }
            if not strict_env:
                clean_env["PATH"] = os.environ.get("PATH", clean_env["PATH"])
            if env:
                allowed = {"LANG", "LC_ALL", "TZ"} if strict_env else {"PATH", "LANG", "LC_ALL", "HOME", "TZ"}
                clean_env.update({key: value for key, value in env.items() if key in allowed})
                if strict_env:
                    clean_env["HOME"] = home
                    clean_env["PATH"] = str(Path(executable).parent)
            process = subprocess.Popen(
                resolved_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd_path),
                env=clean_env,
                shell=False,
                start_new_session=True,
                preexec_fn=_resource_preexec(resource_limits),
            )
            stdout_buffer = bytearray()
            stderr_buffer = bytearray()
            stdout_truncated = False
            stderr_truncated = False
            killed = False
            selector = selectors.DefaultSelector()
            if process.stdout is not None:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            if process.stderr is not None:
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            deadline = start + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 and not killed:
                    timed_out = True
                    killed = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        process.kill()
                events = selector.select(timeout=0.05 if remaining <= 0 else min(0.05, remaining))
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if key.data == "stdout":
                        stdout_truncated = _limit_append(stdout_buffer, chunk, max_output_bytes) or stdout_truncated
                    else:
                        stderr_truncated = _limit_append(stderr_buffer, chunk, max_output_bytes) or stderr_truncated
            process.wait(timeout=1)
            stdout = bytes(stdout_buffer)
            stderr = bytes(stderr_buffer)
            if stdout_truncated:
                stdout += b"\n[stdout truncated]"
            if stderr_truncated:
                stderr += b"\n[stderr truncated]"
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait(timeout=1)
    except OSError as exc:
        return ToolResult(
            args=resolved_args,
            returncode=None,
            stdout="",
            stderr="",
            error=str(exc),
            duration_ms=(time.monotonic() - start) * 1000,
        )
    duration = (time.monotonic() - start) * 1000
    return ToolResult(
        args=resolved_args,
        returncode=None if timed_out else process.returncode,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        duration_ms=duration,
    )
