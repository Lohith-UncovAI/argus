import sys
from pathlib import Path

from argus_img.subprocesses.runner import run_tool


def test_nonexistent_executable_is_structured_error():
    result = run_tool(["definitely-not-installed-argus-tool"], timeout=1)
    assert result.error == "executable_not_found"
    assert result.returncode is None


def test_timeout_is_reported_and_process_is_killed():
    result = run_tool([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.1)
    assert result.timed_out is True
    assert result.returncode is None


def test_shell_metacharacters_are_passed_as_arguments_not_executed(tmp_path):
    marker = tmp_path / "marker"
    result = run_tool([sys.executable, "-c", "import sys; print(sys.argv[1])", ";", "touch", str(marker)], timeout=1)
    assert result.returncode == 0
    assert not marker.exists()


def test_output_is_streamed_and_truncated():
    result = run_tool(
        [sys.executable, "-c", "import sys; sys.stdout.write('A' * 200000)"],
        timeout=2,
        max_output_bytes=1024,
    )
    assert result.returncode == 0
    assert len(result.stdout) < 1200
    assert "[stdout truncated]" in result.stdout


def test_strict_environment_uses_isolated_home_and_minimal_path():
    result = run_tool(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('HOME')); print(os.environ.get('PATH'))",
        ],
        timeout=2,
    )
    home, path = result.stdout.strip().splitlines()
    assert "argus-tool-home-" in home
    assert path == str(Path(sys.executable).resolve().parent)
