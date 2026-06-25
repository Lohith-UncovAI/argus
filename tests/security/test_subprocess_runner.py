import sys

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

