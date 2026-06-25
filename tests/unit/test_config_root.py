import subprocess
import sys
from pathlib import Path

from argus_img.core.config import load_config


def test_load_config_works_outside_repository_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.default_policy == "agent-with-tools"


def test_cli_validate_rules_works_outside_repository_cwd(tmp_path):
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-m", "argus_img.cli.main", "validate-rules"],
        cwd=tmp_path,
        env={"PYTHONPATH": str(root / "src")},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert '"status": "ok"' in result.stdout


def test_packaged_config_resources_match_repository_config():
    root = Path(__file__).resolve().parents[2]
    package_config = root / "src" / "argus_img" / "config"
    for source in (root / "config").rglob("*.yaml"):
        relative = source.relative_to(root / "config")
        assert (package_config / relative).read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
