import shutil
from pathlib import Path


def cleanup_job_dir(path: Path) -> None:
    if path.exists() and path.is_dir():
        shutil.rmtree(str(path))

