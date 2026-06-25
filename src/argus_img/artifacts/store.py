from __future__ import annotations

import json
import os
import tempfile
import fcntl
from pathlib import Path
from typing import Dict, Optional

from argus_img.core.enums import EpistemicState
from argus_img.core.exceptions import ArtifactAccessDenied, IntakeRejected
from argus_img.core.hashing import bare_sha256, sha256_bytes, sha256_file
from argus_img.core.models import Artifact, ArtifactTransformation, ModuleStatus


class ArtifactStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir.resolve()
        self.quarantine_dir = self.base_dir / "quarantine"
        self.artifacts_dir = self.base_dir / "artifacts" / "sha256"
        self.reports_dir = self.base_dir / "reports"
        self.jobs_dir = self.base_dir / "jobs"
        self.temporary_dir = self.base_dir / "temporary"
        self.index_path = self.base_dir / "artifacts" / "index.json"
        for directory in [
            self.quarantine_dir,
            self.artifacts_dir,
            self.reports_dir,
            self.jobs_dir,
            self.temporary_dir,
            self.index_path.parent,
        ]:
            directory.mkdir(parents=True, exist_ok=True)

    def _safe_relative(self, path: Path) -> str:
        resolved = path.resolve()
        if not str(resolved).startswith(str(self.base_dir) + os.sep):
            raise ArtifactAccessDenied("artifact path escapes data directory")
        return str(resolved.relative_to(self.base_dir))

    def _artifact_path_for_hash(self, digest: str, quarantine: bool) -> Path:
        bare = bare_sha256(digest)
        if quarantine:
            return self.quarantine_dir / bare[:2] / bare[2:4] / bare
        return self.artifacts_dir / bare[:2] / bare[2:4] / bare

    def _atomic_write(self, dest: Path, data: bytes) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            return
        with tempfile.NamedTemporaryFile(dir=str(dest.parent), delete=False) as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        os.replace(str(tmp_path), str(dest))

    def _load_index(self) -> Dict[str, dict]:
        if not self.index_path.exists():
            return {}
        with self.index_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _save_index(self, index: Dict[str, dict]) -> None:
        payload = json.dumps(index, sort_keys=True, indent=2)
        with tempfile.NamedTemporaryFile(dir=str(self.index_path.parent), delete=False, mode="w", encoding="utf-8") as tmp:
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        os.replace(str(tmp_path), str(self.index_path))

    def _index_artifact(self, artifact: Artifact) -> None:
        lock_path = self.index_path.parent / ".index.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            index = self._load_index()
            index[artifact.artifact_id] = artifact.model_dump(mode="json")
            self._save_index(index)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def create_job_dir(self, scan_id: str) -> Path:
        safe = "".join(ch for ch in scan_id if ch.isalnum() or ch in {"-", "_"})
        if safe != scan_id:
            raise IntakeRejected("invalid scan id")
        job_dir = (self.jobs_dir / safe).resolve()
        if not str(job_dir).startswith(str(self.jobs_dir.resolve()) + os.sep):
            raise IntakeRejected("job directory escapes jobs root")
        job_dir.mkdir(parents=True, exist_ok=False)
        return job_dir

    def store_bytes(
        self,
        data: bytes,
        artifact_id: str,
        media_type: str,
        created_by: str,
        role: str,
        quarantine: bool = False,
        release_eligible: bool = False,
        derived_from: Optional[str] = None,
        transformation: Optional[ArtifactTransformation] = None,
        width: Optional[int] = None,
        height: Optional[int] = None,
        frame_index: Optional[int] = None,
    ) -> Artifact:
        digest = sha256_bytes(data)
        dest = self._artifact_path_for_hash(digest, quarantine=quarantine)
        self._atomic_write(dest, data)
        artifact = Artifact(
            artifact_id=artifact_id,
            sha256=digest,
            media_type=media_type,
            size_bytes=len(data),
            created_by=created_by,
            derived_from=derived_from,
            transformation=transformation,
            storage_reference=self._safe_relative(dest),
            release_eligible=release_eligible,
            role=role,
            width=width,
            height=height,
            frame_index=frame_index,
        )
        self._index_artifact(artifact)
        return artifact

    def store_file(
        self,
        path: Path,
        artifact_id: str,
        media_type: str,
        created_by: str,
        role: str,
        quarantine: bool = False,
        release_eligible: bool = False,
        max_bytes: Optional[int] = None,
    ) -> Artifact:
        if path.is_symlink():
            raise IntakeRejected("symlink inputs are not accepted")
        digest = sha256_file(path)
        size = path.stat().st_size
        if max_bytes is not None and size > max_bytes:
            raise IntakeRejected("input exceeds maximum byte limit")
        dest = self._artifact_path_for_hash(digest, quarantine=quarantine)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            with path.open("rb") as src, tempfile.NamedTemporaryFile(dir=str(dest.parent), delete=False) as tmp:
                copied = 0
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    copied += len(chunk)
                    if max_bytes is not None and copied > max_bytes:
                        raise IntakeRejected("input exceeds maximum byte limit")
                    tmp.write(chunk)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = Path(tmp.name)
            os.replace(str(tmp_path), str(dest))
        artifact = Artifact(
            artifact_id=artifact_id,
            sha256=digest,
            media_type=media_type,
            size_bytes=size,
            created_by=created_by,
            storage_reference=self._safe_relative(dest),
            release_eligible=release_eligible,
            role=role,
        )
        self._index_artifact(artifact)
        return artifact

    def resolve_path(self, artifact: Artifact) -> Path:
        path = (self.base_dir / artifact.storage_reference).resolve()
        if path.is_symlink() or not str(path).startswith(str(self.base_dir) + os.sep):
            raise ArtifactAccessDenied("artifact path is not contained")
        return path

    def get_artifact(self, artifact_id: str, release_only: bool = True) -> Artifact:
        index = self._load_index()
        raw = index.get(artifact_id)
        if raw is None:
            raise ArtifactAccessDenied("unknown artifact")
        artifact = Artifact.model_validate(raw)
        if release_only and not artifact.release_eligible:
            raise ArtifactAccessDenied("artifact is not release eligible")
        return artifact

    def save_report(self, scan_id: str, report_json: str) -> Path:
        dest = (self.reports_dir / (scan_id + ".json")).resolve()
        if not str(dest).startswith(str(self.reports_dir.resolve()) + os.sep):
            raise ArtifactAccessDenied("report path escapes reports root")
        tmp = dest.with_suffix(".tmp")
        tmp.write_text(report_json, encoding="utf-8")
        os.replace(str(tmp), str(dest))
        return dest

    def load_report(self, scan_id: str) -> str:
        path = (self.reports_dir / (scan_id + ".json")).resolve()
        if not str(path).startswith(str(self.reports_dir.resolve()) + os.sep) or not path.exists():
            raise ArtifactAccessDenied("unknown report")
        return path.read_text(encoding="utf-8")

    def capability_status(self) -> ModuleStatus:
        return ModuleStatus(name="artifact_store", status=EpistemicState.CONFIRMED, reason=str(self.base_dir))
