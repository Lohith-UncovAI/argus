from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from argus_img.core.enums import EpistemicState
from argus_img.core.exceptions import ArtifactAccessDenied, ArtifactNotReleased, IntakeRejected
from argus_img.core.hashing import bare_sha256, sha256_bytes
from argus_img.core.models import Artifact, ArtifactTransformation, ModuleStatus, Observation, PolicyDecision, ReleaseGrant


SECURE_DIR_MODE = 0o700
SECURE_FILE_MODE = 0o600


class ArtifactStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir.resolve()
        self.quarantine_dir = self.base_dir / "quarantine"
        self.artifacts_dir = self.base_dir / "artifacts" / "sha256"
        self.reports_dir = self.base_dir / "reports"
        self.jobs_dir = self.base_dir / "jobs"
        self.temporary_dir = self.base_dir / "temporary"
        self.forensic_dir = self.base_dir / "forensic"
        self.db_path = self.base_dir / "argus.sqlite3"
        for directory in [
            self.base_dir,
            self.quarantine_dir,
            self.artifacts_dir,
            self.reports_dir,
            self.jobs_dir,
            self.temporary_dir,
            self.forensic_dir,
            self.db_path.parent,
        ]:
            directory.mkdir(parents=True, exist_ok=True)
            self._chmod(directory, SECURE_DIR_MODE)
        self._init_db()

    def _chmod(self, path: Path, mode: int) -> None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        for path in self.base_dir.glob("argus.sqlite3*"):
            if path.is_file():
                self._chmod(path, SECURE_FILE_MODE)
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    storage_reference TEXT NOT NULL,
                    role TEXT NOT NULL,
                    release_eligible INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
                CREATE INDEX IF NOT EXISTS idx_artifacts_role ON artifacts(role);

                CREATE TABLE IF NOT EXISTS release_grants (
                    grant_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
                );
                CREATE INDEX IF NOT EXISTS idx_release_scan ON release_grants(scan_id);
                CREATE INDEX IF NOT EXISTS idx_release_artifact ON release_grants(artifact_id);

                CREATE TABLE IF NOT EXISTS reports (
                    scan_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS forensic_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    location_json TEXT NOT NULL,
                    text_sha256 TEXT NOT NULL,
                    text_length INTEGER NOT NULL,
                    raw_text TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_forensic_scan ON forensic_evidence(scan_id);

                CREATE TABLE IF NOT EXISTS orphaned_artifacts (
                    storage_reference TEXT PRIMARY KEY,
                    sha256 TEXT,
                    size_bytes INTEGER NOT NULL,
                    recovered_at REAL NOT NULL
                );
                """
            )
        for path in self.base_dir.glob("argus.sqlite3*"):
            if path.is_file():
                self._chmod(path, SECURE_FILE_MODE)

    def _safe_relative(self, path: Path) -> str:
        resolved = path.resolve()
        if resolved == self.base_dir:
            raise ArtifactAccessDenied("artifact path points at data directory")
        if not str(resolved).startswith(str(self.base_dir) + os.sep):
            raise ArtifactAccessDenied("artifact path escapes data directory")
        return str(resolved.relative_to(self.base_dir))

    def _artifact_path_for_hash(self, digest: str, quarantine: bool) -> Path:
        bare = bare_sha256(digest)
        root = self.quarantine_dir if quarantine else self.artifacts_dir
        return root / bare[:2] / bare[2:4] / bare

    def _atomic_write(self, dest: Path, data: bytes) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        self._chmod(dest.parent, SECURE_DIR_MODE)
        if dest.exists():
            self._chmod(dest, SECURE_FILE_MODE)
            return
        with tempfile.NamedTemporaryFile(dir=str(dest.parent), delete=False) as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        self._chmod(tmp_path, SECURE_FILE_MODE)
        os.replace(str(tmp_path), str(dest))
        self._chmod(dest, SECURE_FILE_MODE)

    def _copy_and_hash_bounded(self, source: Path, max_bytes: Optional[int], quarantine: bool) -> tuple[str, int, Path]:
        if source.is_symlink():
            raise IntakeRejected("symlink inputs are not accepted")
        root = self.quarantine_dir if quarantine else self.temporary_dir
        root.mkdir(parents=True, exist_ok=True)
        self._chmod(root, SECURE_DIR_MODE)
        import hashlib

        digest = hashlib.sha256()
        copied = 0
        tmp_path: Optional[Path] = None
        try:
            with source.open("rb") as src, tempfile.NamedTemporaryFile(dir=str(root), delete=False) as tmp:
                tmp_path = Path(tmp.name)
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    copied += len(chunk)
                    if max_bytes is not None and copied > max_bytes:
                        raise IntakeRejected("input exceeds maximum byte limit")
                    digest.update(chunk)
                    tmp.write(chunk)
                tmp.flush()
                os.fsync(tmp.fileno())
            if copied == 0:
                raise IntakeRejected("empty inputs are not accepted")
            self._chmod(tmp_path, SECURE_FILE_MODE)
            return "sha256:" + digest.hexdigest(), copied, tmp_path
        except Exception:
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise

    def _index_artifact(self, artifact: Artifact) -> None:
        payload = artifact.model_dump_json()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO artifacts
                    (artifact_id, sha256, storage_reference, role, release_eligible, payload, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.artifact_id,
                    artifact.sha256,
                    artifact.storage_reference,
                    artifact.role,
                    1 if artifact.release_eligible else 0,
                    payload,
                    time.time(),
                ),
            )

    def update_artifact(self, artifact: Artifact) -> None:
        self._index_artifact(artifact)

    def _artifact_from_row(self, row: sqlite3.Row) -> Artifact:
        return Artifact.model_validate_json(row["payload"])

    def _update_artifact_release_flag(self, artifact_id: str, release_eligible: bool) -> Artifact:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise ArtifactAccessDenied("unknown artifact")
            artifact = Artifact.model_validate_json(row["payload"])
            artifact.release_eligible = release_eligible
            connection.execute(
                "UPDATE artifacts SET release_eligible = ?, payload = ? WHERE artifact_id = ?",
                (1 if release_eligible else 0, artifact.model_dump_json(), artifact_id),
            )
        return artifact

    def create_job_dir(self, scan_id: str) -> Path:
        safe = "".join(ch for ch in scan_id if ch.isalnum() or ch in {"-", "_"})
        if safe != scan_id:
            raise IntakeRejected("invalid scan id")
        job_dir = (self.jobs_dir / safe).resolve()
        if not str(job_dir).startswith(str(self.jobs_dir.resolve()) + os.sep):
            raise IntakeRejected("job directory escapes jobs root")
        job_dir.mkdir(parents=True, exist_ok=False)
        self._chmod(job_dir, SECURE_DIR_MODE)
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
        representation_id: Optional[str] = None,
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
            release_eligible=False,
            role=role,
            width=width,
            height=height,
            frame_index=frame_index,
            representation_id=representation_id,
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
        digest, size, tmp_path = self._copy_and_hash_bounded(path, max_bytes, quarantine=quarantine)
        dest = self._artifact_path_for_hash(digest, quarantine=quarantine)
        dest.parent.mkdir(parents=True, exist_ok=True)
        self._chmod(dest.parent, SECURE_DIR_MODE)
        if dest.exists():
            tmp_path.unlink()
        else:
            os.replace(str(tmp_path), str(dest))
            self._chmod(dest, SECURE_FILE_MODE)
        artifact = Artifact(
            artifact_id=artifact_id,
            sha256=digest,
            media_type=media_type,
            size_bytes=size,
            created_by=created_by,
            storage_reference=self._safe_relative(dest),
            release_eligible=False,
            role=role,
        )
        self._index_artifact(artifact)
        return artifact

    def grant_release(self, scan_id: str, artifact: Artifact, decision: PolicyDecision, reason: str) -> ReleaseGrant:
        if artifact.role == "original" or artifact.role.startswith("frame-"):
            raise ArtifactAccessDenied("artifact role cannot be released")
        if artifact.role not in {"canonical_lossy", "redacted"}:
            raise ArtifactAccessDenied("artifact role is analysis-only")
        grant = ReleaseGrant(
            grant_id="grant:%s:%s" % (scan_id, artifact.artifact_id.rsplit(":", 1)[-1]),
            scan_id=scan_id,
            artifact_id=artifact.artifact_id,
            sha256=artifact.sha256,
            role=artifact.role,
            action=decision.action,
            media_type=artifact.media_type,
            transformation_id=artifact.transformation.transformation_id if artifact.transformation else None,
            reason=reason,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO release_grants
                    (grant_id, scan_id, artifact_id, payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (grant.grant_id, scan_id, artifact.artifact_id, grant.model_dump_json(), time.time()),
            )
        self._update_artifact_release_flag(artifact.artifact_id, True)
        artifact.release_eligible = True
        return grant

    def grants_for_scan(self, scan_id: str) -> List[ReleaseGrant]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM release_grants WHERE scan_id = ? ORDER BY grant_id",
                (scan_id,),
            ).fetchall()
        return [ReleaseGrant.model_validate_json(row["payload"]) for row in rows]

    def grant_for_artifact(self, artifact_id: str) -> Optional[ReleaseGrant]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM release_grants WHERE artifact_id = ? ORDER BY created_at DESC LIMIT 1",
                (artifact_id,),
            ).fetchone()
        return ReleaseGrant.model_validate_json(row["payload"]) if row else None

    def resolve_path(self, artifact: Artifact) -> Path:
        path = (self.base_dir / artifact.storage_reference).resolve()
        if path.is_symlink() or not str(path).startswith(str(self.base_dir) + os.sep):
            raise ArtifactAccessDenied("artifact path is not contained")
        return path

    def get_artifact(self, artifact_id: str, release_only: bool = True) -> Artifact:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            raise ArtifactAccessDenied("unknown artifact")
        artifact = Artifact.model_validate_json(row["payload"])
        if release_only:
            grant = self.grant_for_artifact(artifact.artifact_id)
            if grant is None or not artifact.release_eligible:
                raise ArtifactNotReleased("artifact is not released")
            if artifact.role in {"original"} or artifact.role.startswith("frame-"):
                raise ArtifactNotReleased("artifact role cannot be released")
            if artifact.role not in {"canonical_lossy", "redacted"}:
                raise ArtifactNotReleased("artifact role is analysis-only")
        return artifact

    def save_report(self, scan_id: str, report_json: str) -> Path:
        dest = (self.reports_dir / (scan_id + ".json")).resolve()
        if not str(dest).startswith(str(self.reports_dir.resolve()) + os.sep):
            raise ArtifactAccessDenied("report path escapes reports root")
        tmp = dest.with_suffix(".tmp")
        tmp.write_text(report_json, encoding="utf-8")
        self._chmod(tmp, SECURE_FILE_MODE)
        os.replace(str(tmp), str(dest))
        self._chmod(dest, SECURE_FILE_MODE)
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO reports (scan_id, payload, created_at) VALUES (?, ?, ?)",
                (scan_id, report_json, time.time()),
            )
        return dest

    def load_report(self, scan_id: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM reports WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is not None:
            return str(row["payload"])
        path = (self.reports_dir / (scan_id + ".json")).resolve()
        if not str(path).startswith(str(self.reports_dir.resolve()) + os.sep) or not path.exists():
            raise ArtifactAccessDenied("unknown report")
        return path.read_text(encoding="utf-8")

    def save_forensic_texts(self, scan_id: str, observations: Iterable[Observation]) -> int:
        rows = []
        for observation in observations:
            raw_text = getattr(observation, "raw_text", None)
            if not raw_text:
                continue
            public = observation.to_public() if hasattr(observation, "to_public") else None
            location = public.location if public is not None else {}
            classification = public.classification if public is not None else str(observation.type)
            rows.append(
                (
                    "forensic:%s:%s" % (scan_id, observation.observation_id),
                    scan_id,
                    observation.observation_id,
                    classification,
                    json.dumps(location, sort_keys=True),
                    sha256_bytes(raw_text.encode("utf-8", errors="replace")),
                    len(raw_text.encode("utf-8", errors="replace")),
                    raw_text,
                    time.time(),
                )
            )
        if not rows:
            return 0
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT OR REPLACE INTO forensic_evidence
                    (evidence_id, scan_id, source_id, classification, location_json,
                     text_sha256, text_length, raw_text, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def forensic_texts_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT evidence_id, source_id, classification, location_json,
                       text_sha256, text_length, raw_text
                FROM forensic_evidence WHERE scan_id = ? ORDER BY evidence_id
                """,
                (scan_id,),
            ).fetchall()
        return [
            {
                "evidence_id": row["evidence_id"],
                "source_id": row["source_id"],
                "classification": row["classification"],
                "location": json.loads(row["location_json"]),
                "text_sha256": row["text_sha256"],
                "text_length": row["text_length"],
                "raw_text": row["raw_text"],
            }
            for row in rows
        ]

    def recover_orphans(self) -> List[str]:
        with self._connect() as connection:
            known = {
                row["storage_reference"]
                for row in connection.execute("SELECT storage_reference FROM artifacts").fetchall()
            }
            recovered: List[str] = []
            roots = [self.quarantine_dir, self.artifacts_dir]
            for root in roots:
                if not root.exists():
                    continue
                for path in root.rglob("*"):
                    if not path.is_file():
                        continue
                    relative = self._safe_relative(path)
                    if relative in known:
                        continue
                    data = path.read_bytes()
                    digest = sha256_bytes(data)
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO orphaned_artifacts
                            (storage_reference, sha256, size_bytes, recovered_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (relative, digest, len(data), time.time()),
                    )
                    recovered.append(relative)
        return recovered

    def garbage_collect(self, retention_seconds: float = 0.0) -> List[str]:
        cutoff = time.time() - retention_seconds
        removed: List[str] = []
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT storage_reference FROM orphaned_artifacts WHERE recovered_at <= ?",
                (cutoff,),
            ).fetchall()
            for row in rows:
                path = (self.base_dir / row["storage_reference"]).resolve()
                if str(path).startswith(str(self.base_dir) + os.sep) and path.exists():
                    path.unlink()
                    removed.append(row["storage_reference"])
            connection.execute("DELETE FROM orphaned_artifacts WHERE recovered_at <= ?", (cutoff,))
        for root in [self.quarantine_dir, self.artifacts_dir, self.temporary_dir]:
            if root.exists():
                for directory in sorted((p for p in root.rglob("*") if p.is_dir()), reverse=True):
                    try:
                        directory.rmdir()
                    except OSError:
                        pass
        return removed

    def enforce_storage_quota(self, max_total_bytes: int) -> None:
        total = 0
        for root in [self.quarantine_dir, self.artifacts_dir, self.forensic_dir]:
            if root.exists():
                total += sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
        if self.db_path.exists():
            total += self.db_path.stat().st_size
        if total > max_total_bytes:
            raise ArtifactAccessDenied("artifact store quota exceeded")

    def cleanup_job_dirs(self, older_than_seconds: float = 0.0) -> List[str]:
        cutoff = time.time() - older_than_seconds
        removed: List[str] = []
        for path in self.jobs_dir.iterdir() if self.jobs_dir.exists() else []:
            if path.is_dir() and path.stat().st_mtime <= cutoff:
                shutil.rmtree(path)
                removed.append(path.name)
        return removed

    def capability_status(self) -> ModuleStatus:
        return ModuleStatus(name="artifact_store", status=EpistemicState.CONFIRMED, reason=str(self.db_path))
