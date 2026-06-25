from __future__ import annotations

from typing import Dict, Iterable, Set

from argus_img.core.models import Artifact, RepresentationEntry, RepresentationManifest


def _kind_for_artifact(label: str, artifact: Artifact) -> str:
    if artifact.role == "original":
        return "original_container"
    if artifact.role == "canonical_lossy":
        return "release_candidate"
    if artifact.role == "canonical_lossless":
        return "canonical_lossless"
    if artifact.role in {"flattened_white", "flattened_black"}:
        return "alpha_view"
    if artifact.role.startswith("frame-"):
        return "animation_frame"
    if artifact.role.endswith("-channel"):
        return "channel_view"
    if "thumbnail" in artifact.role:
        return "thumbnail"
    return "derived_view"


def build_representation_manifest(
    artifacts: Dict[str, Artifact],
    analyzed_artifact_ids: Iterable[str],
) -> RepresentationManifest:
    analyzed: Set[str] = set(analyzed_artifact_ids)
    entries = []
    missing = []
    for label, artifact in sorted(artifacts.items()):
        kind = _kind_for_artifact(label, artifact)
        required = kind in {
            "original_container",
            "release_candidate",
            "canonical_lossless",
            "alpha_view",
            "animation_frame",
            "thumbnail",
            "channel_view",
            "derived_view",
        }
        is_analyzed = artifact.artifact_id in analyzed
        representation_id = artifact.representation_id or "repr:%s" % label
        entry = RepresentationEntry(
            representation_id=representation_id,
            artifact_id=artifact.artifact_id,
            kind=kind,
            source_artifact_id=artifact.derived_from or artifact.artifact_id,
            required_for_release=required,
            release_relevant=required,
            analyzed=is_analyzed,
            media_type=artifact.media_type,
            sha256=artifact.sha256,
            width=artifact.width,
            height=artifact.height,
            frame_index=artifact.frame_index,
            transformation_id=artifact.transformation.transformation_id if artifact.transformation else None,
            coverage_notes=[] if is_analyzed else ["representation was not analyzed"],
        )
        entries.append(entry)
        if required and not is_analyzed:
            missing.append(representation_id)
    return RepresentationManifest(
        entries=entries,
        coverage_complete=not missing,
        missing_required=missing,
    )
