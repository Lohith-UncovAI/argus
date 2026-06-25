from __future__ import annotations

from typing import Dict, List

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.enums import PolicyAction
from argus_img.core.models import Artifact, PolicyDecision, ReleaseGrant


NON_RELEASING_ACTIONS = {
    PolicyAction.BLOCK,
    PolicyAction.QUARANTINE,
    PolicyAction.REVIEW,
    PolicyAction.UNSUPPORTED,
}


def _approved_reconstructed_artifact(artifact: Artifact) -> bool:
    if artifact.role != "canonical_lossy" or artifact.media_type != "image/jpeg":
        return False
    if artifact.transformation is None or artifact.transformation.type != "canonical_lossy_jpeg":
        return False
    params = artifact.transformation.parameters
    return (
        params.get("lossy") is True
        and params.get("flattened") is True
        and params.get("metadata_stripped") is True
    )


def _approved_redacted_artifact(artifact: Artifact) -> bool:
    if artifact.role != "redacted":
        return False
    if artifact.transformation is None:
        return False
    params = artifact.transformation.parameters
    return params.get("redacted") is True and params.get("metadata_stripped") is True


def apply_release_grants(
    store: ArtifactStore,
    scan_id: str,
    artifacts: Dict[str, Artifact],
    decision: PolicyDecision,
) -> List[ReleaseGrant]:
    if decision.action in NON_RELEASING_ACTIONS:
        return []
    if decision.action == PolicyAction.ALLOW_RECONSTRUCTED_ONLY:
        candidate = artifacts.get("canonical_lossy")
        if candidate is None or not _approved_reconstructed_artifact(candidate):
            return []
        return [
            store.grant_release(
                scan_id,
                candidate,
                decision,
                "policy allowed only the approved lossy flattened metadata-free reconstruction",
            )
        ]
    if decision.action == PolicyAction.ALLOW_WITH_REDACTION:
        grants: List[ReleaseGrant] = []
        for artifact in artifacts.values():
            if _approved_redacted_artifact(artifact):
                grants.append(
                    store.grant_release(
                        scan_id,
                        artifact,
                        decision,
                        "policy allowed only a real redacted metadata-free artifact",
                    )
                )
        return grants
    return []
