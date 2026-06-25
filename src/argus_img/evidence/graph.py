from __future__ import annotations

from typing import Dict, List

from argus_img.artifacts.lineage import lineage_edges
from argus_img.core.models import Artifact, DetectorFinding, Observation


def build_evidence_graph(
    artifacts: Dict[str, Artifact],
    observations: List[Observation],
    findings: List[DetectorFinding],
) -> Dict[str, object]:
    nodes = []
    for artifact in artifacts.values():
        nodes.append({"id": artifact.artifact_id, "type": "Artifact", "role": artifact.role})
    for observation in observations:
        nodes.append({"id": observation.observation_id, "type": "Observation", "detector": observation.detector_id})
    for finding in findings:
        nodes.append({"id": finding.finding_id, "type": "Finding", "category": finding.category})
    edges = lineage_edges(artifacts)
    for observation in observations:
        edges.append({"from": observation.source_artifact_id, "to": observation.observation_id, "type": "observed_in"})
    for finding in findings:
        for observation_id in finding.observation_ids:
            edges.append({"from": observation_id, "to": finding.finding_id, "type": "supports"})
        for artifact_id in finding.source_artifact_ids:
            edges.append({"from": artifact_id, "to": finding.finding_id, "type": "supports"})
    return {"nodes": nodes, "edges": edges}

