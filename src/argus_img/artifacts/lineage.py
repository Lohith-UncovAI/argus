from typing import Dict, List

from argus_img.core.models import Artifact


def lineage_edges(artifacts: Dict[str, Artifact]) -> List[dict]:
    edges = []
    for artifact in artifacts.values():
        if artifact.derived_from:
            edges.append(
                {
                    "from": artifact.derived_from,
                    "to": artifact.artifact_id,
                    "type": "derived_from",
                    "transformation": artifact.transformation.transformation_id
                    if artifact.transformation
                    else None,
                }
            )
    return edges

