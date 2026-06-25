from argus_img.core.models import Artifact


def is_release_candidate(artifact: Artifact) -> bool:
    return artifact.release_eligible and artifact.role != "original"

