from argus_img.core.models import TextObservation


def merge_text_observations(observations):
    seen = set()
    merged = []
    for obs in observations:
        key = (obs.normalized_text.lower().strip(), obs.source_artifact_id)
        if key in seen:
            continue
        seen.add(key)
        merged.append(obs)
    return merged


OCRObservation = TextObservation

