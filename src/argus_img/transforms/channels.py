from __future__ import annotations

from typing import List


def channel_names() -> List[str]:
    """Return the ordered channel names produced by RGBA split in generate_fast_transformations."""
    return ["red", "green", "blue", "alpha"]


def channel_role(channel: str) -> str:
    """Return the artifact role used in the store for a given channel name."""
    return "%s-channel" % channel
