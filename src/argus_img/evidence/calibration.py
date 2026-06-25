from argus_img.core.enums import EpistemicState


STATE_RANK = {
    EpistemicState.CONFIRMED: 7,
    EpistemicState.HIGHLY_LIKELY: 6,
    EpistemicState.POSSIBLE: 5,
    EpistemicState.INCONCLUSIVE: 4,
    EpistemicState.ERROR: 3,
    EpistemicState.UNSUPPORTED: 2,
    EpistemicState.NOT_TESTED: 1,
    EpistemicState.NO_EVIDENCE_FOUND: 0,
}

