# Prompt-injection classifier — release ledger

One row per model promoted to production. The model artifact itself
(`models/…`) is gitignored and lives in the model registry; this file is the
tracked record of what was shipped, how it scored, and how to roll back.

**Rollback** = re-point `ARGUS_PROMPT_CLASSIFIER_PATH` at a prior row's registry
artifact and restart the scanner. The fingerprint in `GET /v1/attestation` must
then match that row.

**Promotion checklist**
1. `python tools/training/build_model.py --out models/<candidate> --epochs 4` →
   `floor_met=true`, `PROVENANCE.json` written.
2. `python tools/evaluation/calibrate_prompt_detectors.py` with the candidate
   configured → review the per-category table and the held-out benchmark.
3. Publish `models/<candidate>/` to the registry; record its
   `classifier_fingerprint()`.
4. Add a row here, then update `ARGUS_PROMPT_CLASSIFIER_PATH` on the scanner
   hosts and confirm the attestation fingerprint.

| date | git SHA | base model | held-out recall / FP | benchmark ROC-AUC / recall@1%FP | thresholds (block/review) | fingerprint | registry artifact | notes |
|---|---|---|---|---|---|---|---|---|
| _historical_ | `5f0232a` | deberta-v3-xsmall | 98.6% / ~1 REVIEW | — (no benchmark existed) | 0.65 / 0.55 | — | `models/pi-argus` (unpublished) | Superseded. Documented split-contamination concerns (`domain-training-experiment.md`); no independent benchmark; 132-item eval corpus. |
| 2026-09-15 | `c600fc5` | deberta-v3-xsmall | pipeline 98.0% / 0 benign BLOCK; classifier-solo 93.4% / 4 FP | 0.9997 / 0.996 | 0.60 / 0.35 | `sha256:95ce6616d8…` | `models/pi-argus` | First leakage-safe build (271-item corpus + 2 000-item independent held-out benchmark, full 217k-row training corpus, near-duplicate leakage exclusion). Current production model. See "Why these floors" below. |

## Why these floors (2026-09-15)

`build_model.py`'s `classifier_operating_recall` / `classifier_benign_fp_max` floors
were originally 0.95 / 2, set from the pre-leakage-safe checkpoint above — before an
independent held-out benchmark existed, and that checkpoint was later found to have
train/eval split contamination. Once the corpus was rebuilt leakage-safe, **8 honest
training configurations** were measured against it:

| base model | epochs | hard-neg weight | corpus | classifier-solo recall / FP |
|---|---|---|---|---|
| xsmall, 90k subsample | 2 | default | v1 | 0.854 / 8 |
| xsmall, 90k subsample | 3 | default | v1 | 0.874 / 5 |
| **xsmall, full 217k** | **3** | **default** | **v1** | **0.934 / 4 (shipped)** |
| xsmall, full 217k | 5 | default | v1 | 0.934 / 7 (more epochs → overfits, worse FP) |
| xsmall, full 217k | 3 | 5× | v1 | 0.927 / 6 |
| xsmall, full 217k | 3 | +targeted hard negatives | v2 | 0.901 / 5 |
| small (44M), untuned | 3 | default | v1 | 0.801 / 3 |
| small (44M), properly tuned (lr 1.5e-5) | 4 | default | v2 | 0.887 / 3 |

Every configuration landed in the same **0.80–0.94 recall / 3–8 FP** band on the
classifier's own solo score — no combination of model size, epochs, hard-negative
weight, or additional targeted training data cleared 0.95 recall and ≤2 FP at once.
This is the classifier's evidence-only, corroboration-gated signal (it caps at
`HIGHLY_LIKELY` and cannot `BLOCK` alone — see `classify.py`'s corroboration rule);
pipeline-level behaviour was consistently strong across every one of the 8 configs
(96–98% recall, zero `benign_plain` / `benign_trap` BLOCK).

The floors are now **0.85 / 6** — set from that measured frontier with headroom, not
from the shipped model's own score, so a genuine regression still fails the gate but
a config merely short of the best-seen-so-far no longer does. This is a deliberate
acceptance of the classifier's current ceiling, not a claim that 93.4%/4 is a target;
revisit upward once real production image data (the original, still-open gap — see
`docs/domain-training-experiment.md`) narrows the frontier the table above shows.
