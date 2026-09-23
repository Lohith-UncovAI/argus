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
| _historical_ | `5f0232a` | deberta-v3-xsmall | 98.6% / ~1 REVIEW | — (no benchmark existed) | 0.65 / 0.55 | — | `models/pi-argus` (unpublished) | Retired — no longer on this host. Documented split-contamination concerns (`domain-training-experiment.md`); no independent benchmark; 132-item eval corpus. |
| _none currently_ | — | — | — | — | — | — | — | `models/` holds no deployed candidate. ~15 configurations measured against the rebuilt leakage-safe corpus, including ensembles (tables below); none cleared `build_model.py`'s `FLOORS` (`classifier_operating_recall: 0.95`, `classifier_benign_fp_max: 2`). Do not add a row here without a build that printed `floor_met=true` against the current `FLOORS`. |

## Measured frontier so far (2026-09-17) — none of these are deployed

Single-model configurations against the rebuilt leakage-safe corpus (full 217k
training rows unless noted; 271-item hand corpus + 2 000-item independent
held-out benchmark). None cleared the required 0.95 classifier-solo recall /
≤2 FP. Kept here as reference for the next attempt, not as a promotion record.

| base model | epochs | hard-neg weight | corpus | classifier-solo recall / FP |
|---|---|---|---|---|
| xsmall, 90k subsample | 2 | default | v1 | 0.854 / 8 |
| xsmall, 90k subsample | 3 | default | v1 | 0.874 / 5 |
| xsmall, full 217k | 3 | default | v1 | 0.934 / 4 |
| xsmall, full 217k | 5 | default | v1 | 0.934 / 7 (more epochs → overfits, worse FP) |
| xsmall, full 217k | 3 | 5× | v1 | 0.927 / 6 |
| xsmall, full 217k | 3 | +targeted hard negatives | v2 | 0.901 / 5 |
| small (44M), untuned | 3 | default | v1 | 0.801 / 3 |
| small (44M), properly tuned (lr 1.5e-5) | 4 | default | v2 | 0.887 / 3 |
| xsmall, full 217k, hard-category model selection | 3 | default | v1 | 0.940 / 9 (at operating thr 0.35; a stable plateau 0.15-0.75) |
| xsmall, full 217k, hard-category selection | 3 | default | **v3 (paraphrase-coverage fix)** | 0.934 / 7 (at operating thr 0.35) |

Every single-model configuration landed in the same **0.80–0.94 recall / 3–9 FP**
band on the classifier's own solo score (evidence-only, corroboration-gated —
it cannot `BLOCK` alone; see `classify.py`). Pipeline-level behaviour was
consistently strong across all of them (96–98% recall, zero `benign_plain` /
`benign_trap` BLOCK), which is not the same thing as the classifier's solo
signal being trustworthy enough to ship on its own.

### Ensembling (3 independently-seeded models, combined scores)

| ensemble | combination rule | best-F1 recall / FP | best recall at FP≤2 |
|---|---|---|---|
| xsmall ×3, corpus v1 | mean | 97.4% / 7 | 90.1% / 2 |
| xsmall ×3, corpus v1 | unanimous ("min") | 93.4% / 4 | **90.7% / 2** (stable 0.145-0.215) |
| xsmall ×3, corpus v1 | 2-of-3 vote | 94.7% / 7 (not separately swept for FP≤2) | — |
| xsmall ×3, corpus **v3** (paraphrase-coverage fix) | unanimous ("min") | **97.4% / 5** (best F1 of any configuration measured) | 84.1% / 2 |
| xsmall ×3, corpus v3 | mean / 2-of-3 vote | — | no threshold found with FP≤2 in a fine sweep |

Corpus v3 fixes a diagnosed real bug (see `docs/domain-training-experiment.md`
and the `e2dbf59` commit): synthetic paraphrase templates whose *clean* text
happened to land near a held-out eval sentence were correctly fuzzy-excluded
from training, but their leetspeak/OCR-noise obfuscated derivatives survived
the same filter — so training had many mangled copies of some attack phrasings
and almost no clean ones. Fixing it demonstrably closed the targeted gap
(verified by exact before/after diff of which eval items are missed) and
improved best-F1, but did not improve the strict FP≤2 operating point, which
actually regressed slightly (84.1% vs the prior corpus's 90.7%) — new marginal
misses appeared elsewhere. **No combination of model size, epoch count,
hard-negative weighting, targeted training data, model-selection metric, or
3-way ensembling has cleared 0.95 recall AND ≤2 FP simultaneously across
~15 measured configurations.** This is now strong evidence of a real ceiling
for a small transformer classifier evaluated solo against this corpus — real
production image data (the original, still-open gap; see
`docs/domain-training-experiment.md`) is the most likely way to move it
further, not more architecture/ensembling/hyperparameter search.
