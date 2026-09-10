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
| _pending_ | — | — | — | — | — | — | — | First leakage-safe build against the 271-item corpus + 2 000-item held-out benchmark. Fill in from `PROVENANCE.json` / `EVAL_SUMMARY.json` on promotion. |
