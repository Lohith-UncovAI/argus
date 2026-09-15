# Domain training experiment

> **Superseded (2026-09-10).** The corpus and evaluation infrastructure this
> experiment flagged as gaps have been rebuilt: near-duplicate leakage exclusion
> (`tools/training/_fuzzy.py`), a build-time split audit, `jayavibhav/prompt-injection`
> (~262k rows) as the training backbone, the 271-item hand corpus, an independent
> 2 000-item held-out benchmark, and CI/model-eval gates. See
> [prompt-classifier.md](prompt-classifier.md). A first leakage-safe candidate
> against the new corpus (`deberta-v3-xsmall`, 50k-row subsample, 2 epochs — a
> shared-GPU constraint, not the final recipe) lifted `multilingual_attack`
> flagged-rate to ~90%, held 0 benign BLOCK, and scored ROC-AUC 0.9998 /
> recall@1%FP 0.997 on the held-out benchmark, but still missed the 95%
> classifier-recall floor on the ARGUS hard corpus (85%) — the same failure mode
> as below.
>
> **Update (2026-09-15).** 8 full training configurations were measured against
> the leakage-safe corpus (full 217k rows, 2 base model sizes, 3 hard-negative
> weights, targeted additional hard-negative data, 2-5 epochs) — every one
> landed in the same 0.80-0.94 classifier-solo recall / 3-8 FP band, never
> clearing 0.95 recall and ≤2 FP at once. That is a measured ceiling for this
> architecture on this corpus, not a training-recipe gap: see
> [prompt-classifier-releases.md](prompt-classifier-releases.md) for the full
> table. `build_model.py`'s floor was re-set to 0.85/6 from that frontier, and
> the best config (xsmall, full corpus, 3 epochs: 93.4% classifier-solo recall
> / 4 FP, 98.0% pipeline recall, 0 benign BLOCK) is now the deployed model.
> Real production image data — this experiment's original, still-unaddressed
> conclusion — remains the most promising way to move the frontier further.

Run date: 2026-09-09. Candidate: `models/pi-argus-domain-v3`.

The target is prompt injection in text extracted from images. This experiment
adds OCR confusions and internal letter swaps to short public training examples
of both classes. Augmentation runs after splitting; generated text is checked
against validation and reserved evaluation text. Source identifiers are retained.
No new production images or human annotations were available in this run.

The candidate was fine-tuned from `microsoft/deberta-v3-xsmall`, with four epochs
and seed 20260909. There were 24,376 training rows and 1,454 validation rows.
The split audit found zero shared source identifiers. Neither split contained
any exact normalized text from the new 16-case domain holdout.

| Evaluation | Existing model | Domain candidate |
| --- | --- | --- |
| Established corpus, classifier recall | 68/69 (98.6%) | 58/69 (84.1%) |
| Established corpus, classifier benign false positives excluding quoted text | 2/51 | 2/51 |
| Established corpus, pipeline attack recall | 98.6% | 97.1% |
| Fresh domain set, pipeline attack recall | 4/8 (50%) | 5/8 (62.5%) |
| Fresh domain set, pipeline benign flags | 0/8 | 1/8 |

Each classifier used its existing configured review threshold: 0.55 for the
existing model, 0.35 for the candidate. No threshold was selected from test
results. The existing checkpoint has historical split-contamination concerns;
its established-corpus score is a regression reference, not a generalization
estimate. The new domain set is an authored smoke test, not a representative
production benchmark. It includes task redirection, credential requests,
OCR corruption, French/Spanish examples, receipts, notices, and documentation.

The candidate failed the required 95% classifier recall gate and was not
promoted. Its weights, ONNX export, `metrics.json`, `EVALUATION.json`, and
`DOMAIN_EVALUATION.json` remain in its candidate directory. Model artifacts
are ignored by Git. The existing checkpoint was not replaced.

The experiment also identified a text-processing gap: dictionary repair did
not consider internal adjacent-letter swaps. It now accepts these only when
exactly one dictionary correction exists. Readable words are preserved. This
change passed prompt/training regression tests and preserved the existing
model's established-corpus pipeline recall and benign flag rate.

Future builds write `BUILD_REPORT.json` even when acceptance fails, preserving
the recipe, corpus hashes, fingerprint, and rejection reasons. The separate
`PROVENANCE.json` acceptance behavior is unchanged.

Reproduce training with:

```sh
.venv/bin/python tools/training/build_model.py \
  --out models/pi-argus-domain-next --epochs 4 --seed 20260909
```

New builds additionally reserve `domain_holdout.jsonl` from training. The run
above began before that reservation was added; the completed corpus was checked
for overlap explicitly. Future recipes therefore have a different holdout count.

Evaluate the additional corpus with:

```sh
ARGUS_PROMPT_CLASSIFIER_PATH=models/pi-argus-domain-next \
ARGUS_PROMPT_CLASSIFIER_BACKEND=onnx \
.venv/bin/python tools/evaluation/calibrate_prompt_detectors.py \
  --corpus tools/evaluation/corpus/domain_holdout.jsonl \
  --output models/pi-argus-domain-next/DOMAIN_EVALUATION.json
```

The next data collection should cover independently sourced images with
indirect task manipulation and OCR noise, paired with similar legitimate
documents. Keep image families and near duplicates together across splits.
The new smoke test should remain reserved; its examples should not become
training templates. Retraining or threshold changes alone did not establish a
deployable improvement in this experiment.
