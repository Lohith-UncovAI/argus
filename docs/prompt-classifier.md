# Prompt-injection classifier (optional local ML signal)

## Where it sits

ARGUS-IMG's prompt layer has three signals over extracted text, in decreasing
order of determinism:

| # | Component | Module | Max epistemic state | Decision role |
|---|-----------|--------|---------------------|---------------|
| 1 | Regex rule bundle | `detectors/prompt/rules.py` | `CONFIRMED` | deterministic floor |
| 2 | Heuristic scorer (token / bigram / structural / paraphrase banks) | `detectors/prompt/semantic.py` | `HIGHLY_LIKELY` | evidence |
| 3 | **Local ML classifier** | `detectors/prompt/classify.py` + `classifier.py` | `HIGHLY_LIKELY` | evidence |

All three emit `DetectorFinding`s. The deterministic **policy engine** combines
them and makes the BLOCK / REVIEW / allow decision. The classifier never decides
anything on its own — a model probability is not proof.

Pipeline wiring (`orchestration/pipeline.py`, "configured prompt-classifier
adapter", plan.md §19.2): `rules → classifier → semantic`. Observations the rule
engine already resolved as `CONFIRMED` are skipped by both later signals.

## Why a model, and why a *small* one

The regex/heuristic banks key off attack vocabulary. They can be extended to
catch any *known* phrasing (the paraphrase bank in `semantic.py` does exactly
that), but they do not generalise to phrasings nobody has written a pattern for
yet, and they are brittle against OCR corruption and obfuscation. A small
encoder fine-tuned for this one task generalises across phrasing while staying
CPU-cheap (single-digit ms on short text) and fully offline.

It is a fixed artifact: it generalises, it does not learn at runtime. There is
no feedback loop — that would be a poisoning surface.

## Offline / optional contract

Identical to ExifTool / Tesseract / ClamAV and the SmolVLM caption detector:

* **Optional.** No configured model → `detector:prompt-classifier` reports
  `NOT_TESTED`, signals 1 and 2 are unchanged. `prompt_classifier_available()`
  gates the whole thing in the pipeline.
* **Offline.** Every `from_pretrained` call passes `local_files_only=True`.
  Nothing is downloaded at scan time. The model is an operator-supplied local
  directory.
* **No hardcoded repo.** The model identity lives entirely in configuration.

### Configuration (environment variables)

| Variable | Meaning |
|----------|---------|
| `ARGUS_PROMPT_CLASSIFIER_PATH` | Absolute path to a local HF sequence-classification model dir. Unset = disabled. |
| `ARGUS_PROMPT_CLASSIFIER_BACKEND` | `transformers` (default) or `onnx` (needs `onnxruntime` + `model.onnx` in the dir). |
| `ARGUS_PROMPT_CLASSIFIER_LABELMAP` | Optional path to a label-map JSON (see below). |
| `ARGUS_PROMPT_CLASSIFIER_BLOCK` / `_REVIEW` | Global threshold overrides (defaults 0.60 / 0.35). Per-model thresholds in the label map win. |

### Label map

One adapter serves both a plain binary detector and an ARGUS-native multi-label
model. Resolution order: explicit `ARGUS_PROMPT_CLASSIFIER_LABELMAP` →
`argus_label_map.json` in the model dir → the model's own `config.json`
`id2label` (with a name-heuristic mapping of `INJECTION` / `JAILBREAK` /
`LEGIT` / … to reason codes) → binary fallback.

```json
{
  "problem_type": "multi_label_classification",
  "threshold_block": 0.60,
  "threshold_review": 0.35,
  "calibration": {"method": "temperature", "temperature": 1.8},
  "labels": {
    "0": {"name": "benign", "benign": true, "reason_codes": []},
    "1": {"name": "instruction_override", "severity": "critical",
          "reason_codes": ["PROMPT_INJECTION", "INSTRUCTION_OVERRIDE"]},
    "2": {"name": "credential_request", "severity": "high",
          "reason_codes": ["PROMPT_INJECTION", "CREDENTIAL_REQUEST"]},
    "3": {"name": "tool_invocation", "severity": "critical",
          "reason_codes": ["PROMPT_INJECTION", "TOOL_INVOCATION_REQUEST"]},
    "4": {"name": "data_exfiltration", "severity": "high",
          "reason_codes": ["PROMPT_INJECTION", "DATA_EXFILTRATION"]},
    "5": {"name": "policy_bypass", "severity": "critical",
          "reason_codes": ["PROMPT_INJECTION", "POLICY_BYPASS"]}
  }
}
```

Multi-label matters: the policy engine already distinguishes these categories,
so `data_exfiltration @ 0.9` is far more actionable than `injection @ 0.9`.

`calibration` (optional) rescales the raw probability so the `attack_likelihood`
on a finding means what it says. `temperature` divides logits before the
sigmoid; `platt` fits `sigmoid(a·logit + b)`. `train_prompt_classifier.py` fits
a temperature on the val split automatically and writes it here.

### Attestation

Every classifier finding carries a `model_fingerprint`
(`sha256:` over `config.json` + `argus_label_map.json` + tokenizer files + a
weight-file size manifest — cheap, no gigabyte hashing). The same fingerprint,
plus backend / labels / thresholds / calibration method, appears under
`model_adapters.prompt_classifier` in `GET /v1/capabilities` and
`model_adapters_configured.prompt_classifier` in `GET /v1/attestation`, so a
report is tied to a reproducible model.

## The dataset is the product

The single decision that determines whether this works is the training corpus,
not the architecture. A model trained on a weak negative set becomes a
false-positive machine that flags every security blog post and every benign UI
screenshot.

`tools/evaluation/build_prompt_corpus.py` bootstraps a corpus from the 107-item
seed set with **no network and no LLM calls**:

1. **Multi-label annotation** of every item into the schema above.
2. **Attack augmentation** — simulated OCR corruption, leetspeak, character
   spacing, unicode confusables, truncation, and embedding inside benign
   captions (the exact mutations that defeat the regex banks today).
3. **Template paraphrase generation** — slot-filled sentence banks per attack
   family, producing phrasings the seed set never contained.
4. **Hard-negative generation** — the largest bank: benign text that reuses
   attack vocabulary ("ignore", "override", "reveal the secret", "send … to"),
   security-education text, instruction-shaped microcopy, plus plain captions.

Splits are leakage-safe (all variants of a seed, and all fills of a template,
share a split). The manifest reports class/label/source balance per split.

**This synthetic corpus is a scaffold.** Before the model is trusted in
production, fold in real data: `deepset/prompt-injections`,
`xTRam1/safe-guard-prompt-injection`, in-the-wild jailbreak collections, the
CyberSecEval prompt-injection subset, and — most importantly — real OCR
captures from ARGUS's own image pipeline. Keep the eval split frozen and
source-stratified. Document licensing per source (the repo is MIT; models and
datasets carry their own terms).

## Training

`tools/training/train_prompt_classifier.py` — not run in CI or at scan time.
Fine-tunes `microsoft/deberta-v3-xsmall` (22M) as a multi-label classifier with
per-label positive weighting and optional soft-label distillation from a
base-size prompt-injection teacher (e.g.
`protectai/deberta-v3-base-prompt-injection-v2`). Exports to the exact on-disk
layout the adapter loads, writes `argus_label_map.json`, `metrics.json`, a model
card, and optionally an int8 ONNX file.

```bash
python tools/evaluation/build_prompt_corpus.py --out tools/evaluation/corpus
python tools/training/train_prompt_classifier.py \
    --corpus-dir tools/evaluation/corpus \
    --out models/prompt-classifier-v1 \
    --teacher-model protectai/deberta-v3-base-prompt-injection-v2 \
    --epochs 4 --export-onnx
```

## Calibration

`tools/evaluation/calibrate_prompt_detectors.py` is the gate. With
`ARGUS_PROMPT_CLASSIFIER_PATH` set it adds a `classifier%` column to the
per-category table and a classifier threshold sweep (precision / recall / F1),
and shows how the classifier does on the quoted/discussed security-education
band. Pick the operating point from the sweep, write it into the label map's
`threshold_block` / `threshold_review`, and re-run. Run this in CI as the
regression gate for any model or threshold change.

## Recommended rollout

1. **Shadow an off-the-shelf model first.** Point `ARGUS_PROMPT_CLASSIFIER_PATH`
   at `protectai/deberta-v3-base-prompt-injection-v2` (downloaded once, run
   offline) and read the calibration harness. This costs ~a day and tells you
   whether a model beats the regex banks on held-out paraphrases, by how much,
   and what it false-positives on — before investing in a dataset.
2. **Build the real corpus** (public datasets + image-distribution captures,
   frozen eval split).
3. **Train small** (deberta-v3-xsmall multi-label, distilled), export int8 ONNX.
4. Ship as an operator-supplied artifact (or a `argus-img models fetch` step —
   never an auto-download at scan time). Regexes remain the `CONFIRMED` floor.
