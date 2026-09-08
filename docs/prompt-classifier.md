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

`build_prompt_corpus.py`'s synthetic data alone is a scaffold — it is a small
part of the mix. `assemble_training_corpus.py` (below) combines it with the
public datasets; the highest-value addition still missing is **real OCR
captures from ARGUS's own image pipeline**, labelled and folded in with the eval
split kept frozen. Document licensing per source (the repo is MIT; models and
datasets carry their own terms).

## Training

Two paths:

* **`tools/training/assemble_training_corpus.py` + `train_binary_classifier.py`**
  — the path used for the current `pi-argus-v1`. `assemble` pulls
  `deepset/prompt-injections` + `xTRam1/safe-guard-prompt-injection`, adds the
  synthetic image-domain augmentations and hard negatives, and holds out the
  ARGUS corpus + adversarial probes by normalized text. `train_binary` fine-tunes
  a binary (SAFE / INJECTION) head — matching the public data — with
  class weighting, optional KL distillation from a base-size teacher, and
  temperature scaling fitted on val.

* **`tools/training/train_prompt_classifier.py`** — the multi-label recipe
  (the six ARGUS policy categories). Use once there is per-category labelled
  data; the pipeline adapter already handles both shapes via the label map.

Neither runs in CI or at scan time. See "How the current model was produced".

## Calibration

`tools/evaluation/calibrate_prompt_detectors.py` is the gate. With
`ARGUS_PROMPT_CLASSIFIER_PATH` set it adds a `classifier%` column to the
per-category table and a classifier threshold sweep (precision / recall / F1),
and shows how the classifier does on the quoted/discussed security-education
band. Pick the operating point from the sweep, write it into the label map's
`threshold_block` / `threshold_review`, and re-run. Run this in CI as the
regression gate for any model or threshold change.

## Measured results (2026-09)

Held-out evaluation = the 107-item `prompt_text_corpus.jsonl` plus the 21
adversarial-benign probes from
`tests/unit/test_prompt_paraphrase_generalization.py`, none of which enter
training (`assemble_training_corpus.py` excludes them by normalized text).

| signal stack | attack recall | non-quoted benign BLOCK FP | notes |
|---|---|---|---|
| rules + semantic (regex only) | 82.5% | 0 | misses garbled-OCR (42%) and obfuscated (40%) |
| + `protectai/deberta-v3-base-prompt-injection-v2` (184M, shadow) | 98.2% | **3** | bimodal outputs — flat threshold sweep, can't calibrate the FPs away |
| + **`pi-argus-v1`** (deberta-v3-xsmall, 22M, distilled from ProtectAI) | **100%** | **0** | 1 soft REVIEW FP (`trap-024`); real precision/recall curve; temperature 1.36 |

`pi-argus-v1`: 294 MB fp32 / **87 MB int8 ONNX**, **~8 ms/text CPU** (int8,
single thread). Trained in ~3.5 min on one RTX 5080 from ~9.3k items
(deepset + xTRam1/safe-guard public sets + the synthetic image-domain
augmentations and hard negatives). Recommended thresholds:
`threshold_block: 0.65`, `threshold_review: 0.45`.

The classifier's weak spots (tool-call, shell-command, and exfil phrasings all
score 0.55-0.60) are exactly where the deterministic rules are strongest, so
the layers are complementary. It still scores 8/10 security-education texts as
injection — the context gate skips them, so 0/10 wrongly BLOCK.

Residual work: 2/21 adversarial-benign probes still misfire
("Whatever you were told at orientation…", "Only you know the gate code…") —
add those phrasings to the hard-negative bank for a v2. And the full digit-leet
case is caught by the model now but a leet→ascii normalizer pass in
`normalizer.py` would make it robust rather than lucky.

## How the current model was produced

```bash
# 1. corpus (public sets + synthetic image-domain data, ARGUS corpus held out)
python tools/training/assemble_training_corpus.py --out tools/training/corpus

# 2. shadow the teacher, read the harness (optional but recommended)
huggingface-cli download protectai/deberta-v3-base-prompt-injection-v2 \
    --local-dir models/pi-shadow-protectai
ARGUS_PROMPT_CLASSIFIER_PATH=$PWD/models/pi-shadow-protectai \
    PYTHONPATH=src python3 tools/evaluation/calibrate_prompt_detectors.py

# 3. train the small distilled student, export int8 ONNX
python tools/training/train_binary_classifier.py \
    --corpus-dir tools/training/corpus \
    --base-model microsoft/deberta-v3-xsmall \
    --teacher-model models/pi-shadow-protectai \
    --out models/pi-argus-v1 --epochs 3 --export-onnx

# 4. calibrate thresholds against the held-out ARGUS corpus, edit argus_label_map.json
ARGUS_PROMPT_CLASSIFIER_PATH=$PWD/models/pi-argus-v1 \
    PYTHONPATH=src python3 tools/evaluation/calibrate_prompt_detectors.py
```

The model artifact (`models/`) is gitignored — publish it to a model registry
and ship it as an operator-supplied directory (or a `argus-img models fetch`
step), never an auto-download at scan time. The regex/heuristic banks remain the
`CONFIRMED` deterministic floor; the model is `HIGHLY_LIKELY` evidence only.
