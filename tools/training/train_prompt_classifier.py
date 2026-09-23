#!/usr/bin/env python3
"""Fine-tune the local prompt-injection classifier used by
``argus_img.detectors.prompt.classify``.

This trains a small encoder (default: ``microsoft/deberta-v3-xsmall``, 22M
params) as a **multi-label** classifier over the ARGUS policy categories, then
exports it to the exact on-disk layout the pipeline adapter loads:

    <out>/
      config.json  tokenizer*  model.safetensors          <- transformers backend
      model.onnx                                           <- onnx backend (int8)
      argus_label_map.json                                 <- read by classifier.load_label_map
      metrics.json  model_card.md

Deliberately NOT run in CI or at scan time — it needs a GPU box (or patience),
``transformers[torch]``, ``datasets``, ``scikit-learn`` and, for the ONNX step,
``optimum[exporters]`` + ``onnxruntime``. It is the reproducible recipe, checked
in next to the code it produces.

Typical run:

    python tools/training/train_prompt_classifier.py \
        --corpus-dir tools/evaluation/corpus \
        --base-model microsoft/deberta-v3-xsmall \
        --out models/prompt-classifier-v1 \
        --epochs 4 --export-onnx

Then point the scanner at it:

    export ARGUS_PROMPT_CLASSIFIER_PATH=$PWD/models/prompt-classifier-v1
    PYTHONPATH=src python3 tools/evaluation/calibrate_prompt_detectors.py

The calibration harness will now print a classifier column and threshold sweep;
copy the operating point you pick into ``argus_label_map.json``
(``threshold_block`` / ``threshold_review``).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Dict, List

# ARGUS multi-label schema — index order is the contract with
# argus_img.detectors.prompt.classifier.ARGUS_MULTILABEL.
LABELS = ["benign", "instruction_override", "credential_request",
          "tool_invocation", "data_exfiltration", "policy_bypass"]
LABEL_TO_IDX = {name: i for i, name in enumerate(LABELS)}

ARGUS_LABEL_MAP = {
    "problem_type": "multi_label_classification",
    "threshold_block": 0.60,
    "threshold_review": 0.35,
    "calibration": {"method": "none", "temperature": 1.0},
    "labels": {
        "0": {"name": "benign", "benign": True, "reason_codes": []},
        "1": {"name": "instruction_override", "severity": "critical",
              "reason_codes": ["PROMPT_INJECTION", "INSTRUCTION_OVERRIDE"]},
        "2": {"name": "credential_request", "severity": "high",
              "reason_codes": ["PROMPT_INJECTION", "CREDENTIAL_REQUEST"]},
        "3": {"name": "tool_invocation", "severity": "critical",
              "reason_codes": ["PROMPT_INJECTION", "TOOL_INVOCATION_REQUEST"]},
        "4": {"name": "data_exfiltration", "severity": "high",
              "reason_codes": ["PROMPT_INJECTION", "DATA_EXFILTRATION"]},
        "5": {"name": "policy_bypass", "severity": "critical",
              "reason_codes": ["PROMPT_INJECTION", "POLICY_BYPASS"]},
    },
}


def _load_split(corpus_dir: pathlib.Path, split: str) -> List[dict]:
    path = corpus_dir / ("prompt_corpus.%s.jsonl" % split)
    if not path.is_file():
        raise SystemExit("missing %s — run tools/evaluation/build_prompt_corpus.py first" % path)
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _multi_hot(labels: List[str]) -> List[float]:
    vec = [0.0] * len(LABELS)
    for name in labels:
        if name in LABEL_TO_IDX:
            vec[LABEL_TO_IDX[name]] = 1.0
    if sum(vec) == 0:
        vec[0] = 1.0
    return vec


def _pos_weights(rows: List[dict]) -> List[float]:
    """Per-label positive weight = neg/pos, clipped, for BCEWithLogitsLoss."""
    n = len(rows)
    counts = [0] * len(LABELS)
    for r in rows:
        for name in r["labels"]:
            if name in LABEL_TO_IDX:
                counts[LABEL_TO_IDX[name]] += 1
    weights = []
    for c in counts:
        c = max(c, 1)
        weights.append(min(max((n - c) / c, 0.25), 10.0))
    return weights


def build_metrics_fn(threshold: float = 0.5):
    import numpy as np
    from sklearn.metrics import f1_score, precision_score, recall_score

    def compute(eval_pred):
        logits, labels = eval_pred
        probs = 1.0 / (1.0 + np.exp(-logits))
        preds = (probs >= threshold).astype(int)
        # "attack" = any non-benign label predicted / present
        attack_true = (labels[:, 1:].sum(axis=1) > 0).astype(int)
        attack_pred = (preds[:, 1:].sum(axis=1) > 0).astype(int)
        return {
            "attack_precision": precision_score(attack_true, attack_pred, zero_division=0),
            "attack_recall": recall_score(attack_true, attack_pred, zero_division=0),
            "attack_f1": f1_score(attack_true, attack_pred, zero_division=0),
            "macro_f1": f1_score(labels.astype(int), preds, average="macro", zero_division=0),
        }
    return compute


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus-dir", type=pathlib.Path, default=pathlib.Path("tools/evaluation/corpus"))
    ap.add_argument("--base-model", default="microsoft/deberta-v3-xsmall")
    ap.add_argument("--teacher-model", default=None,
                    help="optional HF sequence-classification model for soft-label distillation "
                         "(e.g. protectai/deberta-v3-base-prompt-injection-v2)")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--epochs", type=float, default=4.0)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--export-onnx", action="store_true")
    ap.add_argument("--seed", type=int, default=20260908)
    args = ap.parse_args(argv)

    import numpy as np
    import torch
    from torch import nn
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
        set_seed,
    )
    from datasets import Dataset

    set_seed(args.seed)

    train_rows = _load_split(args.corpus_dir, "train")
    val_rows = _load_split(args.corpus_dir, "val")
    test_rows = _load_split(args.corpus_dir, "test")
    print("train=%d val=%d test=%d" % (len(train_rows), len(val_rows), len(test_rows)))

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)

    def to_dataset(rows: List[dict]) -> Dataset:
        return Dataset.from_dict({
            "text": [r["text"] for r in rows],
            "labels": [_multi_hot(r["labels"]) for r in rows],
        })

    def tok(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    ds_train = to_dataset(train_rows).map(tok, batched=True)
    ds_val = to_dataset(val_rows).map(tok, batched=True)
    ds_test = to_dataset(test_rows).map(tok, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=len(LABELS),
        problem_type="multi_label_classification",
        id2label={i: n for i, n in enumerate(LABELS)},
        label2id=LABEL_TO_IDX,
    )

    pos_weight = torch.tensor(_pos_weights(train_rows), dtype=torch.float32)
    print("pos_weight:", {LABELS[i]: round(float(w), 2) for i, w in enumerate(pos_weight)})

    teacher = None
    if args.teacher_model:
        teacher = AutoModelForSequenceClassification.from_pretrained(args.teacher_model)
        teacher.eval()

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            loss = nn.BCEWithLogitsLoss(pos_weight=pos_weight.to(outputs.logits.device))(
                outputs.logits, labels.float())
            if teacher is not None:
                with torch.no_grad():
                    t_logits = teacher(input_ids=inputs["input_ids"],
                                       attention_mask=inputs["attention_mask"]).logits
                # teacher is binary injection/benign -> distill onto the "any-attack" margin
                t_attack = torch.sigmoid(t_logits[:, -1]).unsqueeze(1)
                s_attack = torch.sigmoid(outputs.logits[:, 1:]).max(dim=1, keepdim=True).values
                loss = loss + 0.3 * nn.functional.mse_loss(s_attack, t_attack)
            return (loss, outputs) if return_outputs else loss

    targs = TrainingArguments(
        output_dir=str(args.out / "_hf"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="attack_f1",
        greater_is_better=True,
        logging_steps=25,
        seed=args.seed,
        report_to=[],
    )

    trainer = WeightedTrainer(
        model=model, args=targs,
        train_dataset=ds_train, eval_dataset=ds_val,
        tokenizer=tokenizer, compute_metrics=build_metrics_fn(),
    )
    trainer.train()

    val_metrics = trainer.evaluate(ds_val)
    test_metrics = trainer.evaluate(ds_test, metric_key_prefix="test")
    print("val :", {k: round(v, 4) for k, v in val_metrics.items() if isinstance(v, float)})
    print("test:", {k: round(v, 4) for k, v in test_metrics.items() if isinstance(v, float)})

    # Fit temperature scaling on the val logits so reported attack_likelihood is
    # calibrated rather than the model's raw (usually over-confident) sigmoid.
    temperature = _fit_temperature(trainer, ds_val)
    label_map = dict(ARGUS_LABEL_MAP)
    label_map["calibration"] = {"method": "temperature", "temperature": round(temperature, 4)}
    print("fitted temperature: %.3f" % temperature)

    args.out.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(args.out))
    tokenizer.save_pretrained(str(args.out))
    (args.out / "argus_label_map.json").write_text(json.dumps(label_map, indent=2))
    (args.out / "metrics.json").write_text(json.dumps(
        {"base_model": args.base_model, "teacher_model": args.teacher_model,
         "val": val_metrics, "test": test_metrics,
         "corpus_dir": str(args.corpus_dir)}, indent=2))
    _write_model_card(args, val_metrics, test_metrics)

    if args.export_onnx:
        _export_onnx(args.out)

    print("\nwrote model -> %s" % args.out)
    print("set ARGUS_PROMPT_CLASSIFIER_PATH=%s to enable it in the pipeline" % args.out.resolve())
    return 0


def _fit_temperature(trainer, ds_val) -> float:
    """Single-parameter temperature scaling (Guo et al. 2017) on the val split,
    minimising multi-label BCE. Returns T; probs use sigmoid(logit / T)."""
    import numpy as np
    import torch
    from torch import nn

    pred = trainer.predict(ds_val)
    logits = torch.tensor(pred.predictions, dtype=torch.float32)
    labels = torch.tensor(np.array(ds_val["labels"]), dtype=torch.float32)
    log_t = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([log_t], lr=0.1, max_iter=60)
    loss_fn = nn.BCEWithLogitsLoss()

    def _closure():
        opt.zero_grad()
        loss = loss_fn(logits / log_t.exp(), labels)
        loss.backward()
        return loss

    opt.step(_closure)
    return float(log_t.exp().item()) or 1.0


def _write_model_card(args, val_metrics: Dict, test_metrics: Dict) -> None:
    card = f"""# ARGUS prompt-injection classifier

- **Base model**: `{args.base_model}`
- **Teacher (distillation)**: `{args.teacher_model or "none"}`
- **Task**: multi-label classification over {LABELS}
- **Training data**: `{args.corpus_dir}` (see `prompt_corpus.manifest.json`)
- **Intended use**: optional *evidence* signal inside ARGUS-IMG's prompt-injection
  detector. Runs offline on CPU. Never the sole basis for a policy decision —
  findings cap at `HIGHLY_LIKELY`.
- **Not for**: standalone content moderation, or any use where a false negative
  has no second line of defence.

## Metrics (attack = any non-benign label)

| split | precision | recall | f1 | macro_f1 |
|-------|-----------|--------|----|----------|
| val   | {val_metrics.get('eval_attack_precision', 0):.3f} | {val_metrics.get('eval_attack_recall', 0):.3f} | {val_metrics.get('eval_attack_f1', 0):.3f} | {val_metrics.get('eval_macro_f1', 0):.3f} |
| test  | {test_metrics.get('test_attack_precision', 0):.3f} | {test_metrics.get('test_attack_recall', 0):.3f} | {test_metrics.get('test_attack_f1', 0):.3f} | {test_metrics.get('test_macro_f1', 0):.3f} |

## Calibration

Run `tools/evaluation/calibrate_prompt_detectors.py` with
`ARGUS_PROMPT_CLASSIFIER_PATH` set to this directory, then edit
`argus_label_map.json` `threshold_block` / `threshold_review` to the chosen
operating point. The current corpus is synthetic (augmented from a 107-item
seed); replace it with public prompt-injection datasets + real OCR captures
before trusting these numbers.
"""
    (args.out / "model_card.md").write_text(card)


def _export_onnx(out: pathlib.Path) -> None:
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
        from optimum.onnxruntime.configuration import AutoQuantizationConfig
    except ImportError:
        print("optimum not installed — skipping ONNX export "
              "(pip install 'optimum[onnxruntime]')")
        return
    ort_model = ORTModelForSequenceClassification.from_pretrained(str(out), export=True)
    ort_model.save_pretrained(str(out))
    quantizer = ORTQuantizer.from_pretrained(str(out))
    quantizer.quantize(
        save_dir=str(out),
        quantization_config=AutoQuantizationConfig.avx512_vnni(is_static=False, per_channel=True),
    )
    # Normalise the quantized file name to model.onnx (what the adapter loads).
    for cand in ("model_quantized.onnx", "model.onnx"):
        p = out / cand
        if p.is_file():
            p.replace(out / "model.onnx")
            break
    print("exported int8 ONNX -> %s/model.onnx" % out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
