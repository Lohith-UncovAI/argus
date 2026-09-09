#!/usr/bin/env python3
"""Fine-tune a small *binary* (benign / injection) prompt-injection classifier.

The near-term realistic path: public prompt-injection datasets are binary, so
this trains a binary head (SAFE / INJECTION) rather than the multi-label schema
in train_prompt_classifier.py. The pipeline adapter handles both — a binary
model's ``INJECTION`` label maps to ``PROMPT_INJECTION`` via the name
heuristics, or via the ``argus_label_map.json`` this script writes.

Reads the corpus produced by ``assemble_training_corpus.py`` (train + val;
the held-out 107-item ARGUS corpus is the real evaluation, run through
``tools/evaluation/calibrate_prompt_detectors.py``).

Optional knowledge distillation from a base-size teacher (e.g. the ProtectAI
DeBERTa-v3-base prompt-injection model): the student matches the teacher's
softened class distribution on top of the hard-label loss.

Fits temperature scaling on val and writes it into ``argus_label_map.json`` so
the reported ``attack_likelihood`` is calibrated.

    python tools/training/train_binary_classifier.py \
        --corpus-dir tools/training/corpus \
        --base-model microsoft/deberta-v3-xsmall \
        --teacher-model models/pi-shadow-protectai \
        --out models/pi-argus-v1 --epochs 3 --export-onnx
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tempfile

ARGUS_LABEL_MAP = {
    "problem_type": "single_label_classification",
    "threshold_block": 0.60,
    "threshold_review": 0.35,
    "calibration": {"method": "temperature", "temperature": 1.0},
    "labels": {
        "0": {"name": "benign", "benign": True, "reason_codes": []},
        "1": {"name": "prompt_injection", "severity": "critical",
              "reason_codes": ["PROMPT_INJECTION"]},
    },
}


def _load(corpus_dir: pathlib.Path, split: str):
    path = corpus_dir / ("prompt_corpus.%s.jsonl" % split)
    if not path.is_file():
        raise SystemExit("missing %s — run assemble_training_corpus.py first" % path)
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _binlabel(row: dict) -> int:
    if "binary_label" in row:
        return int(row["binary_label"])
    return 0 if row.get("labels") == ["benign"] or row.get("label") == "benign" else 1


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus-dir", type=pathlib.Path, default=pathlib.Path("tools/training/corpus"))
    ap.add_argument("--base-model", default="microsoft/deberta-v3-xsmall")
    ap.add_argument("--teacher-model", default=None)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--distill-weight", type=float, default=0.0,
                    help="KL distillation weight. Default 0: the ProtectAI teacher cannot handle negation and poisons the student; keep the teacher for a shadow-eval reference only.")
    ap.add_argument("--distill-temp", type=float, default=2.0)
    ap.add_argument("--hard-negative-weight", type=float, default=3.0,
                    help="loss multiplier for contrastive-negation and vocabulary-trap benign examples")
    ap.add_argument("--export-onnx", action="store_true")
    ap.add_argument("--seed", type=int, default=20260908)
    args = ap.parse_args(argv)

    import numpy as np
    import torch
    from torch import nn
    from datasets import Dataset
    from sklearn.metrics import f1_score, precision_score, recall_score
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                              Trainer, TrainingArguments, set_seed)

    set_seed(args.seed)
    tr, va = _load(args.corpus_dir, "train"), _load(args.corpus_dir, "val")
    n_inj = sum(_binlabel(r) for r in tr)
    print("train=%d (inj=%d) val=%d  base=%s teacher=%s"
          % (len(tr), n_inj, len(va), args.base_model, args.teacher_model))

    tok = AutoTokenizer.from_pretrained(args.base_model)

    def _oversample(rows: List[dict]) -> List[dict]:
        """Repeat the examples the model most needs the contrast on:
        contrastive-negation pairs and vocabulary-trap hard negatives."""
        w = max(1, int(round(args.hard_negative_weight)))
        out = []
        for r in rows:
            src = r.get("source", "")
            n = 1
            if "contrast" in src:
                n = w + 1
            elif ("hardneg" in src or "ocr_capture" in src) and _binlabel(r) == 0:
                n = w
            out.extend([r] * n)
        return out

    def ds(rows):
        d = Dataset.from_dict({"text": [r["text"] for r in rows],
                               "label": [_binlabel(r) for r in rows]})
        return d.map(lambda b: tok(b["text"], truncation=True, max_length=args.max_length), batched=True)

    tr_os = _oversample(tr)
    n_inj = sum(_binlabel(r) for r in tr_os)
    d_tr, d_va = ds(tr_os), ds(va)
    print("train rows after oversampling hard negatives: %d (inj=%d)" % (len(tr_os), n_inj))

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=2,
        id2label={0: "SAFE", 1: "INJECTION"}, label2id={"SAFE": 0, "INJECTION": 1}).float()

    class_weight = torch.tensor([1.0, (len(tr_os) - n_inj) / max(n_inj, 1)], dtype=torch.float32)
    print("class weight:", [round(w, 3) for w in class_weight.tolist()])

    teacher = None
    if args.teacher_model:
        teacher = AutoModelForSequenceClassification.from_pretrained(args.teacher_model)
        teacher.eval()
        if torch.cuda.is_available():
            teacher.cuda()

    dw, dt = args.distill_weight, args.distill_temp

    class DistilTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            loss = nn.CrossEntropyLoss(weight=class_weight.to(out.logits.device))(out.logits, labels)
            if teacher is not None:
                with torch.no_grad():
                    t = teacher(input_ids=inputs["input_ids"],
                                attention_mask=inputs["attention_mask"]).logits
                kd = nn.KLDivLoss(reduction="batchmean")(
                    torch.log_softmax(out.logits / dt, -1),
                    torch.softmax(t / dt, -1)) * (dt * dt)
                loss = (1 - dw) * loss + dw * kd
            return (loss, out) if return_outputs else loss

    def metrics(ep):
        logits, labels = ep
        pred = logits.argmax(-1)
        return {"precision": precision_score(labels, pred, zero_division=0),
                "recall": recall_score(labels, pred, zero_division=0),
                "f1": f1_score(labels, pred, zero_division=0)}

    targs = TrainingArguments(
        output_dir=str(args.out / "_hf"), num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size, per_device_eval_batch_size=64,
        learning_rate=args.lr, warmup_ratio=0.1, eval_strategy="epoch",
        save_strategy="epoch", load_best_model_at_end=True, metric_for_best_model="f1",
        greater_is_better=True, logging_steps=50,
        bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
        fp16=torch.cuda.is_available() and not torch.cuda.is_bf16_supported(),
        report_to=[], seed=args.seed)

    trainer = DistilTrainer(model=model, args=targs, train_dataset=d_tr, eval_dataset=d_va,
                            processing_class=tok, compute_metrics=metrics)
    trainer.train()
    val = trainer.evaluate()
    print("VAL:", {k: round(v, 4) for k, v in val.items() if isinstance(v, float)})

    # temperature scaling on val logits
    pred = trainer.predict(d_va)
    logits = torch.tensor(pred.predictions, dtype=torch.float32)
    labels = torch.tensor(np.array(d_va["label"]), dtype=torch.long)
    log_t = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([log_t], lr=0.1, max_iter=60)
    opt.step(lambda: _temp_closure(opt, log_t, logits, labels, nn))
    temperature = float(log_t.exp().detach())
    print("fitted temperature:", round(temperature, 3))

    args.out.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(args.out))
    tok.save_pretrained(str(args.out))
    label_map = dict(ARGUS_LABEL_MAP)
    label_map["calibration"] = {"method": "temperature", "temperature": round(temperature, 4)}
    (args.out / "argus_label_map.json").write_text(json.dumps(label_map, indent=2))
    (args.out / "metrics.json").write_text(json.dumps(
        {"base_model": args.base_model, "teacher_model": args.teacher_model,
         "val": val, "temperature": temperature,
         "corpus_manifest": json.loads((args.corpus_dir / "manifest.json").read_text())
         if (args.corpus_dir / "manifest.json").is_file() else None}, indent=2))

    if args.export_onnx:
        _export_onnx(args.out)

    print("\nwrote model -> %s" % args.out)
    print("evaluate:  ARGUS_PROMPT_CLASSIFIER_PATH=%s "
          "PYTHONPATH=src python3 tools/evaluation/calibrate_prompt_detectors.py" % args.out.resolve())
    return 0


def _temp_closure(opt, log_t, logits, labels, nn):
    opt.zero_grad()
    loss = nn.CrossEntropyLoss()(logits / log_t.exp(), labels)
    loss.backward()
    return loss


def _export_onnx(out: pathlib.Path) -> None:
    import torch
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(out), local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(str(out), local_files_only=True).float().eval()
    encoded = tokenizer("Offline image text analysis", return_tensors="pt")
    input_names = list(encoded)

    class LogitsOnly(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.model = model

        def forward(self, *inputs):
            return self.model(**dict(zip(input_names, inputs))).logits

    dynamic_axes = {name: {0: "batch", 1: "sequence"} for name in input_names}
    dynamic_axes["logits"] = {0: "batch"}
    with tempfile.TemporaryDirectory(dir=out) as temporary:
        full_precision = pathlib.Path(temporary) / "model.onnx"
        with torch.no_grad():
            torch.onnx.export(LogitsOnly(), tuple(encoded.values()), str(full_precision),
                              input_names=input_names, output_names=["logits"],
                              dynamic_axes=dynamic_axes, opset_version=17, dynamo=False)
        quantize_dynamic(str(full_precision), str(out / "model.onnx"),
                         weight_type=QuantType.QInt8, per_channel=True)
    print("exported int8 ONNX -> %s/model.onnx" % out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
