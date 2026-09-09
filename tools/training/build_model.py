#!/usr/bin/env python3
"""One-command, reproducible build of the local prompt-injection classifier.

Chains the three existing steps and gates the result against a metrics floor so a
bad model can never be published by accident:

    1. assemble_training_corpus.py  -> tools/training/corpus/{train,val}.jsonl
    2. train_binary_classifier.py   -> <out>/  (safetensors + int8 ONNX)
    3. calibrate_prompt_detectors.py against the held-out corpus
       tools/evaluation/corpus/prompt_text_corpus.jsonl

Then writes ``<out>/PROVENANCE.json`` — git SHA, every step's arguments, the
random seed, sha256 of each corpus split, base model, dependency versions, the
evaluation metrics, and the classifier fingerprint — so the artifact is tied to
a reproducible recipe rather than a one-off GPU session.

Datasets and the base model are read from the local Hugging Face cache
(``deepset/prompt-injections``, ``xTRam1/safe-guard-prompt-injection``,
``microsoft/deberta-v3-xsmall``); training may use the network to populate that
cache but scan time never does.

    python tools/training/build_model.py --out models/pi-argus --epochs 3

Add ``--image-corpus <dir>`` to re-run OCR capture extraction first (slow;
otherwise the existing tools/training/corpus/ocr_captures.jsonl is reused).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "tools" / "training" / "corpus"
HELD_OUT = REPO_ROOT / "tools" / "evaluation" / "corpus" / "prompt_text_corpus.jsonl"

# A model below any of these on the held-out corpus is a regression — do not ship.
FLOORS = {
    "flat_attack_recall_pct": 97.0,      # tls-001 (no geometry in the flat harness) may miss
    "benign_plain_blocked": 0,
    "benign_trap_blocked": 0,
    "classifier_operating_recall": 0.95,
    "classifier_benign_fp_max": 2,       # doc-005 / ml-b01, both corroboration-bounded to REVIEW
}


def _run(argv: list[str], *, env: dict | None = None) -> None:
    print("\n$ " + " ".join(argv), flush=True)
    subprocess.run(argv, check=True, cwd=REPO_ROOT, env={**os.environ, **(env or {})})


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _dep_versions() -> dict:
    import onnxruntime
    import torch
    import transformers
    try:
        import datasets
        ds_v = datasets.__version__
    except Exception:  # noqa: BLE001
        ds_v = None
    return {
        "python": sys.version.split()[0],
        "torch": torch.__version__,
        "transformers": transformers.__version__,
        "onnxruntime": onnxruntime.__version__,
        "datasets": ds_v,
        "cuda": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
    }


def _git_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT,
                               capture_output=True, text=True, check=True).stdout.strip()
        return out.stdout.strip() + ("-dirty" if dirty else "")
    except Exception:  # noqa: BLE001
        return "unknown"


def _check_floors(report: dict) -> list[str]:
    try:
        if report.get("classifier_configured") is not True:
            return ["classifier was not configured during evaluation"]
        pipeline = report["pipeline_behaviour"]
        operating = report["classifier_sweep"]["operating_threshold_metrics"]
        values = [pipeline["overall_recall_pct"], operating["recall"], operating["fp"]]
        values.extend(pipeline["by_category"][category]["blocked"]
                      for category in ("benign_plain", "benign_trap"))
        if any(isinstance(value, bool) or not isinstance(value, (int, float))
               or not math.isfinite(value) or value < 0 for value in values):
            return ["evaluation contains invalid or non-finite metrics"]
        if values[0] > 100 or values[1] > 1 or any(value != int(value) for value in values[2:]):
            return ["evaluation metrics are outside their valid ranges"]
    except (KeyError, TypeError):
        return ["evaluation is missing required classifier or category metrics"]
    pb = report["pipeline_behaviour"]
    by_cat = pb["by_category"]
    cs = report["classifier_sweep"]
    failures = []

    recall = float(pb["overall_recall_pct"])
    if recall < FLOORS["flat_attack_recall_pct"]:
        failures.append("flat attack recall %.1f%% < %.1f%%" % (recall, FLOORS["flat_attack_recall_pct"]))

    for cat in ("benign_plain", "benign_trap"):
        blocked = int(by_cat.get(cat, {}).get("blocked", 0))
        if blocked > FLOORS["%s_blocked" % cat]:
            failures.append("%s produced %d BLOCK(s)" % (cat, blocked))

    best = cs["operating_threshold_metrics"]
    clf_recall = float(best.get("recall", 0.0))
    if clf_recall < FLOORS["classifier_operating_recall"]:
        failures.append("classifier operating recall %.3f < %.3f" % (clf_recall, FLOORS["classifier_operating_recall"]))
    fp = int(round(best.get("fp", best.get("false_positives", 0)) or 0))
    if fp > FLOORS["classifier_benign_fp_max"]:
        failures.append("classifier benign FP %d > %d at operating threshold" % (fp, FLOORS["classifier_benign_fp_max"]))
    return failures


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=pathlib.Path, required=True, help="model output dir, e.g. models/pi-argus")
    ap.add_argument("--base-model", default="microsoft/deberta-v3-xsmall")
    ap.add_argument("--epochs", type=float, default=4.0)
    ap.add_argument("--seed", type=int, default=20260908)
    ap.add_argument("--synthetic-multiplier", type=int, default=10)
    ap.add_argument("--image-corpus", type=pathlib.Path, default=None,
                    help="if given, re-run extract_ocr_captures.py over this labelled image corpus dir first "
                         "(requires --ocr-manifest)")
    ap.add_argument("--ocr-manifest", type=pathlib.Path, default=None,
                    help="labels manifest for --image-corpus")
    ap.add_argument("--skip-train", action="store_true", help="only re-assemble corpus + evaluate an existing --out model")
    ap.add_argument("--allow-below-floor", action="store_true",
                    help="write PROVENANCE even if the metrics floor is not met (still exits non-zero)")
    args = ap.parse_args(argv)

    out = args.out.resolve()
    if out.exists() and any(out.iterdir()) and not args.skip_train:
        ap.error("--out must be empty for a new build; use a separate candidate directory")
    py = sys.executable
    steps: list[dict] = []

    # 1. OCR captures (optional) --------------------------------------------------
    if args.image_corpus:
        if not args.ocr_manifest:
            ap.error("--image-corpus requires --ocr-manifest")
        cmd = [py, "tools/training/extract_ocr_captures.py",
               "--corpus", str(args.image_corpus),
               "--manifest", str(args.ocr_manifest),
               "--out", str(CORPUS_DIR / "ocr_captures.jsonl"), "--merge-lines"]
        _run(cmd)
        steps.append({"step": "extract_ocr_captures", "argv": cmd[2:]})
    elif not (CORPUS_DIR / "ocr_captures.jsonl").is_file():
        print("WARNING: no tools/training/corpus/ocr_captures.jsonl and no --image-corpus; "
              "training without real-OCR captures.")

    # 2. Assemble corpus --------------------------------------------------------
    asm = [py, "tools/training/assemble_training_corpus.py",
           "--out", str(CORPUS_DIR),
           "--synthetic-multiplier", str(args.synthetic_multiplier),
           "--seed", str(args.seed)]
    _run(asm)
    steps.append({"step": "assemble_training_corpus", "argv": asm[2:]})

    split_hashes = {
        name: _sha256(CORPUS_DIR / ("prompt_corpus.%s.jsonl" % name))
        for name in ("train", "val")
        if (CORPUS_DIR / ("prompt_corpus.%s.jsonl" % name)).is_file()
    }
    manifest = json.loads((CORPUS_DIR / "manifest.json").read_text())

    # 3. Train ----------------------------------------------------------------
    if not args.skip_train:
        tr = [py, "tools/training/train_binary_classifier.py",
              "--corpus-dir", str(CORPUS_DIR),
              "--base-model", args.base_model,
              "--out", str(out),
              "--epochs", str(args.epochs),
              "--seed", str(args.seed),
              "--export-onnx"]
        _run(tr)
        steps.append({"step": "train_binary_classifier", "argv": tr[2:]})

    else:
        # record the training args/metrics the existing model was built with
        mp = out / "metrics.json"
        if mp.is_file():
            m = json.loads(mp.read_text())
            steps.append({"step": "train_binary_classifier", "reused": True,
                          "base_model": m.get("base_model"), "val": m.get("val"),
                          "temperature": m.get("temperature")})

    # 4. Evaluate against the held-out corpus --------------------------------
    evaluation_path = out / "EVALUATION.json"
    ev = [py, "tools/evaluation/calibrate_prompt_detectors.py", "--output", str(evaluation_path)]
    _run(ev, env={"ARGUS_PROMPT_CLASSIFIER_PATH": str(out),
                  "ARGUS_PROMPT_CLASSIFIER_BACKEND": "onnx",
                  "PYTHONPATH": str(REPO_ROOT / "src")})
    steps.append({"step": "calibrate_prompt_detectors", "argv": ev[2:]})
    report = json.loads(evaluation_path.read_text())

    # 5. Fingerprint + provenance -----------------------------------------------
    sys.path.insert(0, str(REPO_ROOT / "src"))
    os.environ["ARGUS_PROMPT_CLASSIFIER_PATH"] = str(out)
    from argus_img.detectors.prompt.classifier import classifier_fingerprint, classifier_status

    failures = _check_floors(report)
    if report.get("model_fingerprint") != classifier_fingerprint():
        failures.append("evaluated model fingerprint differs from the build artifact")
    pb = report["pipeline_behaviour"]
    provenance = {
        "built_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "git_sha": _git_sha(),
        "base_model": args.base_model,
        "seed": args.seed,
        "steps": steps,
        "corpus": {"manifest": manifest, "split_sha256": split_hashes,
                   "held_out_corpus": str(HELD_OUT.relative_to(REPO_ROOT)),
                   "held_out_sha256": _sha256(HELD_OUT)},
        "dependencies": _dep_versions(),
        "evaluation": {
            "held_out_attack_recall_pct": pb["overall_recall_pct"],
            "held_out_false_positive_rate_pct": pb["overall_false_positive_rate_pct"],
            "missed_attacks": [m["id"] for m in pb["missed_attacks"]],
            "classifier_best_f1": report["classifier_sweep"].get("best_f1_threshold_metrics"),
            "classifier_operating": report["classifier_sweep"].get("operating_threshold_metrics"),
            "by_category": pb["by_category"],
        },
        "fingerprint": classifier_fingerprint(),
        "status": classifier_status(),
        "floor": FLOORS,
        "floor_met": not failures,
        "floor_failures": failures,
    }

    (out / "BUILD_REPORT.json").write_text(json.dumps(provenance, indent=2))
    if failures and not args.allow_below_floor:
        print("\nMETRICS FLOOR NOT MET:")
        for f in failures:
            print("  - " + f)
        print("\nRefusing to write PROVENANCE.json. Re-run with --allow-below-floor to override.")
        return 1

    (out / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2))
    print("\nwrote %s" % (out / "PROVENANCE.json"))
    print("floor_met=%s  recall=%.1f%%  fingerprint=%s"
          % (provenance["floor_met"], pb["overall_recall_pct"], provenance["fingerprint"]))
    if failures:
        print("(PROVENANCE written under --allow-below-floor; still exiting non-zero)")
        return 1
    print("\nPublish %s to the model registry, then set ARGUS_PROMPT_CLASSIFIER_PATH." % out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
