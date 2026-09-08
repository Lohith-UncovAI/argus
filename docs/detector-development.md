# Detector Development

A detector should produce observations and findings, not policy decisions. Add a typed detector manifest, return explicit unsupported or error states, and trace every finding to source artifacts and observations.

External tools must use `argus_img.subprocesses.runner.run_tool`. Do not use `shell=True`, do not fetch URLs, and do not treat missing tools as clean results.

Text-producing detectors should emit `TextObservation` objects and let the normalization, prompt-rule, privacy, and phishing layers analyze derived text.

The ExifTool adapter is the reference pattern for optional metadata tools: it runs in JSON mode, records `UNSUPPORTED` when missing, emits free-text metadata as `TextObservation`, and redacts location values while still producing a privacy finding.

The prompt-injection classifier (`detectors/prompt/classifier.py`, `classify.py`) is the reference pattern for an optional *local ML model*: gated on a configured model directory via `prompt_classifier_available()` (mirroring `vlm_detector.vlm_available()`), `local_files_only=True` on every load, `NOT_TESTED` when unconfigured, findings capped at `HIGHLY_LIKELY` (evidence only), and a `model_fingerprint` on every finding. It also demonstrates the supporting infrastructure an ML detector needs:

* **Reproducible build** — `tools/training/build_model.py` chains corpus assembly, training, ONNX export and held-out evaluation, enforces a metrics floor, and writes `PROVENANCE.json` (git SHA, step args, seed, corpus hashes, deps, metrics, fingerprint). The model artifact stays gitignored and is operator-supplied.
* **Calibration gate** — `tools/evaluation/calibrate_prompt_detectors.py` (threshold sweep + per-category recall/FPR against a held-out corpus).
* **Deploy preflight** — `classifier_preflight()` / `python -m argus_img.detectors.prompt.classifier` validates a configured model dir and exits non-zero with concrete problems; the same list appears in `GET /v1/capabilities`.
* **Corroboration** — a lone classifier BLOCK on an observation no deterministic signal flagged is emitted as REVIEW, not BLOCK.

See `docs/prompt-classifier.md`.
