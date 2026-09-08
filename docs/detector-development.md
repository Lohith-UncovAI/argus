# Detector Development

A detector should produce observations and findings, not policy decisions. Add a typed detector manifest, return explicit unsupported or error states, and trace every finding to source artifacts and observations.

External tools must use `argus_img.subprocesses.runner.run_tool`. Do not use `shell=True`, do not fetch URLs, and do not treat missing tools as clean results.

Text-producing detectors should emit `TextObservation` objects and let the normalization, prompt-rule, privacy, and phishing layers analyze derived text.

The ExifTool adapter is the reference pattern for optional metadata tools: it runs in JSON mode, records `UNSUPPORTED` when missing, emits free-text metadata as `TextObservation`, and redacts location values while still producing a privacy finding.

The prompt-injection classifier (`detectors/prompt/classifier.py`, `classify.py`) is the reference pattern for an optional *local ML model*: gated on a configured model directory via `prompt_classifier_available()` (mirroring `vlm_detector.vlm_available()`), `local_files_only=True` on every load, `NOT_TESTED` when unconfigured, findings capped at `HIGHLY_LIKELY` (evidence only), and a `model_fingerprint` on every finding. Its threshold sweep lives in `tools/evaluation/calibrate_prompt_detectors.py`.
