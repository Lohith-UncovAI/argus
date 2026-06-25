# Detector Development

A detector should produce observations and findings, not policy decisions. Add a typed detector manifest, return explicit unsupported or error states, and trace every finding to source artifacts and observations.

External tools must use `argus_img.subprocesses.runner.run_tool`. Do not use `shell=True`, do not fetch URLs, and do not treat missing tools as clean results.

Text-producing detectors should emit `TextObservation` objects and let the normalization, prompt-rule, privacy, and phishing layers analyze derived text.

The ExifTool adapter is the reference pattern for optional metadata tools: it runs in JSON mode, records `UNSUPPORTED` when missing, emits free-text metadata as `TextObservation`, and redacts location values while still producing a privacy finding.
