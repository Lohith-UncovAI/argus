# Offline Deployment

The Python runtime makes no cloud API calls, downloads no models, fetches no QR URLs, and performs no telemetry. Optional tools and models must be local.

For container deployment, run with no network, a read-only application filesystem, a writable job/artifact volume, no new privileges, and dropped capabilities. The included compose file uses `network_mode: "none"` and `read_only: true`.

Application-level `OfflineGuard` detects remote input/model identifiers and exposes a self-test, but host or container isolation remains required for strong offline guarantees.

Regenerate deployment dependencies after changing `pyproject.toml`:

```bash
uv lock
uv export --locked --format requirements-txt --no-dev --no-editable --output-file requirements.lock
uv export --locked --format requirements-txt --no-dev --no-emit-project --output-file requirements-pinned.txt
```

The container export excludes the local project because Docker installs its
source in a later layer. Stage Tesseract and English language data for image OCR;
an absent OCR backend is incomplete coverage, not evidence that image text is benign.

## Optional local models

The prompt-injection classifier (`ARGUS_PROMPT_CLASSIFIER_PATH`) and the visual analyzer are operator-supplied local directories. Every `from_pretrained` passes `local_files_only=True`; nothing is fetched at scan time. Stage the model directory onto the host, then run the preflight check before starting the service:

For ONNX deployments, stage the `prompt-classifier` extra using
`uv sync --locked --extra prompt-classifier` on the build host.

```
PYTHONPATH=src python -m argus_img.detectors.prompt.classifier
```

It exits non-zero and lists concrete problems (missing files, wrong backend, bad label map) instead of the classifier silently disabling itself. `GET /v1/capabilities` and `GET /v1/attestation` report the loaded model's fingerprint; confirm it matches the published artifact. Training a classifier (`tools/training/build_model.py`) may use the network to populate the Hugging Face cache — that is a build-host step, never a scan-host one.
