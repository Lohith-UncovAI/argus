# ARGUS-IMG

ARGUS-IMG is a CPU-first, offline image-security analysis and content-disarm prototype. It accepts an untrusted raster image, quarantines the original bytes, reconstructs metadata-free derivatives, runs deterministic local analysis, and emits a structured JSON report with a policy decision.

The system does not claim an image is universally safe. Unknown encrypted steganography, unknown watermark schemes, OCR failures, stale local signatures, and model-specific adversarial perturbations remain possible.

## Quick Start

```bash
PYTHONPATH=src python3 scripts/generate_test_images.py
PYTHONPATH=src python3 -m argus_img.cli.main scan tests/fixtures/clean.png --output report.json
PYTHONPATH=src python3 -m argus_img.cli.main scan tests/fixtures/visible_prompt.png --profile AGENT_WITH_TOOLS
```

Run tests:

```bash
PYTHONPATH=src pytest
```

Run the API:

```bash
PYTHONPATH=src uvicorn argus_img.api.app:app --host 127.0.0.1 --port 8000
curl -F "file=@tests/fixtures/clean.png" -F "mode=fast" http://127.0.0.1:8000/v1/scans
```

## Threat Model

Uploaded bytes are hostile. The original container is stored in quarantine and is not released through the normal artifact endpoint. Downstream semantic analysis uses reconstructed pixel artifacts, not the uploaded container. Detectors produce evidence; only the deterministic policy engine produces the final action.

## Current Backends

Implemented baseline:

- Pillow intake validation and metadata-free reconstruction.
- Content-addressed local artifact store.
- Optional ExifTool JSON metadata adapter when the local binary is installed.
- Tesseract OCR adapter when the local binary is installed.
- pyzbar QR/barcode adapter when local libraries are available.
- YAML prompt-injection rules and deterministic intent context.
- Privacy and phishing heuristics.
- Structural trailing-byte detection and basic entropy summary.
- Null/mock interfaces for prompt classifiers, VLMs, watermark detectors, and steganalysis models.

Optional tools such as ExifTool, ClamAV, YARA, Binwalk, zsteg, C2PA, PaddleOCR, and OpenCV degrade to explicit `UNSUPPORTED` or `NOT_TESTED` statuses when unavailable. ExifTool output is parsed locally in JSON mode and precise GPS values are not returned by default.

## Reconstructed Artifacts

ARGUS-IMG creates `canonical_lossless.png`, `canonical_lossy.jpg`, `flattened_white.png`, and `flattened_black.png` from validated pixels. These artifacts are newly encoded and metadata-free. Recompression can disrupt fragile payloads, but the report never claims all hidden information was removed.

## Limitations

This milestone is useful without a GPU or VLM, but it is not a complete forensic suite. It does not execute real malware scanning without local tools, does not retrieve remote threat intelligence, does not perform remote C2PA checks, and does not prove absence of hidden content.
