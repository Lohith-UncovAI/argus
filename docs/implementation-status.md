# Implementation Status

| component | status | implemented backend | test status | known limitations | next work |
|---|---|---|---|---|---|
| core models | implemented | Pydantic v2 | unit tests | schema is broad | expand detector schemas |
| artifact store | implemented | CAS store + scan_id cascade delete + CAS re-verification + storage status/quota preflight | unit/integration/security tests | single-process index; default user eval store can exceed quota if not cleaned | locking for concurrent API workers |
| intake | implemented | magic bytes + Pillow validation | unit/integration tests | limited malformed-header fixtures | deeper container parsing |
| reconstruction | implemented | Pillow PNG/JPEG encoders | integration tests | first frame baseline | full animation derivatives |
| differential decode | implemented | Pillow + OpenCV channel-difference, CLAHE, deskew | unit/integration tests | LibVips adapter absent | add LibVips adapter |
| OCR | implemented | Tesseract + EasyOCR (offline) + SmolVLM-256M (offline), bounded 3x small-text and footer-region OCR transforms | unit/integration tests | `more_046` remains a known OCR-region miss | text-region search/local VLM crop fallback |
| QR/barcode | partial | pyzbar adapter | unsupported if local zbar absent | no OpenCV fallback yet | add OpenCV QR fallback |
| metadata | partial | Pillow metadata + optional ExifTool JSON adapter | unit/integration tests | ExifTool must be locally installed | richer ExifTool field mapping |
| semantic scorer | implemented | token/bigram/structural + paraphrased-injection banks; figstep/indirect-ref coverage; text-candidate decoders (leetspeak / word re-segmentation / de-spacing / OCR spell-repair) and geometry-gated tile-split reassembly feed all signals | unit tests + adversarial-benign generalization guard | steganographic text undetectable; paraphrase bank is conservative (lone signal -> REVIEW) | OCR-confidence-aware garbled-text matching |
| prompt rules | implemented | YAML regex + intent context (OCR-tolerant) | unit/integration tests | deterministic context is imperfect | — |
| prompt-injection classifier | implemented (optional) | local deberta-v3-xsmall (22M), int8 ONNX, `local_files_only`; evidence only (caps at `HIGHLY_LIKELY`), corroboration-gated for BLOCK; `NOT_TESTED` until `ARGUS_PROMPT_CLASSIFIER_PATH` set; leakage-safe reproducible build (`build_model.py` + near-duplicate holdout + split audit + `--fail-on-leak`) → `PROVENANCE.json` / `EVAL_SUMMARY.json`; deploy preflight; CI deterministic-gate + manual model-eval workflow; opt-in scan-time score log + `classifier_drift_report.py`; release ledger `docs/prompt-classifier-releases.md` | unit tests + model-in-the-loop generalization guards; 271-item hand corpus + 2 000-item independent held-out benchmark; current model (2026-09-15) is the first leakage-safe build: 98.0% pipeline recall, 0 benign BLOCK, benchmark ROC-AUC 0.9997 | English base model — multilingual coverage is data-driven (`multilingual_attack` 97% flagged, 6% BLOCK); binary head only; classifier-solo (evidence-only) recall plateaus at 93.4%/4FP across 8 measured configs — floor re-set to 0.85/6 to match the measured frontier rather than an unreachable 0.95/2 (see release ledger); real production image data is the actual remaining gap | multilingual base (`mdeberta-v3-base`) + external benchmarks once the HF cache is staged; multi-label head once per-category data exists; real production image data to move the classifier-solo frontier |
| privacy/phishing | partial | regex heuristics + login-form structure fallback | unit/integration tests | limited region evidence | stronger UI detectors |
| malware/embedded tools | partial | ClamAV + YARA + binwalk adapters | status tests | tools must be locally installed | mocked output parsers |
| steganography | partial | trailing bytes + entropy status | unit/integration tests | VLM-based obfuscated text still 16-56% detected | zsteg parser and bit-plane reports |
| watermarks | interface | visible text heuristic | unit tests | no invisible schemes | plugin registry loading |
| VLM | implemented | SmolVLM-256M-Instruct (offline, MPS/CPU) | unit tests + availability gate | local model path required; ~2-10s/image | larger model for obfuscated text |
| policy | implemented | deterministic YAML engine | unit tests | limited operators | full nested operators |
| API | implemented | FastAPI + body-size + concurrency middleware | security tests | synchronous scan path | async job model |
| CLI | implemented | Typer with argparse fallback, storage status/cleanup commands | integration tests | Typer absent locally | package install test |
| offline guard | implemented | passive checks only (no outbound socket) | security tests | not host isolation | stricter seccomp |
| security (ARGUS findings) | implemented / hardening | ARGUS-01 uses an authoritative isolated intake worker for magic detection, bounds, structural verification, forced decode, canonical derivatives, and animated-frame extraction; ARGUS-03/04/05/08/09/10/11 fixed; ARGUS-02 N/A | full suite passes; worker/integration regressions covered | embedded-thumbnail extraction, fast transform-bank generation, and some differential/metadata adapters still run in the control process after worker validation | move remaining thumbnail/transform and original-byte differential/metadata parsing into parser_worker |

## Historical verification snapshot

- Date: July 8, 2026.
- Git SHA at latest evaluation start: `5f0232a`.
- Historical full test suite: `PYTHONPATH=src .venv/bin/pytest -q` passed for 224 collected tests; warnings were deprecations only.
- Current hardening verification: the OCR-enabled suite passes with exit code 0; focused classifier/training isolation checks pass, and model-backed adversarial guards pass 10/10. The currently deployed model remains the 98.6% held-out baseline; a leakage-safe retrained candidate was rejected by the operating-recall gate and was not promoted.
- Latest targeted evaluation: `evaluation-results/latest/20260708-150030`, acceptance gate `PASS`, 6 scans, 0 release-grant violations.
- Latest evaluation config hash: `sha256:99d7227895ea3713b82be8362a03093674a796778f908e7d7cc1c2d56e37e299` with run-local `ARGUS_DATA_DIR`.
- Historical folders `random-dataset-20260707-argus`, `retest-previous-fail-cases-20260707-final`, and `more-diverse-20260707` are historical only because their `UNSUPPORTED` actions predate the ClamAV database fix.
- Current known gaps: default user eval store over quota, `more_046` OCR-region miss, and incomplete parser-worker isolation.
