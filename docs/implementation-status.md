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
| semantic scorer | implemented | token/bigram/structural patterns + figstep/indirect-ref coverage | unit tests (36) | 97% GT BLOCK; steganographic text undetectable | VLM-only patterns for obfuscated images |
| prompt rules | implemented | YAML regex + intent context | unit/integration tests | deterministic context is imperfect | classifier adapter |
| privacy/phishing | partial | regex heuristics + login-form structure fallback | unit/integration tests | limited region evidence | stronger UI detectors |
| malware/embedded tools | partial | ClamAV + YARA + binwalk adapters | status tests | tools must be locally installed | mocked output parsers |
| steganography | partial | trailing bytes + entropy status | unit/integration tests | VLM-based obfuscated text still 16-56% detected | zsteg parser and bit-plane reports |
| watermarks | interface | visible text heuristic | unit tests | no invisible schemes | plugin registry loading |
| VLM | implemented | SmolVLM-256M-Instruct (offline, MPS/CPU) | unit tests + availability gate | local model path required; ~2-10s/image | larger model for obfuscated text |
| policy | implemented | deterministic YAML engine | unit tests | limited operators | full nested operators |
| API | implemented | FastAPI + body-size + concurrency middleware | security tests | synchronous scan path | async job model |
| CLI | implemented | Typer with argparse fallback, storage status/cleanup commands | integration tests | Typer absent locally | package install test |
| offline guard | implemented | passive checks only (no outbound socket) | security tests | not host isolation | stricter seccomp |
| security (ARGUS findings) | implemented | ARGUS-03/04/05/08/09/10/11 all fixed; ARGUS-02 N/A; strict profiles fail closed when parser-worker infrastructure is unavailable | 224 tests pass | ARGUS-01 remains open: parser worker is pre-validation only; main process still performs Pillow/OpenCV/OCR parsing | move frame extraction, thumbnails, transformations, and OCR into parser_worker |

## Current verification snapshot

- Date: July 8, 2026.
- Git SHA at latest evaluation start: `5f0232a`.
- Full test suite: `PYTHONPATH=src .venv/bin/pytest -q` passed for 224 collected tests; warnings were deprecations only.
- Latest targeted evaluation: `evaluation-results/latest/20260708-150030`, acceptance gate `PASS`, 6 scans, 0 release-grant violations.
- Latest evaluation config hash: `sha256:99d7227895ea3713b82be8362a03093674a796778f908e7d7cc1c2d56e37e299` with run-local `ARGUS_DATA_DIR`.
- Historical folders `random-dataset-20260707-argus`, `retest-previous-fail-cases-20260707-final`, and `more-diverse-20260707` are historical only because their `UNSUPPORTED` actions predate the ClamAV database fix.
- Current known gaps: default user eval store over quota, `more_046` OCR-region miss, and incomplete parser-worker isolation.
