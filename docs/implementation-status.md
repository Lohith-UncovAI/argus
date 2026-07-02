# Implementation Status

| component | status | implemented backend | test status | known limitations | next work |
|---|---|---|---|---|---|
| core models | implemented | Pydantic v2 | unit tests | schema is broad | expand detector schemas |
| artifact store | implemented | CAS store + scan_id cascade delete + CAS re-verification | unit/integration/security tests | single-process index | locking for concurrent API workers |
| intake | implemented | magic bytes + Pillow validation | unit/integration tests | limited malformed-header fixtures | deeper container parsing |
| reconstruction | implemented | Pillow PNG/JPEG encoders | integration tests | first frame baseline | full animation derivatives |
| differential decode | implemented | Pillow + OpenCV channel-difference, CLAHE, deskew | unit/integration tests | LibVips adapter absent | add LibVips adapter |
| OCR | implemented | Tesseract + EasyOCR (offline) + SmolVLM-256M (offline) | unit/integration tests | steganographic text unreadable by all OCR | EasyOCR model local cache path required |
| QR/barcode | partial | pyzbar adapter | unsupported if local zbar absent | no OpenCV fallback yet | add OpenCV QR fallback |
| metadata | partial | Pillow metadata + optional ExifTool JSON adapter | unit/integration tests | ExifTool must be locally installed | richer ExifTool field mapping |
| semantic scorer | implemented | token/bigram/structural patterns + figstep/indirect-ref coverage | unit tests (36) | 97% GT BLOCK; steganographic text undetectable | VLM-only patterns for obfuscated images |
| prompt rules | implemented | YAML regex + intent context | unit/integration tests | deterministic context is imperfect | classifier adapter |
| privacy/phishing | partial | regex heuristics | unit/integration tests | limited region evidence | stronger UI detectors |
| malware/embedded tools | partial | ClamAV + YARA + binwalk adapters | status tests | tools must be locally installed | mocked output parsers |
| steganography | partial | trailing bytes + entropy status | unit/integration tests | VLM-based obfuscated text still 16-56% detected | zsteg parser and bit-plane reports |
| watermarks | interface | visible text heuristic | unit tests | no invisible schemes | plugin registry loading |
| VLM | implemented | SmolVLM-256M-Instruct (offline, MPS/CPU) | unit tests + availability gate | local model path required; ~2-10s/image | larger model for obfuscated text |
| policy | implemented | deterministic YAML engine | unit tests | limited operators | full nested operators |
| API | implemented | FastAPI + body-size + concurrency middleware | security tests | synchronous scan path | async job model |
| CLI | implemented | Typer with argparse fallback | integration tests | Typer absent locally | package install test |
| offline guard | implemented | passive checks only (no outbound socket) | security tests | not host isolation | stricter seccomp |
| security (ARGUS findings) | implemented | ARGUS-03/04/05/08/09/10/11 all fixed; ARGUS-02 N/A | 185 tests pass | ARGUS-01 (parser worker wiring) still open | wire parser_worker into pipeline |
