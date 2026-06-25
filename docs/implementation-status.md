# Implementation Status

| component | status | implemented backend | test status | known limitations | next work |
|---|---|---|---|---|---|
| core models | implemented | Pydantic v2 | unit tests | schema is broad | expand detector schemas |
| artifact store | implemented | local content-addressed store | unit/integration tests | single-process index | locking for concurrent API workers |
| intake | implemented | magic bytes + Pillow validation | unit/integration tests | limited malformed-header fixtures | deeper container parsing |
| reconstruction | implemented | Pillow PNG/JPEG encoders | integration tests | first frame baseline | full animation derivatives |
| differential decode | partial | Pillow + optional OpenCV | module status | OpenCV absent here | add LibVips adapter |
| OCR | partial | local Tesseract adapter | integration tests when installed | confidence boxes not parsed | TSV parsing and merge scoring |
| QR/barcode | partial | pyzbar adapter | unsupported if local zbar absent | no OpenCV fallback yet | add OpenCV QR fallback |
| metadata | partial | Pillow metadata + optional ExifTool JSON adapter | unit/integration tests | ExifTool must be locally installed; embedded extraction is not enabled | richer ExifTool field mapping and thumbnail extraction |
| prompt rules | implemented | YAML regex + intent context | unit/integration tests | deterministic context is imperfect | classifier adapter |
| privacy/phishing | partial | regex heuristics | unit/integration tests | limited region evidence | stronger UI detectors |
| malware/embedded tools | interface | status adapters | status tests | no real scanning without tools | mocked output parsers |
| steganography | partial | trailing bytes + entropy status | unit/integration tests | weak evidence only | zsteg parser and bit-plane reports |
| watermarks | interface | visible text heuristic | unit tests | no invisible schemes | plugin registry loading |
| VLM/shadow | interface | Null and Mock analyzers | unit tests | no real model execution | local model adapter |
| policy | implemented | deterministic YAML engine | unit tests | limited operators | full nested operators |
| API | implemented | FastAPI synchronous scan | smoke tests | multipart dependency needed | async job model |
| CLI | implemented | Typer with argparse fallback | integration tests | Typer absent locally | package install test |
| offline guard | partial | URL/model checks + self-test | unit tests | not host isolation | stricter socket monkeypatch tests |
