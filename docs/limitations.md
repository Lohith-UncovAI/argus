# Limitations

- `NO_EVIDENCE_FOUND` is not proof of absence.
- Arbitrary encrypted steganography cannot be excluded.
- Unknown watermark schemes are unsupported unless a local detector is configured.
- OCR can miss small, rotated, distorted, low-contrast, or stylized text.
- Prompt detection can produce false positives and false negatives. It is a
  layered signal — deterministic regex rules, a heuristic scorer, and an
  optional local ML classifier — but no layer is complete (see
  `docs/prompt-classifier.md`).
- Malware detection requires local tools and local signatures.
- C2PA absence is neutral, and valid signatures do not prove depicted truth.
- No live revocation or threat-intelligence checks are performed.
- Synthetic-image classifiers are deferred. A local SmolVLM adapter exists but
  requires operator-staged weights and does not enable the VLM_READ_ONLY policy.
  The local
  prompt-injection classifier is implemented but optional — it is `NOT_TESTED`
  until an operator supplies a model directory.
- The prompt-injection classifier's non-English coverage is partial: the base
  tokenizer is English, so non-English attacks are flagged less reliably than
  English ones (`docs/prompt-classifier.md`, "Multilingual coverage").

## Known gap: injection text on severely rotated images

`deskew` (Hough-line skew correction) plus coarse `rotation-candidate-*`
transforms (30-degree steps, see `src/argus_img/transforms/registry.py`) give
OCR a real chance at large-angle rotated text, and this is verified to work:
Tesseract successfully reads injected text once a rotation candidate lands
within roughly +/-10-12 degrees of the true angle.

OCR output on a rotated image is often garbled even when a rotation candidate
is close to correct (font antialiasing and JPEG/PNG resampling artifacts
compound at non-axis-aligned angles), e.g. "previous instructions" may come
back as "PreViong trictiong".

**Partially addressed.** Naive fuzzy matching against the injection vocabulary
was investigated and rejected — ordinary words (`previously`, `precious`,
`system`, `admin`) sit too close in edit-distance to security vocabulary and
false-positive on benign settings screenshots. Instead, three narrower
mechanisms now run (`src/argus_img/detectors/prompt/decoders.py`, fed to all
three signals as extra text candidates):

* `_ocr_spell_repair` — per token, tries the common OCR character confusions
  (`rn`->`m`, `vv`->`w`, `cl`->`d`, `I`/`l`/`1`, `0`/`o`) and keeps a
  substitution *only* when it turns an unknown token into a dictionary word.
* `_resegment` / `_despace` — undo OCR word-gluing ("Nohidden instructions")
  and character-spacing obfuscation ("i.g.n.o.r.e.").
* the local ML classifier is trained on ~750 real easyocr captures of rendered
  ARGUS eval images (`tools/training/extract_ocr_captures.py`), i.e. exactly
  the garbled-attack vs. garbled-benign distribution a calibrated fuzzy matcher
  would need.

**Still unresolved:** a single OCR observation garbled badly enough that no
anchor token survives *and* no decoder can recover one (the leading word fully
destroyed, "Ignore" -> "e"). Payloads split across image regions are handled
separately by geometry-gated reassembly (`decoders.layout_join_texts`).

Fully closing the remaining gap needs an OCR-confidence-aware approach that
trusts high-confidence character runs and treats low-confidence runs
differently, rather than string-similarity heuristics on the raw output. Not
attempted here — Tesseract per-character confidence is not currently plumbed
through.
