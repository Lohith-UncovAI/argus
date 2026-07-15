# Limitations

- `NO_EVIDENCE_FOUND` is not proof of absence.
- Arbitrary encrypted steganography cannot be excluded.
- Unknown watermark schemes are unsupported unless a local detector is configured.
- OCR can miss small, rotated, distorted, low-contrast, or stylized text.
- Rule-based prompt detection can produce false positives and false negatives.
- Malware detection requires local tools and local signatures.
- C2PA absence is neutral, and valid signatures do not prove depicted truth.
- No live revocation or threat-intelligence checks are performed.
- Real local VLM and synthetic-image classifiers are deferred.

## Known gap: injection text on severely rotated images

`deskew` (Hough-line skew correction) plus coarse `rotation-candidate-*`
transforms (30-degree steps, see `src/argus_img/transforms/registry.py`) give
OCR a real chance at large-angle rotated text, and this is verified to work:
Tesseract successfully reads injected text once a rotation candidate lands
within roughly +/-10-12 degrees of the true angle.

What remains unresolved: OCR output on a rotated image is often garbled even
when a rotation candidate is close to correct (font antialiasing and JPEG/PNG
resampling artifacts compound at non-axis-aligned angles), e.g. "previous
instructions" may come back as "PreViong trictiong". The rule-based matcher
(`src/argus_img/detectors/prompt/rules.py`) and the semantic scorer
(`src/argus_img/detectors/prompt/semantic.py`) both require literal or
near-literal token matches and do not recognize this text as an injection
attempt.

Fuzzy/approximate string matching was investigated as a fix and rejected:
matching individual garbled tokens against the injection vocabulary (e.g.
"trictiong" ~ "instructions") produces unacceptable false positives, because
many ordinary English and technical words (`previously`, `precious`, `system`,
`admin`, `reset`, `developer mode`) sit close enough in edit-distance to
security-relevant vocabulary to trigger on ordinary benign text — a photo of
a settings screen or a sentence about "resetting the previous password"
scores as high or higher than genuine garbled attack text. Requiring ordered
bigram pairs (mirroring the existing exact bigram scorer) eliminated those
false positives but then missed the motivating case, because OCR had already
destroyed the leading word ("Ignore" -> "e") beyond recognition. A narrower
attempt — fuzzy-matching only the synthetic eval canary string
(`ARGUS-CANARY-7F91`) — also has a real collision (the token "argus" alone
matches the retailer name "Argos" at the same similarity ratio a garbled
canary produces), and requiring the full multi-part canary to survive OCR
misses cases where only a fragment survives.

Closing this gap needs either: (1) an OCR-confidence-aware approach that
trusts high-confidence character runs and treats low-confidence output
differently, rather than string-similarity heuristics on the raw output, or
(2) a properly calibrated fuzzy matcher tuned and validated against a real
corpus of garbled-attack vs. garbled-benign OCR samples, not ad hoc
thresholds. Neither was attempted here.

