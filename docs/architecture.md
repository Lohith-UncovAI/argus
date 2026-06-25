# Architecture

ARGUS-IMG separates the original-byte path from the decoded-pixel path.

The original-byte path performs intake validation, content-addressed quarantine, format detection, structural checks, metadata inspection, provenance status, optional malware adapters, and steganography signals. The decoded-pixel path reconstructs bounded pixels into new images, generates deterministic transformations, runs OCR and QR decoding, and sends text evidence into prompt, privacy, phishing, and policy analysis.

Trust boundaries:

- Uploaded bytes are hostile.
- Metadata and OCR text are untrusted evidence.
- Optional model outputs are untrusted witness statements.
- The policy engine is the only component that returns a final action.
- Normal artifact release only serves reconstructed artifacts marked `release_eligible`.

The evidence graph links artifacts, transformations, observations, findings, and policy decisions through typed adjacency lists. A graph database is not required for this milestone.

Future VLM integration is isolated behind `VisualAnalyzer`, with separate calls for literal inventory, instruction analysis, deception analysis, OCR verification, and shadow testing. A real model must receive only reconstructed artifacts and no operational tools.

