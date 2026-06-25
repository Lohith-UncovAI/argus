# Threat Model

Attacker capabilities include malformed image containers, metadata instructions, prompt injection text, low-contrast or channel-specific text, QR payloads, appended bytes, embedded payloads, misleading UI screenshots, privacy-sensitive text, and common steganography signals.

Protected assets include downstream model behavior, local files, credentials, user privacy, analysis integrity, and release artifacts.

Trust assumptions:

- Runtime is intended to be offline.
- Local optional tools are installed by the operator and are still treated as untrusted parsers.
- The host or container should enforce stronger network and filesystem isolation than the Python process alone can provide.

Out of scope:

- Proving that depicted events are true.
- Proving absence of all steganography or watermark schemes.
- Live threat intelligence.
- GPU scheduling and real VLM execution.

