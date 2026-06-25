# Offline Deployment

The Python runtime makes no cloud API calls, downloads no models, fetches no QR URLs, and performs no telemetry. Optional tools and models must be local.

For container deployment, run with no network, a read-only application filesystem, a writable job/artifact volume, no new privileges, and dropped capabilities. The included compose file uses `network_mode: "none"` and `read_only: true`.

Application-level `OfflineGuard` detects remote input/model identifiers and exposes a self-test, but host or container isolation remains required for strong offline guarantees.

