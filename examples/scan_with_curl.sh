#!/usr/bin/env sh
curl -s -F "file=@tests/fixtures/clean.png" -F "mode=fast" -F "use_profile=AGENT_WITH_TOOLS" http://127.0.0.1:8000/v1/scans

