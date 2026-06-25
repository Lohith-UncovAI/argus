"""Disposable parser worker package.

Each scan launches a short-lived subprocess (the parser worker) that performs
all hostile image parsing — Pillow, OpenCV, frame extraction, transforms, QR,
metadata, OCR — isolated from the API, policy engine, and release-grant
database.  The control process (pipeline.py) retains responsibility for
policy evaluation and transactional release.
"""
