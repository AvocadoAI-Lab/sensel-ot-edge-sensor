"""Local model artifact integrity checks."""

from __future__ import annotations

import hashlib
from pathlib import Path


def verify_artifact_sha256(path: str | Path, expected_sha256: str) -> None:
    expected = expected_sha256.strip().lower()
    if not expected:
        raise ValueError("model artifact sha256 is required")
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise ValueError("model artifact sha256 must be 64 lowercase hex characters")
    hasher = hashlib.sha256()
    with Path(path).open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    if digest != expected:
        raise ValueError(
            f"model artifact sha256 mismatch: expected {expected}, received {digest}"
        )
