"""Digest-verified Site policy/model cache; activation is intentionally separate."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sensel_site.store import SiteStore

_IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class ArtifactCache:
    def __init__(self, store: SiteStore, root: str | Path) -> None:
        self.store = store
        self.root = Path(root)

    def install(
        self,
        source: str | Path,
        *,
        kind: str,
        artifact_id: str,
        version: str,
        expected_sha256: str,
        media_type: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> tuple[Path, bool]:
        if kind not in {"model", "policy"}:
            raise ValueError("Site artifact kind must be model or policy")
        if not all(_IDENTIFIER.fullmatch(value) for value in (artifact_id, version)):
            raise ValueError("invalid Site artifact identity/version")
        source_path = Path(source)
        payload = source_path.read_bytes()
        actual = "sha256:" + hashlib.sha256(payload).hexdigest()
        if actual != expected_sha256:
            raise ValueError("Site artifact digest mismatch")
        target_dir = self.root / kind / artifact_id / version
        target_dir.mkdir(parents=True, mode=0o750, exist_ok=True)
        final = target_dir / "artifact.bin"
        if not final.exists():
            temporary = target_dir / f".artifact.{uuid.uuid4()}.tmp"
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o440)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, final)
        elif "sha256:" + hashlib.sha256(final.read_bytes()).hexdigest() != actual:
            raise ValueError("cached Site artifact content conflict")
        created = self.store.save_cached_artifact(
            kind=kind,
            artifact_id=artifact_id,
            version=version,
            sha256=actual,
            media_type=media_type,
            path=str(final),
            metadata=dict(metadata or {}),
        )
        return final, created
