"""Durably append locally-generated Trust Episodes for the Edge Agent."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class TrustEpisodeWriter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, episode: Mapping[str, Any]) -> None:
        episode_id = str(episode.get("episode_id") or "").strip()
        if not episode_id:
            raise ValueError("Trust Episode writer requires episode_id")
        encoded = (
            json.dumps(
                dict(episode),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        descriptor = os.open(
            self.path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            0o600,
        )
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
