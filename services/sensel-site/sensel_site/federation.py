"""Framework-neutral boundary for later Flower/XGBoost federation adapters."""

from __future__ import annotations

from typing import Any, Protocol


class FederatedClient(Protocol):
    """P3/P4 adapter seam; P3-A deliberately provides no network implementation."""

    def receive_round(self) -> dict[str, Any] | None: ...

    def submit_candidate(self, manifest: dict[str, Any], artifact: bytes) -> str: ...
