"""Deterministic importer for the two services that both ship a top-level
``src`` package (packet-sensor and sensel-edge-agent).

Both services name their package ``src``, so a bare ``import src`` is ambiguous
and order-dependent when both are on ``sys.path`` during a test run. This helper
clears any cached ``src*`` modules, pins ``sys.path`` to exactly one service's
directory, then imports — making tests independent of execution order without
touching runtime code or Docker images.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

_ROOT = Path(__file__).resolve().parents[1]
SERVICE_DIRS = {
    "packet-sensor": _ROOT / "services" / "packet-sensor",
    "sensel-edge-agent": _ROOT / "services" / "sensel-edge-agent",
}
_ALL_SERVICE_PATHS = {str(d) for d in SERVICE_DIRS.values()}


def import_from_service(service: str, *dotted_paths: str) -> ModuleType | tuple[ModuleType, ...]:
    """Import one or more ``src.*`` modules from a specific service.

    Returns a single module when one path is given, otherwise a tuple in order.
    """
    if service not in SERVICE_DIRS:
        raise KeyError(f"unknown service {service!r}; known: {sorted(SERVICE_DIRS)}")
    service_dir = str(SERVICE_DIRS[service])

    for key in list(sys.modules):
        if key == "src" or key.startswith("src."):
            del sys.modules[key]
    # Ensure only the chosen service's directory provides ``src``.
    sys.path[:] = [p for p in sys.path if p not in _ALL_SERVICE_PATHS]
    sys.path.insert(0, service_dir)

    modules = tuple(importlib.import_module(path) for path in dotted_paths)
    return modules[0] if len(modules) == 1 else modules
