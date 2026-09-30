from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
KB_DIR = ROOT / "config" / "kb"
NAMESPACES = ("asset", "behavior", "threat", "playbook")


class KnowledgeBase:
    def __init__(self, kb_dir: Path | None = None):
        self.kb_dir = kb_dir or KB_DIR
        self.documents: dict[str, list[dict[str, Any]]] = {}
        for namespace in NAMESPACES:
            path = self.kb_dir / f"{namespace}.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.documents[namespace] = list(payload.get("documents", []))

    def all_source_ids(self) -> set[str]:
        ids: set[str] = set()
        for docs in self.documents.values():
            for doc in docs:
                source_id = doc.get("source_id")
                if source_id:
                    ids.add(str(source_id))
        return ids

    def get_by_id(self, source_id: str) -> dict[str, Any] | None:
        for docs in self.documents.values():
            for doc in docs:
                if doc.get("source_id") == source_id:
                    return doc
        return None
