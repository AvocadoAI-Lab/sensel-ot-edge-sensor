from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from .kb import KnowledgeBase


ALLOWED_TOOLS = {
    "get_asset_profile",
    "get_behavior_baseline",
    "search_threat_knowledge",
    "search_playbook",
    "get_related_events",
}

# Retrieved KB / related text is untrusted; strip action-command language from claims.
_PROHIBITED_ACTION_RE = re.compile(
    r"\b(isolate|block|shutdown|firewall|exploit|credential|sudo|rm -rf)\b",
    re.IGNORECASE,
)


@dataclass
class ToolResult:
    tool: str
    ok: bool
    source_ids: list[str]
    payload: dict[str, Any]
    error: str | None = None


def sanitize_untrusted_claim_text(text: str, *, source_id: str) -> str:
    """Treat retrieved document text as untrusted data (PRD SR-5)."""
    if not text or not str(text).strip():
        return f"Retrieved {source_id}"
    cleaned = str(text).strip()
    if _PROHIBITED_ACTION_RE.search(cleaned):
        return f"Retrieved {source_id}; claim text omitted (untrusted action language)."
    return cleaned


class ReadOnlyToolBelt:
    """Allowlisted, read-only retrieval tools. No writes, no dynamic tool creation."""

    def __init__(self, kb: KnowledgeBase, related_events_provider: Callable[..., list[dict[str, Any]]]):
        self.kb = kb
        self._related_events_provider = related_events_provider

    def call(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        if tool_name not in ALLOWED_TOOLS:
            return ToolResult(tool_name, False, [], {}, error=f"tool not allowlisted: {tool_name}")
        handler = getattr(self, tool_name)
        try:
            return handler(**arguments)
        except TypeError as exc:
            return ToolResult(tool_name, False, [], {}, error=f"invalid arguments: {exc}")
        except Exception as exc:  # noqa: BLE001 - convert to tool error, never raise into agent loop
            return ToolResult(tool_name, False, [], {}, error=str(exc))

    def get_asset_profile(self, device_type: str) -> ToolResult:
        docs = self.kb.documents["asset"]
        match = next((doc for doc in docs if doc.get("device_type") == device_type), None)
        if match is None:
            match = next((doc for doc in docs if doc.get("device_type") == "medical_aiot"), None)
        if match is None:
            return ToolResult("get_asset_profile", False, [], {}, error="asset profile not found")
        return ToolResult("get_asset_profile", True, [match["source_id"]], {"document": match})

    def get_behavior_baseline(self, device_type: str, operating_state: str = "unknown") -> ToolResult:
        docs = self.kb.documents["behavior"]
        match = next(
            (
                doc for doc in docs
                if doc.get("device_type") == device_type and doc.get("operating_state") == operating_state
            ),
            None,
        )
        if match is None:
            match = next((doc for doc in docs if doc.get("device_type") == device_type), None)
        if match is None:
            return ToolResult("get_behavior_baseline", False, [], {}, error="behavior baseline not found")
        return ToolResult("get_behavior_baseline", True, [match["source_id"]], {"document": match})

    def search_threat_knowledge(self, query: str) -> ToolResult:
        needle = query.casefold()
        hits = []
        for doc in self.kb.documents["threat"]:
            aliases = " ".join(doc.get("aliases", [])).casefold()
            blob = f"{doc.get('title', '')} {doc.get('summary', '')} {aliases}".casefold()
            if needle in blob or any(token and token in blob for token in needle.replace("-", " ").split()):
                hits.append(doc)
        if not hits:
            # Safe generic fallback document, still sourced.
            generic = self.kb.get_by_id("threat:network-anomaly")
            hits = [generic] if generic else []
        if not hits:
            return ToolResult("search_threat_knowledge", False, [], {}, error="no threat documents")
        return ToolResult(
            "search_threat_knowledge",
            True,
            [doc["source_id"] for doc in hits[:3]],
            {"documents": hits[:3]},
        )

    def search_playbook(self, verdict: str = "anomalous", taxonomy: str = "unknown") -> ToolResult:
        docs = self.kb.documents["playbook"]
        keys = {verdict.casefold(), taxonomy.casefold()}
        hits = [
            doc for doc in docs
            if keys.intersection({str(item).casefold() for item in doc.get("applies_to", [])})
        ]
        if not hits:
            hits = [doc for doc in docs if "verify-device-state" in doc.get("source_id", "")]
        if not hits:
            return ToolResult("search_playbook", False, [], {}, error="no playbook documents")
        return ToolResult(
            "search_playbook",
            True,
            [doc["source_id"] for doc in hits[:2]],
            {"documents": hits[:2]},
        )

    def get_related_events(self, device_id: str, limit: int = 5) -> ToolResult:
        events = self._related_events_provider(device_id=device_id, limit=limit)
        rows: list[dict[str, Any]] = []
        source_ids: list[str] = []
        for item in events:
            event_id = item.get("event_id")
            if not event_id:
                continue
            assessment = item.get("assessment") or {}
            source_id = f"evidence-event:{event_id}"
            source_ids.append(source_id)
            rows.append(
                {
                    "event_id": event_id,
                    "source_id": source_id,
                    "timestamp": item.get("timestamp"),
                    "verdict": assessment.get("verdict"),
                    "severity": assessment.get("severity"),
                    "taxonomy": assessment.get("taxonomy"),
                    "device_id": (item.get("asset") or {}).get("device_id") or device_id,
                }
            )
        return ToolResult(
            "get_related_events",
            True,
            source_ids,
            {"events": rows},
        )
