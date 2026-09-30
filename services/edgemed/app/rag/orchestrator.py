from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..schema import assert_detector_fields_unchanged, detector_owned_snapshot
from .kb import KnowledgeBase
from .tools import ALLOWED_TOOLS, ReadOnlyToolBelt, ToolResult, sanitize_untrusted_claim_text


# Fixed investigation graph. SLM intents may only suggest subsets; they never add tools.
INVESTIGATION_STEPS: tuple[tuple[str, str], ...] = (
    ("asset_context", "get_asset_profile"),
    ("behavior_baseline", "get_behavior_baseline"),
    ("threat_context", "search_threat_knowledge"),
    ("related_events", "get_related_events"),
    ("playbook_lookup", "search_playbook"),
)

INTENT_TO_TOOL = {intent: tool for intent, tool in INVESTIGATION_STEPS}

TOOL_CLAIM_TYPE = {
    "get_asset_profile": "asset",
    "get_behavior_baseline": "behavior",
    "search_threat_knowledge": "threat",
    "search_playbook": "playbook",
    "get_related_events": "related_event",
}

# SLM/formatter taxonomies that are poor threat-KB queries; prefer detector category.
_NON_THREAT_QUERY_LABELS = {
    "detector_conflict",
    "insufficient_evidence",
    "unknown",
    "baseline_traffic",
    "network_behavior_anomaly",
    "known_attack_suspected",
}


@dataclass
class AuditEvent:
    step: int
    tool: str
    ok: bool
    source_ids: list[str]
    error: str | None = None
    elapsed_ms: float = 0.0


@dataclass
class RagResult:
    status: str
    sources: list[dict[str, str]]
    claims: list[dict[str, Any]]
    audit: list[AuditEvent] = field(default_factory=list)
    retrieval_count: int = 0


class DeterministicOrchestrator:
    """Allowlisted state machine with max 5 read-only retrievals."""

    def __init__(
        self,
        tools: ReadOnlyToolBelt,
        kb: KnowledgeBase,
        *,
        max_retrieval_steps: int = 5,
        tool_timeout_sec: float = 2.0,
    ):
        self.tools = tools
        self.kb = kb
        self.max_retrieval_steps = max_retrieval_steps
        self.tool_timeout_sec = tool_timeout_sec

    def investigate(self, event: dict[str, Any]) -> RagResult:
        suggested = set((event.get("enrichment") or {}).get("retrieval_intents") or [])
        # Intents are suggestions only. Unknown names are ignored; SLM cannot add tools.
        suggested = {intent for intent in suggested if intent in INTENT_TO_TOOL or intent == "none"}
        verdict = (event.get("assessment") or {}).get("verdict", "baseline")

        if verdict == "baseline":
            ordered_tools = ["get_asset_profile"]
            if "playbook_lookup" in suggested:
                ordered_tools.append("search_playbook")
        else:
            # Fixed investigation graph for non-baseline events.
            ordered_tools = [tool for _, tool in INVESTIGATION_STEPS]
            # Optional priority boost: move suggested tools earlier, still within allowlist.
            if suggested and "none" not in suggested:
                boosted = [INTENT_TO_TOOL[intent] for intent in INVESTIGATION_STEPS if intent in suggested]
                rest = [tool for tool in ordered_tools if tool not in boosted]
                ordered_tools = boosted + rest

        ordered_tools = ordered_tools[: self.max_retrieval_steps]

        audit: list[AuditEvent] = []
        sources: list[dict[str, str]] = []
        claims: list[dict[str, Any]] = []
        seen_source_ids: set[str] = set()

        for index, tool_name in enumerate(ordered_tools, start=1):
            started = time.perf_counter()
            arguments = self._arguments_for(tool_name, event)
            result = self._call_with_timeout(tool_name, arguments)
            elapsed_ms = (time.perf_counter() - started) * 1000
            audit.append(AuditEvent(
                step=index,
                tool=tool_name,
                ok=result.ok,
                source_ids=result.source_ids,
                error=result.error,
                elapsed_ms=elapsed_ms,
            ))
            if not result.ok:
                continue
            for source_id in result.source_ids:
                if source_id in seen_source_ids:
                    continue
                # Related events use evidence-event IDs outside KB; accept either.
                if source_id.startswith("evidence-event:") or source_id in self.kb.all_source_ids():
                    seen_source_ids.add(source_id)
                    source_type = source_id.split(":", 1)[0]
                    sources.append({"source_id": source_id, "source_type": source_type})
                    claims.append(self._claim_from_result(tool_name, source_id, result))

        status = "available" if sources and claims else "enrichment_unavailable"
        # Drop unsourced claims.
        sourced_claims = [claim for claim in claims if claim.get("source_id") in seen_source_ids]
        if not sourced_claims:
            status = "enrichment_unavailable"
        return RagResult(
            status=status,
            sources=sources,
            claims=sourced_claims,
            audit=audit,
            retrieval_count=len(audit),
        )

    def apply(self, event: dict[str, Any]) -> dict[str, Any]:
        before = detector_owned_snapshot(event)
        result = self.investigate(event)
        # Keep SLM generation_status intact; RAG status lives only under enrichment.
        updated = {
            **event,
            "enrichment": {
                **(event.get("enrichment") or {}),
                "status": result.status,
                "sources": result.sources,
                "claims": result.claims,
                "audit": [
                    {
                        "step": item.step,
                        "tool": item.tool,
                        "ok": item.ok,
                        "source_ids": item.source_ids,
                        "error": item.error,
                        "elapsed_ms": round(item.elapsed_ms, 3),
                    }
                    for item in result.audit
                ],
                "retrieval_count": result.retrieval_count,
            },
        }
        assert_detector_fields_unchanged(
            {"detection": before["detection"], "evidence": before["evidence"]},
            updated,
        )
        return updated

    def _arguments_for(self, tool_name: str, event: dict[str, Any]) -> dict[str, Any]:
        asset = event.get("asset") or {}
        assessment = event.get("assessment") or {}
        detection = event.get("detection") or {}
        if tool_name == "get_asset_profile":
            return {"device_type": asset.get("device_type", "medical_aiot")}
        if tool_name == "get_behavior_baseline":
            return {
                "device_type": asset.get("device_type", "medical_aiot"),
                "operating_state": asset.get("operating_state", "unknown"),
            }
        if tool_name == "search_threat_knowledge":
            return {"query": self._threat_query(event)}
        if tool_name == "search_playbook":
            return {
                "verdict": assessment.get("verdict", "anomalous"),
                "taxonomy": assessment.get("taxonomy", "unknown"),
            }
        if tool_name == "get_related_events":
            return {"device_id": asset.get("device_id", "unknown-device"), "limit": 5}
        raise ValueError(f"no argument mapper for {tool_name}")

    @staticmethod
    def _threat_query(event: dict[str, Any]) -> str:
        """Prefer detector-owned known_attack.category over SLM taxonomy labels."""
        detection = event.get("detection") or {}
        assessment = event.get("assessment") or {}
        known = detection.get("known_attack") or {}
        category = str(known.get("category") or "").strip()
        taxonomy = str(assessment.get("taxonomy") or "").strip()

        parts: list[str] = []
        if category and category.casefold() not in {"benign", "attack", "unknown"}:
            parts.append(category)
        if taxonomy and taxonomy.casefold() not in _NON_THREAT_QUERY_LABELS:
            if taxonomy.casefold() not in {p.casefold() for p in parts}:
                parts.append(taxonomy)
        if not parts:
            # Fall back to generic anomaly KB doc rather than conflict labels.
            parts.append("anomaly")
        return " ".join(parts)

    def _call_with_timeout(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        # Tools are local/deterministic; enforce a soft timeout budget marker.
        started = time.perf_counter()
        result = self.tools.call(tool_name, arguments)
        if (time.perf_counter() - started) > self.tool_timeout_sec:
            return ToolResult(tool_name, False, [], {}, error="tool_timeout")
        return result

    def _claim_from_result(self, tool_name: str, source_id: str, result: ToolResult) -> dict[str, Any]:
        claim_type = TOOL_CLAIM_TYPE.get(tool_name, "other")
        document = None
        if "document" in result.payload:
            document = result.payload["document"]
        elif "documents" in result.payload and result.payload["documents"]:
            document = next(
                (doc for doc in result.payload["documents"] if doc.get("source_id") == source_id),
                result.payload["documents"][0],
            )

        if tool_name == "get_related_events":
            row = next(
                (
                    item
                    for item in (result.payload.get("events") or [])
                    if item.get("source_id") == source_id or f"evidence-event:{item.get('event_id')}" == source_id
                ),
                None,
            ) or {}
            event_id = row.get("event_id") or source_id.split(":", 1)[-1]
            bits = [f"Related historical event {event_id}"]
            if row.get("timestamp"):
                bits.append(f"at {row['timestamp']}")
            if row.get("verdict"):
                bits.append(f"verdict={row['verdict']}")
            if row.get("severity"):
                bits.append(f"severity={row['severity']}")
            if row.get("taxonomy"):
                bits.append(f"taxonomy={row['taxonomy']}")
            summary = "; ".join(bits) + "."
            claim = {
                "claim": sanitize_untrusted_claim_text(summary, source_id=source_id),
                "source_id": source_id,
                "tool": tool_name,
                "claim_type": claim_type,
                "event_id": event_id,
                "timestamp": row.get("timestamp"),
                "verdict": row.get("verdict"),
                "severity": row.get("severity"),
                "taxonomy": row.get("taxonomy"),
            }
            return claim

        summary = None
        if isinstance(document, dict):
            summary = (
                document.get("notes")
                or document.get("baseline_summary")
                or document.get("summary")
                or document.get("title")
            )
            if tool_name == "search_playbook" and document.get("steps"):
                steps = document.get("steps") or []
                if isinstance(steps, list) and steps:
                    summary = f"{document.get('title') or 'Playbook'}: " + "; ".join(str(s) for s in steps[:3])

        claim: dict[str, Any] = {
            "claim": sanitize_untrusted_claim_text(
                summary or f"Retrieved {tool_name}",
                source_id=source_id,
            ),
            "source_id": source_id,
            "tool": tool_name,
            "claim_type": claim_type,
        }
        if tool_name == "search_playbook" and isinstance(document, dict) and document.get("steps"):
            claim["steps"] = list(document.get("steps") or [])[:5]
        return claim


def build_default_orchestrator(related_events_provider) -> DeterministicOrchestrator:
    kb = KnowledgeBase()
    tools = ReadOnlyToolBelt(kb, related_events_provider=related_events_provider)
    return DeterministicOrchestrator(tools, kb, max_retrieval_steps=5)
