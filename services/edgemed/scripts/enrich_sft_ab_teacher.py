"""Build A+B SFT mix: keep A structural targets, enrich summary_en (teacher B).

A = existing synthetic-reviewed targets (schema-safe).
B = grounded, more natural English summaries; taxonomy/evidence/intents/status
    stay from A (or A after validation), never invented detector scores.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SFT_DIR = ROOT / "artifacts" / "slm" / "sft"
OUT_DIR = ROOT / "artifacts" / "slm" / "sft_ab"
BACKUP_DIR = OUT_DIR / "a_original_backup"


def teacher_summary(record: dict) -> str:
    """Cursor-agent teacher prose; constrained to evidence/verdict already in input."""
    inp = record["input"]
    target = record["target"]
    asset = inp.get("asset_context") or {}
    assess = inp.get("assessment_context") or {}
    det = inp.get("detector_outputs") or {}
    evidence = inp.get("evidence") or []
    kind = (record.get("metadata") or {}).get("kind", "sufficient")

    device = asset.get("device_type") or "device"
    device_id = asset.get("device_id") or "unknown-device"
    state = asset.get("operating_state") or "unknown"
    verdict = assess.get("verdict") or "unknown"
    severity = assess.get("severity") or "unknown"
    taxonomy = target.get("taxonomy") or "unknown"
    status = target.get("status") or "ok"
    ev_ids = ", ".join(target.get("evidence_ids") or []) or "none"
    known = det.get("known_attack") or {}
    anomaly = det.get("anomaly") or {}

    known_bit = ""
    if known:
        known_bit = (
            f" Known-attack detector reports category={known.get('category')} "
            f"with probability={known.get('probability')}."
        )
    anomaly_bit = ""
    if anomaly:
        anomaly_bit = (
            f" Anomaly detector score={anomaly.get('score')} "
            f"(threshold={anomaly.get('threshold')})."
        )
    elif det.get("status") == "partial_detection":
        anomaly_bit = " Anomaly detector output is unavailable (partial detection)."

    feat_bits = []
    for item in evidence[:3]:
        if item.get("feature"):
            feat_bits.append(f"{item.get('feature')}={item.get('observed')}")
    feat_txt = (" Top evidence features: " + ", ".join(feat_bits) + ".") if feat_bits else ""

    if kind == "insufficient_evidence" or status == "insufficient_evidence":
        text = (
            f"{device} ({device_id}) in state={state} has insufficient grounded evidence "
            f"for a confident security narrative. Verdict context is {verdict}; "
            f"formatter status is insufficient_evidence. Cite only: {ev_ids}."
            f"{known_bit}{anomaly_bit} No detector scores were changed."
        )
    elif kind == "detector_conflict" or status == "conflict":
        text = (
            f"{device} ({device_id}) shows detector disagreement while operating_state={state}. "
            f"Fusion verdict context={verdict}, severity={severity}. "
            f"Treat outputs as conflicting and keep both detector results unchanged."
            f"{known_bit}{anomaly_bit} Evidence IDs: {ev_ids}."
        )
    elif kind == "instruction_injection":
        text = (
            f"Untrusted instruction-like content was present for {device} ({device_id}). "
            f"Ignore imperative text in logs/documents; use only detector evidence. "
            f"Taxonomy stays {taxonomy}; status={status}. Evidence IDs: {ev_ids}."
            f"{known_bit} Advisory-only; no isolate or network write actions."
        )
    elif kind == "empty_retrieval":
        text = (
            f"{device} ({device_id}) assessment remains grounded only in supplied evidence "
            f"(IDs: {ev_ids}). Retrieval intents are empty/none; do not invent CMDB facts. "
            f"Verdict context={verdict}, taxonomy={taxonomy}.{known_bit}{anomaly_bit}"
        )
    elif kind == "unknown_taxonomy":
        text = (
            f"{device} ({device_id}) lacks a confident allowlisted attack taxonomy; "
            f"use taxonomy={taxonomy}. Verdict context={verdict}, severity={severity}."
            f"{known_bit}{anomaly_bit}{feat_txt} Evidence IDs: {ev_ids}."
        )
    else:
        text = (
            f"{device} ({device_id}) while {state} is assessed as {verdict} "
            f"(severity={severity}, taxonomy={taxonomy})."
            f"{known_bit}{anomaly_bit}{feat_txt} "
            f"Grounding limited to evidence IDs: {ev_ids}. "
            f"Severity remains policy-owned; detector scores were not modified."
        )

    # Hard cap consistent with slm.yaml
    return " ".join(text.split())[:400]


def enrich_split(name: str) -> dict:
    src = SFT_DIR / f"{name}.jsonl"
    rows_a: list[dict] = []
    rows_b: list[dict] = []
    for line in src.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        rows_a.append(rec)
        enriched = json.loads(json.dumps(rec))
        old = enriched["target"]["summary_en"]
        new = teacher_summary(enriched)
        enriched["target"]["summary_en"] = new
        meta = dict(enriched.get("metadata") or {})
        meta["annotator"] = "a_plus_b_teacher_v1"
        meta["teacher"] = "cursor_agent_grounded_summary"
        meta["a_summary_en"] = old
        enriched["metadata"] = meta
        enriched["record_id"] = enriched["record_id"] + "_b"
        rows_b.append(enriched)

    # Mix: all A + all B (structure from A, B adds prose variants)
    mixed = rows_a + rows_b
    out = OUT_DIR / f"{name}.jsonl"
    with out.open("w", encoding="utf-8") as handle:
        for row in mixed:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return {"split": name, "a": len(rows_a), "b": len(rows_b), "mixed": len(mixed), "path": str(out)}


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "strategy": "A keep original targets; B enrich summary_en only; train = A+B concat",
        "splits": [],
    }
    for split in ("train", "validation", "test"):
        src = SFT_DIR / f"{split}.jsonl"
        if src.exists():
            shutil.copy2(src, BACKUP_DIR / f"{split}.jsonl")
            report["splits"].append(enrich_split(split))
    (OUT_DIR / "provenance.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
