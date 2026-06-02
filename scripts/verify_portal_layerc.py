#!/usr/bin/env python3
"""
S5-E1: Verify 108 Portal OT events expose Layer C card fields (not raw JSON only).

Requires SMB user JWT (M2M ingest key cannot call /ot-security/*).

Usage:
  export PORTAL_BEARER_TOKEN='...'
  export WORKSPACE_ID=6
  python3 scripts/verify_portal_layerc.py

  # Or login:
  python3 scripts/verify_portal_layerc.py --email user@example.com --password '...'

  # Export samples for LLM eval (S5-E2):
  python3 scripts/verify_portal_layerc.py --export-json docs/llm-eval-samples.jsonl --limit 10
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any


def _request(
    *,
    base_url: str,
    path: str,
    token: str,
    workspace_id: int,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> Any:
    url = base_url.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Workspace-Id": str(workspace_id),
        "Accept": "application/json",
        "Accept-Language": "zh-TW",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def login(base_url: str, email: str, password: str) -> str:
    url = base_url.rstrip("/") + "/api/v1/smb/auth/login"
    req = urllib.request.Request(
        url,
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json", "Accept-Language": "zh-TW"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode())
    token = (payload.get("access_token") or "").strip()
    if not token:
        raise RuntimeError("login succeeded but access_token missing")
    return token


def validate_layerc_summary(summary: dict[str, Any] | None, *, expect_llm: bool) -> list[str]:
    """Return list of validation errors (empty = OK for Portal card)."""
    errors: list[str] = []
    if not summary or not isinstance(summary, dict):
        return ["layerc_summary missing or not an object"]

    summary_zh = str(summary.get("summary_zh") or "").strip()
    if len(summary_zh) < 8:
        errors.append("summary_zh missing or too short (<8 chars)")

    severity = str(summary.get("severity") or "").strip().lower()
    if severity not in ("low", "medium", "high", "critical"):
        errors.append(f"severity invalid: {severity!r}")

    if expect_llm:
        if summary.get("llm_enriched") is not True:
            errors.append(f"expected llm_enriched=true got {summary.get('llm_enriched')!r}")
        actions = summary.get("recommended_actions")
        if not isinstance(actions, list) or len(actions) == 0:
            errors.append("recommended_actions empty (LLM enrich expected)")
        elif not str((actions[0] or {}).get("action_zh") or "").strip():
            errors.append("recommended_actions[0].action_zh empty")

    # Portal card must have human-readable fields, not only nested raw blob
    if not summary_zh and not summary.get("severity_rationale_zh"):
        errors.append("no human-readable Layer C text fields")

    return errors


def pick_candidate_events(items: list[dict[str, Any]], *, prefer_layer: str | None) -> list[dict[str, Any]]:
    if not items:
        return []
    layer_first = [e for e in items if prefer_layer and e.get("layer") == prefer_layer]
    with_episode = [e for e in items if e.get("episode_id")]
    pool = layer_first or with_episode or items
    return pool


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Portal Layer C card data on live OT events")
    parser.add_argument("--portal-url", default="http://192.168.1.108:8081")
    parser.add_argument("--workspace-id", type=int, default=0)
    parser.add_argument("--token", default="")
    parser.add_argument("--email", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--hours", type=int, default=168)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--expect-llm", action="store_true")
    parser.add_argument("--min-pass", type=int, default=1, help="Minimum events that must pass validation")
    parser.add_argument("--episode-id", default="", help="Verify a specific episode_id if present")
    parser.add_argument("--export-json", default="", help="Write up to --limit event details for LLM eval")
    parser.add_argument("--skip-health", action="store_true")
    args = parser.parse_args()

    import os

    portal_url = args.portal_url or os.environ.get("SENSEL_API_URL", "http://192.168.1.108:8081")
    workspace_id = args.workspace_id or int(os.environ.get("WORKSPACE_ID", "6"))
    token = (args.token or os.environ.get("PORTAL_BEARER_TOKEN") or "").strip()
    email = (args.email or os.environ.get("PORTAL_EMAIL") or "").strip()
    password = args.password or os.environ.get("PORTAL_PASSWORD") or ""

    if not args.skip_health:
        health_url = portal_url.rstrip("/") + "/api/health"
        try:
            with urllib.request.urlopen(health_url, timeout=10) as resp:
                if resp.status != 200:
                    print(f"FAIL: health HTTP {resp.status}", file=sys.stderr)
                    return 1
        except urllib.error.URLError as exc:
            print(f"FAIL: Portal health unreachable: {exc}", file=sys.stderr)
            return 1
        print(f"OK health {health_url}")

    if not token:
        if email and password:
            token = login(portal_url, email, password)
            print(f"OK login as {email}")
        else:
            print(
                "FAIL: set PORTAL_BEARER_TOKEN or --token, or PORTAL_EMAIL + PORTAL_PASSWORD",
                file=sys.stderr,
            )
            return 1

    list_path = (
        f"/api/v1/smb/workspaces/{workspace_id}/ot-security/events"
        f"?hours={args.hours}&limit={args.limit}"
    )
    try:
        listed = _request(
            base_url=portal_url,
            path=list_path,
            token=token,
            workspace_id=workspace_id,
        )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        print(f"FAIL: list events HTTP {exc.code}: {body}", file=sys.stderr)
        return 1

    items = listed.get("items") or []
    total = int(listed.get("total") or 0)
    print(f"OK listed {len(items)} events (total={total}, workspace={workspace_id})")

    if args.episode_id:
        items = [e for e in items if e.get("episode_id") == args.episode_id]
        if not items:
            print(f"FAIL: episode_id {args.episode_id!r} not found in recent events", file=sys.stderr)
            return 1

    candidates = pick_candidate_events(items, prefer_layer="layer_c")
    if not candidates:
        print("FAIL: no OT events in lookback window", file=sys.stderr)
        return 1

    passed = 0
    checked = 0
    export_rows: list[dict[str, Any]] = []
    failures: list[str] = []

    for ev in candidates[: args.limit]:
        event_id = ev.get("id")
        if not event_id:
            continue
        detail_path = f"/api/v1/smb/workspaces/{workspace_id}/ot-security/events/{event_id}"
        try:
            detail = _request(
                base_url=portal_url,
                path=detail_path,
                token=token,
                workspace_id=workspace_id,
            )
        except urllib.error.HTTPError as exc:
            failures.append(f"{event_id}: detail HTTP {exc.code}")
            continue

        checked += 1
        layerc = detail.get("layerc_summary")
        errors = validate_layerc_summary(layerc, expect_llm=args.expect_llm)
        ep = detail.get("episode_id") or ev.get("episode_id")
        rule = detail.get("rule_id") or ev.get("rule_id")
        llm = (layerc or {}).get("llm_enriched") if isinstance(layerc, dict) else None

        if errors:
            failures.append(f"event={event_id} episode={ep} rule={rule}: {'; '.join(errors)}")
        else:
            passed += 1
            print(
                f"PASS event={event_id} episode={ep} rule={rule} "
                f"llm_enriched={llm} summary_len={len(str((layerc or {}).get('summary_zh') or ''))}"
            )

        if args.export_json:
            export_rows.append(
                {
                    "event_id": event_id,
                    "episode_id": ep,
                    "rule_id": rule,
                    "severity": detail.get("severity"),
                    "detected_at": detail.get("detected_at"),
                    "layerc_summary": layerc,
                }
            )

    if args.export_json:
        out_path = args.export_json
        with open(out_path, "w", encoding="utf-8") as f:
            for row in export_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"OK exported {len(export_rows)} rows -> {out_path}")

    summary = {
        "ok": passed >= args.min_pass,
        "checked": checked,
        "passed": passed,
        "min_pass": args.min_pass,
        "expect_llm": args.expect_llm,
        "workspace_id": workspace_id,
        "failures": failures[:5],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if passed < args.min_pass:
        print(f"FAIL: {passed}/{args.min_pass} events passed Layer C card validation", file=sys.stderr)
        for msg in failures[:5]:
            print(f"  - {msg}", file=sys.stderr)
        return 1

    print("PORTAL LAYER C VERIFY PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
