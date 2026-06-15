#!/usr/bin/env python3
"""
P4: Baseline Live Learning lab acceptance (PRD §13).

Static + post-flow checks against Portal BFF, Edge Console, CTA coverage API.

Usage:
  cp .env.lab.example .env.lab   # PORTAL_EMAIL / PORTAL_PASSWORD / WORKSPACE_ID
  export TENANT_ID=company-a9ae1234648ee138
  python3 scripts/verify_baseline_live_learning_lab.py

  # After manual listen → learning → detect flow:
  python3 scripts/verify_baseline_live_learning_lab.py \\
    --expect-mode detect \\
    --expect-profile-id <uuid> \\
    --expect-event-metadata

  # Probe 409 duplicate session (requires manage permission):
  python3 scripts/verify_baseline_live_learning_lab.py --probe-409 --sensor-id ot-edge-001

  # CTA: save baseline snapshot during listen, compare after (detect must not grow in listen):
  python3 scripts/verify_baseline_live_learning_lab.py --cta-snapshot /tmp/cta-before.json
  python3 scripts/verify_baseline_live_learning_lab.py --cta-compare /tmp/cta-before.json --max-detect-delta 0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _request(
    *,
    base: str,
    path: str,
    token: str,
    workspace_id: int,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> Any:
    url = base.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Workspace-Id": str(workspace_id),
        "Accept": "application/json",
        "Accept-Language": "zh-TW",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


def _plain_get(url: str, timeout: float = 12.0) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def login(base: str, email: str, password: str) -> str:
    url = base.rstrip("/") + "/api/v1/smb/auth/login"
    req = urllib.request.Request(
        url,
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json", "Accept-Language": "zh-TW"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode())
    token = str(payload.get("access_token") or "").strip()
    if not token:
        raise RuntimeError("login missing access_token")
    return token


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []

    def ok(self, msg: str) -> None:
        print(f"OK  {msg}")

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        print(f"WARN {msg}", file=sys.stderr)

    def fail(self, msg: str) -> None:
        self.failures.append(msg)
        print(f"FAIL {msg}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Baseline Live Learning lab verify (P4)")
    parser.add_argument("--base-url", default=_env("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081"))
    parser.add_argument("--layerc-url", default=_env("LAYERC_URL", "http://192.168.1.203:8001"))
    parser.add_argument("--edge-console-url", default=_env("EDGE_CONSOLE_URL", "http://192.168.1.124:8090"))
    parser.add_argument("--workspace-id", type=int, default=int(_env("WORKSPACE_ID", "6") or "6"))
    parser.add_argument("--tenant-id", default=_env("TENANT_ID", "company-a9ae1234648ee138"))
    parser.add_argument("--sensor-id", default=_env("BASELINE_SENSOR_ID", ""))
    parser.add_argument("--token", default=_env("PORTAL_BEARER_TOKEN", ""))
    parser.add_argument("--email", default=_env("PORTAL_EMAIL", ""))
    parser.add_argument("--password", default=_env("PORTAL_PASSWORD", ""))
    parser.add_argument("--expect-mode", choices=["listen", "learning", "detect", "idle"], default="")
    parser.add_argument("--expect-profile-id", default="")
    parser.add_argument("--expect-event-metadata", action="store_true")
    parser.add_argument("--probe-409", action="store_true", help="Start observe session twice; expect 409")
    parser.add_argument("--cta-snapshot", default="", help="Write CTA coverage summary JSON to path")
    parser.add_argument("--cta-compare", default="", help="Compare CTA detected delta to snapshot file")
    parser.add_argument("--max-detect-delta", type=int, default=0)
    parser.add_argument("--expect-topology", action="store_true", help="Require topology KPI/assets on dashboard")
    parser.add_argument("--expect-topology-patch", action="store_true", help="PATCH low-confidence topology asset and verify manual_override")
    parser.add_argument(
        "--expect-topology-patch-edge",
        action="store_true",
        help="After PATCH, verify Pi edge-agent topology-asset-overrides.json via SSH",
    )
    parser.add_argument("--edge-ssh-host", default=_env("EDGE_SSH_HOST", "192.168.1.124"))
    parser.add_argument("--edge-ssh-user", default=_env("EDGE_SSH_USER", "edgex"))
    parser.add_argument(
        "--edge-override-path",
        default=_env("EDGE_TOPOLOGY_OVERRIDE_PATH", "/home/edgex/sensel-ot-edge-sensor/data/agent/topology-asset-overrides.json"),
    )
    parser.add_argument("--min-topology-assets", type=int, default=2)
    parser.add_argument("--min-topology-conduits", type=int, default=1)
    parser.add_argument(
        "--expect-topology-views",
        action="store_true",
        help="Require conduits / it-dependencies / external BFF endpoints (§7.3–7.5)",
    )
    parser.add_argument(
        "--expect-topology-snapshot-edge",
        action="store_true",
        help="Verify Pi edge-agent topology-snapshot-state.json via SSH (§6.1)",
    )
    parser.add_argument(
        "--edge-topology-snapshot-state-path",
        default=_env(
            "EDGE_TOPOLOGY_SNAPSHOT_STATE_PATH",
            "/home/edgex/sensel-ot-edge-sensor/data/agent/topology-snapshot-state.json",
        ),
    )
    parser.add_argument("--min-it-nodes", type=int, default=0, help="Min IT nodes in it-dependencies view")
    parser.add_argument("--min-external-entities", type=int, default=0, help="Min external entities in topology/external")
    parser.add_argument(
        "--expect-topology-delta-edge",
        action="store_true",
        help="Verify Pi published detect topology_delta (§6.1 detect mode)",
    )
    parser.add_argument(
        "--expect-edr-match",
        action="store_true",
        help="Seed lab topology asset and verify EDR M1 match + edr-context (PRD §11.2 #6)",
    )
    parser.add_argument(
        "--edr-match-scenario",
        choices=["ubuntu108", "windows-hmi"],
        default=_env("EDR_MATCH_SCENARIO", "windows-hmi"),
        help="EDR lab preset when --expect-edr-match (default windows-hmi ≥0.9)",
    )
    args = parser.parse_args()

    chk = Checker()
    base = args.base_url
    ws = args.workspace_id
    ot = f"/api/v1/smb/workspaces/{ws}/ot-security"

    print(f"==> Baseline Live Learning verify tenant={args.tenant_id} workspace={ws}")

    try:
        _plain_get(f"{base}/api/health")
        chk.ok(f"CP health {base}/api/health")
    except Exception as exc:
        chk.fail(f"CP health: {exc}")

    try:
        _plain_get(f"{args.layerc_url.rstrip('/')}/health")
        chk.ok(f"Layer C health {args.layerc_url}/health")
    except Exception as exc:
        chk.fail(f"Layer C health: {exc}")

    token = args.token
    if not token:
        if args.email and args.password:
            try:
                token = login(base, args.email, args.password)
                chk.ok("Portal login")
            except Exception as exc:
                chk.fail(f"Portal login: {exc}")
        else:
            chk.warn("No PORTAL_BEARER_TOKEN / PORTAL_EMAIL — skipping Portal BFF checks")

    sensor_id = args.sensor_id
    if token:
        try:
            sensors = _request(base=base, path=f"{ot}/sensors", token=token, workspace_id=ws)
            items = sensors.get("items") if isinstance(sensors, dict) else []
            if not isinstance(items, list):
                items = []
            chk.ok(f"GET ot-security/sensors ({len(items)} rows)")
            if not sensor_id and items:
                sensor_id = str(items[0].get("sensor_id") or "").strip()
        except Exception as exc:
            chk.fail(f"GET sensors: {exc}")

        for path_suffix, label in (
            ("/sessions", "sessions"),
            ("/baseline-profiles", "baseline-profiles"),
        ):
            try:
                _request(base=base, path=f"{ot}{path_suffix}", token=token, workspace_id=ws)
                chk.ok(f"GET ot-security/{label}")
            except Exception as exc:
                chk.fail(f"GET {label}: {exc}")

        if sensor_id:
            try:
                state = _request(
                    base=base,
                    path=f"{ot}/sensors/{urllib.parse.quote(sensor_id)}/operational-state",
                    token=token,
                    workspace_id=ws,
                )
                mode = str(state.get("mode") or "")
                chk.ok(f"operational-state sensor={sensor_id} mode={mode or '?'}")
                if args.expect_mode and mode != args.expect_mode:
                    chk.fail(f"expected mode={args.expect_mode} got {mode!r}")
                if args.expect_profile_id:
                    got = str(state.get("baseline_profile_id") or "")
                    if got != args.expect_profile_id:
                        chk.fail(f"expected profile_id={args.expect_profile_id} got {got!r}")
            except Exception as exc:
                chk.fail(f"operational-state: {exc}")

        if args.probe_409 and sensor_id:
            start_path = f"{ot}/sensors/{urllib.parse.quote(sensor_id)}/observe-sessions"
            body = {"capture_interface": "eth0", "min_ticks_required": 5}
            try:
                _request(base=base, path=start_path, token=token, workspace_id=ws, method="POST", body=body)
                chk.ok("POST observe-sessions (first)")
            except Exception as exc:
                chk.warn(f"first observe-sessions: {exc} (may already have active session)")
            try:
                _request(base=base, path=start_path, token=token, workspace_id=ws, method="POST", body=body)
                chk.fail("second observe-sessions should return 409")
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    chk.ok("POST observe-sessions duplicate → 409")
                else:
                    chk.fail(f"duplicate observe expected 409 got {exc.code}")
            except Exception as exc:
                chk.fail(f"duplicate observe probe: {exc}")

        if args.expect_event_metadata:
            try:
                events = _request(base=base, path=f"{ot}/events?limit=20", token=token, workspace_id=ws)
                items = events.get("items") if isinstance(events, dict) else []
                found = False
                for ev in items or []:
                    if not isinstance(ev, dict):
                        continue
                    bp = ev.get("baseline_profile_id")
                    if not bp:
                        raw = ev.get("raw_event") if isinstance(ev.get("raw_event"), dict) else {}
                        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
                        episode = payload.get("episode") if isinstance(payload.get("episode"), dict) else {}
                        ctx = episode.get("context") if isinstance(episode.get("context"), dict) else {}
                        bp = ctx.get("baseline_profile_id") or raw.get("baseline_profile_id")
                    if not bp and ev.get("id"):
                        try:
                            detail = _request(
                                base=base,
                                path=f"{ot}/events/{urllib.parse.quote(str(ev.get('id')))}",
                                token=token,
                                workspace_id=ws,
                            )
                            raw = detail.get("raw_payload") if isinstance(detail.get("raw_payload"), dict) else {}
                            payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
                            episode = payload.get("episode") if isinstance(payload.get("episode"), dict) else {}
                            ctx = episode.get("context") if isinstance(episode.get("context"), dict) else {}
                            bp = ctx.get("baseline_profile_id") or raw.get("baseline_profile_id")
                        except Exception:
                            pass
                    if bp:
                        found = True
                        chk.ok(f"event metadata baseline_profile_id={bp}")
                        break
                if not found:
                    chk.warn("no recent event with baseline_profile_id (trigger detect rule first)")
            except Exception as exc:
                chk.fail(f"events metadata check: {exc}")

        try:
            dash = _request(base=base, path=f"{ot}/dashboard", token=token, workspace_id=ws)
            zone_counts = dash.get("zone_asset_counts") if isinstance(dash, dict) else []
            topology_kpi = dash.get("topology_kpi") if isinstance(dash, dict) else {}
            asset_sum = sum(
                int(z.get("asset_count") or 0)
                for z in (zone_counts or [])
                if isinstance(z, dict)
            )
            kpi_assets = int((topology_kpi or {}).get("edr_matched_assets") or 0) + int(
                (topology_kpi or {}).get("ot_assets_without_edr") or 0
            )
            chk.ok(
                f"dashboard topology_kpi zones={len(zone_counts or [])} "
                f"asset_sum={asset_sum} kpi_nodes={kpi_assets}"
            )
            if args.expect_topology:
                if asset_sum < args.min_topology_assets:
                    chk.fail(
                        f"zone_asset_counts sum {asset_sum} < min {args.min_topology_assets}"
                    )
                unknown = int((topology_kpi or {}).get("unknown_purdue_assets") or 0)
                chk.ok(
                    f"topology_kpi unknown_purdue={unknown} "
                    f"edr_matched={(topology_kpi or {}).get('edr_matched_assets')}"
                )

            graph = _request(
                base=base,
                path=(
                    f"{ot}/topology?sensor_id={urllib.parse.quote(sensor_id)}"
                    if sensor_id
                    else f"{ot}/topology"
                ),
                token=token,
                workspace_id=ws,
            )
            nodes = graph.get("nodes") if isinstance(graph, dict) else []
            edges = graph.get("edges") if isinstance(graph, dict) else []
            chk.ok(f"GET ot-security/topology nodes={len(nodes or [])} edges={len(edges or [])}")
            if args.expect_topology:
                if len(nodes or []) < args.min_topology_assets:
                    chk.fail(f"topology nodes {len(nodes or [])} < min {args.min_topology_assets}")
                if len(edges or []) < args.min_topology_conduits:
                    chk.fail(f"topology edges {len(edges or [])} < min {args.min_topology_conduits}")
        except Exception as exc:
            if args.expect_topology:
                chk.fail(f"topology dashboard/graph: {exc}")
            else:
                chk.warn(f"topology dashboard/graph: {exc}")

        if args.expect_topology_patch and sensor_id:
            try:
                low = _request(
                    base=base,
                    path=(
                        f"{ot}/topology/assets?sensor_id={urllib.parse.quote(sensor_id)}"
                        f"&confidence_lt=0.5&limit=5"
                    ),
                    token=token,
                    workspace_id=ws,
                )
                items = low.get("items") if isinstance(low, dict) else []
                if not isinstance(items, list) or not items:
                    all_assets = _request(
                        base=base,
                        path=(
                            f"{ot}/topology/assets?sensor_id={urllib.parse.quote(sensor_id)}"
                            "&limit=20"
                        ),
                        token=token,
                        workspace_id=ws,
                    )
                    all_items = all_assets.get("items") if isinstance(all_assets, dict) else []
                    if isinstance(all_items, list) and all_items:
                        items = sorted(
                            all_items,
                            key=lambda a: float(a.get("confidence") or 1.0),
                        )[:1]
                        chk.warn(
                            "no confidence_lt=0.5 assets; patching lowest-confidence asset for E2E"
                        )
                    else:
                        chk.fail("topology PATCH E2E: no topology assets to patch")
                        items = []

                if items:
                    target = items[0]
                    asset_id = str(target.get("asset_id") or "").strip()
                    if not asset_id:
                        chk.fail("topology PATCH E2E: target asset missing asset_id")
                    else:
                        patch_body = {
                            "purdue_level": "L2",
                            "asset_type": "plc",
                            "criticality": "medium",
                        }
                        patched = _request(
                            base=base,
                            path=f"{ot}/topology/assets/{urllib.parse.quote(asset_id)}",
                            token=token,
                            workspace_id=ws,
                            method="PATCH",
                            body=patch_body,
                        )
                        asset = patched.get("asset") if isinstance(patched, dict) else {}
                        if not isinstance(asset, dict):
                            chk.fail("topology PATCH E2E: missing asset in response")
                        elif not asset.get("manual_override"):
                            chk.fail("topology PATCH E2E: manual_override not true")
                        elif "manual_tag" not in (asset.get("evidence_sources") or []):
                            chk.fail("topology PATCH E2E: evidence_sources missing manual_tag")
                        elif asset.get("purdue_level") != "L2":
                            chk.fail(
                                f"topology PATCH E2E: purdue_level expected L2 got {asset.get('purdue_level')!r}"
                            )
                        else:
                            mqtt_topic = str(patched.get("mqtt_topic") or "")
                            mqtt_err = str(patched.get("mqtt_error") or "")
                            if mqtt_topic:
                                chk.ok(
                                    f"PATCH topology asset={asset_id} manual_override=true mqtt={mqtt_topic}"
                                )
                            elif mqtt_err:
                                chk.warn(
                                    f"PATCH topology asset={asset_id} saved but MQTT failed: {mqtt_err}"
                                )
                            else:
                                chk.ok(
                                    f"PATCH topology asset={asset_id} manual_override=true (no mqtt_topic)"
                                )
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read().decode()
                except Exception:
                    pass
                chk.fail(f"topology PATCH E2E HTTP {exc.code}: {body[:200]}")
            except Exception as exc:
                chk.fail(f"topology PATCH E2E: {exc}")

        if args.expect_topology_patch_edge and args.expect_topology_patch:
            import subprocess

            sshpass = _env("PI_SSHPASS", _env("SSHPASS", "edgex"))
            cmd = [
                "sshpass",
                "-p",
                sshpass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=accept-new",
                f"{args.edge_ssh_user}@{args.edge_ssh_host}",
                f"cat {args.edge_override_path}",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if proc.returncode != 0:
                    chk.fail(f"edge override SSH read failed: {proc.stderr.strip()[:200]}")
                else:
                    edge_doc = json.loads(proc.stdout)
                    overrides = edge_doc.get("overrides") if isinstance(edge_doc, dict) else {}
                    if not isinstance(overrides, dict) or not overrides:
                        chk.fail("edge topology-asset-overrides.json has no overrides")
                    else:
                        sample = next(iter(overrides.values()))
                        if not isinstance(sample, dict) or not sample.get("manual_override"):
                            chk.fail("edge override missing manual_override")
                        elif "manual_tag" not in (sample.get("evidence_sources") or []):
                            chk.fail("edge override missing manual_tag evidence")
                        else:
                            chk.ok(
                                f"edge override store assets={len(overrides)} "
                                f"sample_purdue={(sample.get('patch') or {}).get('purdue_level')}"
                            )
            except Exception as exc:
                chk.fail(f"edge topology override verify: {exc}")

        if args.expect_edr_match and sensor_id:
            from topology_edr_lab_checks import SCENARIOS, run_edr_match_checks

            scenario = SCENARIOS[args.edr_match_scenario]
            ingest_secret = _env("OT_SECURITY_INGEST_SECRET", "sensel-ot-ingest-lab-2026")
            site_id = _env("SITE_ID", "factory-lab-001")
            chk.ok(f"EDR match gate scenario={scenario.name} ip={scenario.target_ip}")
            run_edr_match_checks(
                chk,
                base=base,
                workspace_id=ws,
                tenant_id=args.tenant_id,
                sensor_id=sensor_id,
                site_id=site_id,
                token=token,
                scenario=scenario,
                ingest_secret=ingest_secret,
                api_request=_request,
                expect_edr_context=True,
            )
        elif args.expect_edr_match and not sensor_id:
            chk.fail("--expect-edr-match requires sensor_id (set BASELINE_SENSOR_ID or use Portal sensors)")

        if args.expect_topology_snapshot_edge:
            import subprocess

            sshpass = _env("PI_SSHPASS", _env("SSHPASS", "edgex"))
            cmd = [
                "sshpass",
                "-p",
                sshpass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=accept-new",
                f"{args.edge_ssh_user}@{args.edge_ssh_host}",
                f"cat {args.edge_topology_snapshot_state_path}",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if proc.returncode != 0:
                    chk.fail(f"edge topology snapshot SSH read failed: {proc.stderr.strip()[:200]}")
                else:
                    snap_state = json.loads(proc.stdout)
                    assets = int(snap_state.get("asset_count") or 0)
                    conduits = int(snap_state.get("conduit_count") or 0)
                    mode = str(snap_state.get("operational_mode") or "")
                    if args.expect_topology_delta_edge:
                        if mode != "detect":
                            chk.fail(f"edge topology snapshot expected mode=detect got {mode!r}")
                        delta = snap_state.get("last_topology_delta")
                        if not isinstance(delta, dict):
                            chk.fail("edge topology snapshot missing last_topology_delta")
                        elif not snap_state.get("last_delta_publish_at"):
                            chk.fail("edge topology snapshot missing last_delta_publish_at")
                        else:
                            chk.ok(
                                f"edge topology delta published mode=detect "
                                f"delta={delta} at={snap_state.get('last_delta_publish_at')}"
                            )
                    elif assets < args.min_topology_assets:
                        chk.fail(f"edge topology snapshot asset_count {assets} < min {args.min_topology_assets}")
                    else:
                        chk.ok(
                            f"edge topology snapshot published assets={assets} conduits={conduits} "
                            f"mode={mode or '?'}"
                        )
            except Exception as exc:
                chk.fail(f"edge topology snapshot verify: {exc}")

        if args.expect_topology_delta_edge and not args.expect_topology_snapshot_edge:
            import subprocess

            sshpass = _env("PI_SSHPASS", _env("SSHPASS", "edgex"))
            cmd = [
                "sshpass",
                "-p",
                sshpass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=accept-new",
                f"{args.edge_ssh_user}@{args.edge_ssh_host}",
                f"cat {args.edge_topology_snapshot_state_path}",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if proc.returncode != 0:
                    chk.fail(f"edge topology delta SSH read failed: {proc.stderr.strip()[:200]}")
                else:
                    snap_state = json.loads(proc.stdout)
                    mode = str(snap_state.get("operational_mode") or "")
                    if mode != "detect":
                        chk.fail(f"edge topology delta expected mode=detect got {mode!r}")
                    delta = snap_state.get("last_topology_delta")
                    if not isinstance(delta, dict):
                        chk.fail("edge topology delta missing last_topology_delta")
                    elif not snap_state.get("last_delta_publish_at"):
                        chk.fail("edge topology delta missing last_delta_publish_at")
                    else:
                        chk.ok(
                            f"edge topology delta published delta={delta} "
                            f"at={snap_state.get('last_delta_publish_at')}"
                        )
            except Exception as exc:
                chk.fail(f"edge topology delta verify: {exc}")

        if args.expect_topology_views and token:
            topo_q = f"&sensor_id={urllib.parse.quote(sensor_id)}" if sensor_id else ""
            for suffix, label, min_items in (
                (f"/topology/conduits?limit=20{topo_q}", "conduits", 0),
                (f"/topology/it-dependencies?{topo_q.lstrip('&')}", "it-dependencies", 0),
                (f"/topology/external?since=7d&limit=20", "external", 0),
            ):
                try:
                    payload = _request(
                        base=base,
                        path=f"{ot}{suffix}",
                        token=token,
                        workspace_id=ws,
                    )
                    if "it-dependencies" in suffix:
                        ot_n = len(payload.get("ot_nodes") or []) if isinstance(payload, dict) else 0
                        it_n = len(payload.get("it_nodes") or []) if isinstance(payload, dict) else 0
                        edge_n = len(payload.get("edges") or []) if isinstance(payload, dict) else 0
                        chk.ok(
                            f"GET ot-security/topology/it-dependencies "
                            f"ot_nodes={ot_n} it_nodes={it_n} edges={edge_n}"
                        )
                        if args.expect_topology and edge_n < min_items and ot_n == 0 and it_n == 0:
                            chk.warn("it-dependencies empty — OK if no L4 IT conduits in lab yet")
                        if args.min_it_nodes and it_n < args.min_it_nodes:
                            chk.fail(f"it-dependencies it_nodes {it_n} < min {args.min_it_nodes}")
                        if args.min_it_nodes and edge_n < 1:
                            chk.fail("it-dependencies has no OT→IT edges")
                    else:
                        items = payload.get("items") if isinstance(payload, dict) else []
                        total = int(payload.get("total") or len(items or [])) if isinstance(payload, dict) else 0
                        chk.ok(
                            f"GET ot-security{suffix.split('?')[0]} total={total} "
                            f"items={len(items or [])}"
                        )
                        if args.expect_topology and label == "conduits" and total < args.min_topology_conduits:
                            chk.fail(
                                f"topology {label} total {total} < min {args.min_topology_conduits}"
                            )
                        if label == "external" and args.min_external_entities and total < args.min_external_entities:
                            chk.fail(
                                f"topology external total {total} < min {args.min_external_entities}"
                            )
                except Exception as exc:
                    chk.fail(f"topology view {label}: {exc}")

    # Edge Console mode badge (FR-Edge-1)
    try:
        status = _plain_get(f"{args.edge_console_url.rstrip('/')}/api/status")
        op = status.get("operational_mode") if isinstance(status.get("operational_mode"), dict) else {}
        mode = str(op.get("operational_mode") or status.get("operational_mode") or "")
        if isinstance(status.get("operational_mode"), str):
            mode = str(status.get("operational_mode"))
        chk.ok(f"Edge Console /api/status mode={mode or '?'}")
        if args.expect_mode and mode and mode != args.expect_mode:
            chk.fail(f"Edge Console expected mode={args.expect_mode} got {mode!r}")
    except Exception as exc:
        chk.warn(f"Edge Console status: {exc}")

    # CTA coverage
    cta_url = f"{args.layerc_url.rstrip('/')}/api/cta/coverage?tenant_id={args.tenant_id}"
    try:
        cta = _plain_get(cta_url)
        summary = cta.get("summary") if isinstance(cta.get("summary"), dict) else {}
        detected = int(summary.get("detected") or 0)
        chk.ok(f"CTA coverage detected={detected} fully_covered={summary.get('fully_covered')}")
        if args.cta_snapshot:
            with open(args.cta_snapshot, "w", encoding="utf-8") as fh:
                json.dump({"summary": summary, "tenant_id": args.tenant_id}, fh, ensure_ascii=False, indent=2)
            chk.ok(f"CTA snapshot written {args.cta_snapshot}")
        if args.cta_compare:
            with open(args.cta_compare, encoding="utf-8") as fh:
                before = json.load(fh)
            before_detected = int((before.get("summary") or {}).get("detected") or 0)
            delta = detected - before_detected
            if delta > args.max_detect_delta:
                chk.fail(f"CTA detected grew by {delta} (max {args.max_detect_delta}) — listen/learning pollution?")
            else:
                chk.ok(f"CTA detected delta={delta} (max {args.max_detect_delta})")
    except Exception as exc:
        chk.fail(f"CTA coverage: {exc}")

    if chk.failures:
        print(f"\n==> FAILED ({len(chk.failures)} checks, {len(chk.warnings)} warnings)", file=sys.stderr)
        return 1
    print(f"\n==> PASSED ({len(chk.warnings)} warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
