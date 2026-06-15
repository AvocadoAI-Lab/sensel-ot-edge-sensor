"""Shared Lab checks for OT topology × EDR match (PRD §4.5 / §11.2)."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class EdrMatchScenario:
    name: str
    target_ip: str
    min_confidence: float
    expected_agent_id: str
    asset_type: str = "hmi"
    purdue_level: str = "L2"
    protocols: tuple[str, ...] = ("modbus-tcp",)
    expect_os_family: str = ""


SCENARIOS: dict[str, EdrMatchScenario] = {
    "ubuntu108": EdrMatchScenario(
        name="ubuntu108",
        target_ip="192.168.1.108",
        min_confidence=0.85,
        expected_agent_id="003",
        expect_os_family="linux",
    ),
    "windows-hmi": EdrMatchScenario(
        name="windows-hmi",
        target_ip="192.168.1.235",
        min_confidence=0.9,
        expected_agent_id="004",
        expect_os_family="windows",
    ),
}


class CheckerLike(Protocol):
    def ok(self, msg: str) -> None: ...
    def warn(self, msg: str) -> None: ...
    def fail(self, msg: str) -> None: ...


def asset_id(*, tenant_id: str, sensor_id: str, ip: str) -> str:
    raw = f"{tenant_id}|{sensor_id}|ip:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def ingest_secret_post(*, base: str, path: str, body: dict, ingest_secret: str) -> Any:
    req = urllib.request.Request(
        f"{base.rstrip('/')}{path}",
        data=json.dumps(body, ensure_ascii=False).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Ot-Security-Ingest-Secret": ingest_secret,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def seed_topology_asset(
    *,
    base: str,
    ingest_secret: str,
    tenant_id: str,
    sensor_id: str,
    site_id: str,
    scenario: EdrMatchScenario,
) -> str:
    ip = scenario.target_ip
    aid = asset_id(tenant_id=tenant_id, sensor_id=sensor_id, ip=ip)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    body = {
        "tenant_id": tenant_id,
        "site_id": site_id,
        "sensor_id": sensor_id,
        "observed_at": now,
        "operational_mode": "detect",
        "assets": [
            {
                "schema": "sensel.ot_topology.asset.v1",
                "asset_id": aid,
                "tenant_id": tenant_id,
                "sensor_id": sensor_id,
                "site_id": site_id,
                "ip": ip,
                "asset_type": scenario.asset_type,
                "purdue_level": scenario.purdue_level,
                "protocols": list(scenario.protocols),
                "confidence": 0.75,
                "evidence_sources": ["lab_edr_seed", "modbus_role"],
            }
        ],
        "conduits": [],
        "external_entities": [],
        "zone_counts": {scenario.purdue_level: 1},
    }
    ingest_secret_post(
        base=base,
        path="/api/v1/internal/ot-security/topology/ingest",
        body=body,
        ingest_secret=ingest_secret,
    )
    return aid


def run_edr_match_checks(
    chk: CheckerLike,
    *,
    base: str,
    workspace_id: int,
    tenant_id: str,
    sensor_id: str,
    site_id: str,
    token: str,
    scenario: EdrMatchScenario,
    ingest_secret: str,
    api_request: Any,
    expect_edr_context: bool = True,
) -> None:
    """Seed lab asset and verify EDR enrich + optional edr-context."""
    ot = f"/api/v1/smb/workspaces/{workspace_id}/ot-security"
    target_ip = scenario.target_ip

    agents: list[dict[str, Any]] = []
    try:
        data = api_request(base=base, path="/api/v1/smb/edr/agents", token=token, workspace_id=workspace_id)
        agents = [a for a in (data.get("agents") or []) if isinstance(a, dict)]
        chk.ok(f"EDR agents count={len(agents)} scenario={scenario.name}")
    except Exception as exc:
        chk.fail(f"EDR agents: {exc}")
        return

    agent_for_ip = next((a for a in agents if str(a.get("ip") or "").strip() == target_ip), None)
    if agent_for_ip is None:
        chk.fail(f"no EDR agent with primary ip={target_ip} (scenario={scenario.name})")
    else:
        chk.ok(
            f"EDR agent id={agent_for_ip.get('id')} ip={agent_for_ip.get('ip')} "
            f"os={(agent_for_ip.get('os') or '')[:40]}"
        )
        if scenario.expected_agent_id and str(agent_for_ip.get("id") or "") != scenario.expected_agent_id:
            chk.fail(
                f"expected agent id={scenario.expected_agent_id} "
                f"got {agent_for_ip.get('id')} for ip={target_ip}"
            )

    aid = asset_id(tenant_id=tenant_id, sensor_id=sensor_id, ip=target_ip)
    try:
        seed_topology_asset(
            base=base,
            ingest_secret=ingest_secret,
            tenant_id=tenant_id,
            sensor_id=sensor_id,
            site_id=site_id,
            scenario=scenario,
        )
        chk.ok(f"seed topology asset ip={target_ip} asset_id={aid}")
    except Exception as exc:
        chk.fail(f"topology ingest seed: {exc}")
        return

    asset = None
    try:
        listed = api_request(
            base=base,
            path=f"{ot}/topology/assets?sensor_id={urllib.parse.quote(sensor_id)}&limit=100",
            token=token,
            workspace_id=workspace_id,
        )
        for row in listed.get("items") or []:
            if str(row.get("ip") or "") == target_ip or str(row.get("asset_id") or "") == aid:
                asset = row
                break
        if asset is None:
            chk.fail(f"topology asset ip={target_ip} not found after ingest")
            return

        edr_id = str(asset.get("edr_agent_id") or "").strip()
        conf = float(asset.get("confidence") or 0)
        os_family = str(asset.get("os_family") or "").strip().lower()
        chk.ok(
            f"topology asset ip={target_ip} edr_agent_id={edr_id or '-'} "
            f"confidence={conf:.2f} asset_type={asset.get('asset_type')} os_family={os_family or '-'}"
        )
        if not edr_id:
            chk.fail("topology asset missing edr_agent_id after enrich")
        elif scenario.expected_agent_id and edr_id != scenario.expected_agent_id:
            chk.fail(f"edr_agent_id={edr_id} != expected {scenario.expected_agent_id}")
        if conf < scenario.min_confidence:
            chk.fail(f"confidence {conf:.2f} < min {scenario.min_confidence}")
        if scenario.expect_os_family and os_family != scenario.expect_os_family:
            chk.fail(f"os_family expected {scenario.expect_os_family} got {os_family or '-'}")
        if asset.get("asset_type") != scenario.asset_type:
            chk.fail(f"asset_type expected {scenario.asset_type} got {asset.get('asset_type')!r}")
        if asset.get("purdue_level") != scenario.purdue_level:
            chk.fail(f"purdue_level expected {scenario.purdue_level} got {asset.get('purdue_level')!r}")
    except Exception as exc:
        chk.fail(f"topology assets: {exc}")
        return

    if expect_edr_context and asset and asset.get("asset_id"):
        try:
            ctx = api_request(
                base=base,
                path=f"{ot}/topology/assets/{urllib.parse.quote(str(asset.get('asset_id')))}/edr-context",
                token=token,
                workspace_id=workspace_id,
            )
            if not ctx.get("matched"):
                chk.fail(f"edr-context matched=false reason={ctx.get('reason')}")
            else:
                summary = ctx.get("syscollector_summary")
                chk.ok(
                    f"edr-context matched agent={ctx.get('edr_agent_id')} "
                    f"strategy={ctx.get('match_strategy')} "
                    f"syscollector={'yes' if summary else 'no'}"
                )
                if ctx.get("narrative_zh"):
                    chk.ok("edr-context narrative_zh present")
        except Exception as exc:
            chk.fail(f"edr-context: {exc}")

    try:
        dash = api_request(base=base, path=f"{ot}/dashboard", token=token, workspace_id=workspace_id)
        kpi = dash.get("topology_kpi") if isinstance(dash, dict) else {}
        matched = int((kpi or {}).get("edr_matched_assets") or 0)
        chk.ok(f"dashboard edr_matched_assets={matched}")
        if matched < 1:
            chk.fail("dashboard edr_matched_assets < 1 after EDR seed")
    except Exception as exc:
        chk.fail(f"dashboard edr kpi: {exc}")


def run_cve_context_checks(
    chk: CheckerLike,
    *,
    base: str,
    workspace_id: int,
    tenant_id: str,
    sensor_id: str,
    token: str,
    api_request: Any,
    expected_agent_id: str = "",
    min_vuln_total: int = 1,
    expect_graph_badge: bool = True,
    strict: bool = False,
) -> None:
    """Verify edr-context vulnerability_summary and graph vuln_badge for Lab agents."""
    ot = f"/api/v1/smb/workspaces/{workspace_id}/ot-security"
    edr_base = "/api/v1/smb/edr"

    agents: list[dict[str, Any]] = []
    try:
        data = api_request(base=base, path=f"{edr_base}/agents", token=token, workspace_id=workspace_id)
        agents = [a for a in (data.get("agents") or []) if isinstance(a, dict)]
        chk.ok(f"CVE gate: EDR agents count={len(agents)}")
    except Exception as exc:
        chk.fail(f"CVE gate EDR agents: {exc}")
        return

    best_agent: dict[str, Any] | None = None
    best_total = 0
    for agent in agents:
        aid = str(agent.get("id") or "").strip()
        if not aid:
            continue
        if expected_agent_id and aid != expected_agent_id:
            continue
        try:
            vuln_data = api_request(
                base=base,
                path=f"{edr_base}/agents/{urllib.parse.quote(aid)}/vulnerabilities?limit=20",
                token=token,
                workspace_id=workspace_id,
            )
            counts = vuln_data.get("counts") if isinstance(vuln_data, dict) else {}
            total = int((counts or {}).get("total") or 0)
            chk.ok(f"agent {aid} indexer vuln total={total}")
            if total > best_total:
                best_total = total
                best_agent = agent
        except Exception as exc:
            chk.warn(f"agent {aid} vulnerabilities API: {exc}")

    if expected_agent_id and best_agent is None:
        for agent in agents:
            if str(agent.get("id") or "").strip() == expected_agent_id:
                best_agent = agent
                break

    if best_agent is None and agents:
        for agent in agents:
            aid = str(agent.get("id") or "").strip()
            if not aid:
                continue
            try:
                vuln_data = api_request(
                    base=base,
                    path=f"{edr_base}/agents/{urllib.parse.quote(aid)}/vulnerabilities?limit=20",
                    token=token,
                    workspace_id=workspace_id,
                )
                counts = vuln_data.get("counts") if isinstance(vuln_data, dict) else {}
                total = int((counts or {}).get("total") or 0)
                if total > best_total:
                    best_total = total
                    best_agent = agent
            except Exception:
                continue

    if best_agent is None:
        msg = "no EDR agent available for CVE gate"
        if strict:
            chk.fail(msg)
        else:
            chk.warn(msg)
        return

    agent_id = str(best_agent.get("id") or "").strip()
    if best_total < min_vuln_total:
        msg = (
            f"agent {agent_id} vuln total={best_total} < min {min_vuln_total} "
            "(indexer may be empty — seed Wazuh vuln states for Lab)"
        )
        if strict:
            chk.fail(msg)
        else:
            chk.warn(msg)
            return

    asset_row: dict[str, Any] | None = None
    try:
        listed = api_request(
            base=base,
            path=f"{ot}/topology/assets?sensor_id={urllib.parse.quote(sensor_id)}&limit=200",
            token=token,
            workspace_id=workspace_id,
        )
        for row in listed.get("items") or []:
            if str(row.get("edr_agent_id") or "").strip() == agent_id:
                asset_row = row
                break
        if asset_row is None:
            chk.fail(f"no topology asset with edr_agent_id={agent_id}")
            return
        chk.ok(
            f"topology asset asset_id={asset_row.get('asset_id')} ip={asset_row.get('ip')} "
            f"edr_agent_id={agent_id}"
        )
    except Exception as exc:
        chk.fail(f"CVE gate topology assets: {exc}")
        return

    try:
        ctx = api_request(
            base=base,
            path=f"{ot}/topology/assets/{urllib.parse.quote(str(asset_row.get('asset_id')))}/edr-context",
            token=token,
            workspace_id=workspace_id,
        )
        if not ctx.get("matched"):
            chk.fail(f"edr-context matched=false reason={ctx.get('reason')}")
            return
        summary = ctx.get("vulnerability_summary")
        total = int((summary or {}).get("total") or 0) if isinstance(summary, dict) else 0
        if total < min_vuln_total:
            chk.fail(f"edr-context vulnerability_summary.total={total} < min {min_vuln_total}")
        else:
            crit = int((summary or {}).get("critical") or 0)
            high = int((summary or {}).get("high") or 0)
            chk.ok(f"edr-context vulnerability_summary total={total} critical={crit} high={high}")
    except Exception as exc:
        chk.fail(f"edr-context CVE: {exc}")
        return

    if not expect_graph_badge:
        return

    try:
        graph = api_request(
            base=base,
            path=f"{ot}/topology?sensor_id={urllib.parse.quote(sensor_id)}",
            token=token,
            workspace_id=workspace_id,
        )
        node = next(
            (
                n
                for n in (graph.get("nodes") or [])
                if str(n.get("edr_agent_id") or "").strip() == agent_id
            ),
            None,
        )
        if node is None:
            chk.fail(f"graph missing node for edr_agent_id={agent_id}")
            return
        badge = node.get("vuln_badge")
        badge_total = int((badge or {}).get("total") or 0) if isinstance(badge, dict) else 0
        if badge_total < min_vuln_total:
            chk.fail(f"graph node vuln_badge.total={badge_total} < min {min_vuln_total}")
        else:
            chk.ok(
                f"graph vuln_badge agent={agent_id} total={badge_total} "
                f"critical={(badge or {}).get('critical')} high={(badge or {}).get('high')}"
            )
    except Exception as exc:
        chk.fail(f"graph vuln_badge: {exc}")
