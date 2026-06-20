"""Build ACK/NACK payloads for applied OT policy artifacts (D4 close-the-loop).

The edge reports the outcome of each rule / listfile apply northbound so the
Control Plane distribution log can show ``acked`` / ``nacked`` (rolled back /
rejected) instead of only ``sent``. Payloads are intentionally small and
schema-stable; the northbound envelope wraps them with sensor/tenant identity.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from src.config.settings import AppConfig

logger = logging.getLogger(__name__)


def ids_rule_ack_payload(result: Any) -> dict[str, Any]:
    if result.ok and result.changed:
        status, outcome = "ack", "applied"
    elif getattr(result, "rolled_back", False):
        status, outcome = "nack", "rolled_back"
    else:
        status, outcome = "nack", "rejected"
    return {
        "schema_version": "ot_policy_ack.v1",
        "artifact_type": "ids_rule",
        "engine": result.engine,
        "status": status,
        "outcome": outcome,
        "version": result.version or "",
        "rule_count": int(getattr(result, "rule_count", 0) or 0),
        "rolled_back": bool(getattr(result, "rolled_back", False)),
        "tenant_id": getattr(result, "tenant_id", "") or "",
        "error": getattr(result, "error", None),
    }


def listfile_ack_payload(result: Any) -> dict[str, Any]:
    if result.ok and result.changed:
        status, outcome = "ack", "applied"
    else:
        status, outcome = "nack", "rejected"
    return {
        "schema_version": "ot_policy_ack.v1",
        "artifact_type": "listfile",
        "status": status,
        "outcome": outcome,
        "version": getattr(result, "artifact_version", "") or "",
        "item_count": int(getattr(result, "item_count", 0) or 0),
        "tenant_id": getattr(result, "tenant_id", "") or "",
        "error": getattr(result, "error", None),
    }


def autoupdate_report_payload(result: Any) -> dict[str, Any]:
    """Flat report for an edge ``suricata-update`` execution (G10)."""
    return {
        "schema_version": "ot_autoupdate_report.v1",
        "artifact_type": "autoupdate",
        "engine": getattr(result, "engine", "suricata") or "suricata",
        "status": "ok" if getattr(result, "ok", False) else "failed",
        "version": getattr(result, "version", "") or "",
        "rule_count": int(getattr(result, "rule_count", 0) or 0),
        "tenant_id": getattr(result, "tenant_id", "") or "",
        "error": getattr(result, "error", None),
    }


class PolicyAckReporter:
    """Deliver an ACK/NACK northbound: MQTT first, HTTP fallback when offline.

    The MQTT path lands on ``ot-edge/{tenant}/{site}/{sensor}/policy/ack/v1`` and
    is forwarded to the Control Plane by the northbound bridge. When the bus is
    unavailable (or disabled), the HTTP fallback POSTs the flat ACK directly to
    the internal ingest endpoint so the distribution log still converges.
    """

    def __init__(self, config: AppConfig, mqtt: Any) -> None:
        ps = config.policy_sync
        self._config = config
        self._mqtt = mqtt
        self._http_enabled = bool(ps.policy_ack_http_fallback_enabled)
        self._base = config.sensel.api_url.rstrip("/")
        self._path = ps.policy_ack_ingest_path
        self._autoupdate_path = getattr(
            ps, "autoupdate_report_ingest_path", "/api/v1/internal/ot-security/autoupdate-report"
        )
        self._secret = (ps.policy_ack_ingest_secret or config.sensel.api_key or "").strip()

    def report(self, ack: dict[str, Any]) -> None:
        if self._mqtt is not None and getattr(self._mqtt, "enabled", False):
            if self._mqtt.publish_policy_ack(ack):
                return
        self._http_fallback(ack)

    def report_autoupdate(self, report: dict[str, Any]) -> None:
        """Deliver an edge suricata-update report to the CP ingest endpoint (G10).

        HTTP-only: the report is low-frequency and the dedicated ingest endpoint is
        not bridged over the policy/ack MQTT topic.
        """
        if not self._secret:
            return
        body = dict(report)
        body.setdefault("sensor_id", self._config.sensor.id)
        body.setdefault("site_id", self._config.sensor.site_id)
        body.setdefault("tenant_id", self._config.northbound_mqtt.tenant_id)
        url = f"{self._base}{self._autoupdate_path}"
        headers = {
            "Content-Type": "application/json",
            "X-Ot-Security-Ingest-Secret": self._secret,
            "Authorization": f"Bearer {self._secret}",
        }
        try:
            with httpx.Client(timeout=15.0, verify=self._config.sensel.verify_tls) as client:
                resp = client.post(url, json=body, headers=headers)
            if resp.status_code >= 400:
                logger.warning("Autoupdate report failed (%s): %s", resp.status_code, resp.text[:200])
            else:
                logger.info("Autoupdate report delivered status=%s rules=%s",
                            report.get("status"), report.get("rule_count"))
        except httpx.HTTPError as exc:
            logger.warning("Autoupdate report error: %s", exc)

    def _http_fallback(self, ack: dict[str, Any]) -> None:
        if not self._http_enabled or not self._secret:
            return
        body = dict(ack)
        body.setdefault("sensor_id", self._config.sensor.id)
        body.setdefault("site_id", self._config.sensor.site_id)
        url = f"{self._base}{self._path}"
        headers = {
            "Content-Type": "application/json",
            "X-Ot-Security-Ingest-Secret": self._secret,
            "Authorization": f"Bearer {self._secret}",
        }
        try:
            with httpx.Client(timeout=15.0, verify=self._config.sensel.verify_tls) as client:
                resp = client.post(url, json=body, headers=headers)
            if resp.status_code >= 400:
                logger.warning(
                    "Policy ACK HTTP fallback failed (%s): %s", resp.status_code, resp.text[:200]
                )
            else:
                logger.info(
                    "Policy ACK delivered via HTTP fallback artifact=%s status=%s",
                    ack.get("artifact_type"), ack.get("status"),
                )
        except httpx.HTTPError as exc:
            logger.warning("Policy ACK HTTP fallback error: %s", exc)
