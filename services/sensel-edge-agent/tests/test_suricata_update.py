"""Edge suricata-update runner: execute, parse rule count, reload, report (G10)."""

from __future__ import annotations

import json
from pathlib import Path

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    NorthboundMqttConfig,
    PolicySyncConfig,
    SenselConfig,
    SensorIdentity,
)
from src.policy.policy_ack import autoupdate_report_payload
from src.policy.suricata_update import SuricataUpdateRunner

TENANT = "tenant-a"


def _config(
    tmp_path: Path,
    *,
    enabled: bool = True,
    update_cmd: str = "true",
    reload_cmd: str = "true",
    healthcheck_cmd: str = "true",
) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="s1", site_id="factory-lab-001"),
        sensel=SenselConfig(api_url="http://127.0.0.1:8081", api_key="k"),
        northbound_mqtt=NorthboundMqttConfig(tenant_id=TENANT),
        policy_sync=PolicySyncConfig(
            feed_tenant_id=TENANT,
            suricata_update_enabled=enabled,
            suricata_update_cmd=update_cmd,
            suricata_update_status_path=str(tmp_path / "suricata-update-status.json"),
            ids_rule_reload_cmd=reload_cmd,
            ids_rule_healthcheck_cmd=healthcheck_cmd,
        ),
        logging=LoggingConfig(),
    )


def test_disabled_runner_is_noop(tmp_path: Path) -> None:
    runner = SuricataUpdateRunner(_config(tmp_path, enabled=False))
    res = runner.run()
    assert res.ok and res.error == "suricata_update_disabled"


def test_success_parses_rule_count_and_reports(tmp_path: Path) -> None:
    reports = []
    runner = SuricataUpdateRunner(
        _config(tmp_path, update_cmd="echo '42000 rules successfully loaded'"),
        report_callback=reports.append,
    )
    res = runner.run()
    assert res.ok and res.rule_count == 42000 and res.tenant_id == TENANT
    assert len(reports) == 1 and reports[0].ok
    status = json.loads((tmp_path / "suricata-update-status.json").read_text(encoding="utf-8"))
    assert status["ok"] is True and status["rule_count"] == 42000

    payload = autoupdate_report_payload(res)
    assert payload["artifact_type"] == "autoupdate" and payload["status"] == "ok"
    assert payload["rule_count"] == 42000


def test_update_command_failure_reports_failed(tmp_path: Path) -> None:
    reports = []
    runner = SuricataUpdateRunner(
        _config(tmp_path, update_cmd="false"), report_callback=reports.append
    )
    res = runner.run()
    assert not res.ok and "suricata-update failed" in (res.error or "")
    assert len(reports) == 1 and not reports[0].ok
    assert autoupdate_report_payload(res)["status"] == "failed"


def test_reload_failure_reports_failed(tmp_path: Path) -> None:
    runner = SuricataUpdateRunner(
        _config(tmp_path, update_cmd="echo '10 rules successfully loaded'", reload_cmd="false")
    )
    res = runner.run()
    assert not res.ok and "reload failed" in (res.error or "")


def test_healthcheck_failure_reports_failed(tmp_path: Path) -> None:
    runner = SuricataUpdateRunner(
        _config(
            tmp_path,
            update_cmd="echo '10 rules successfully loaded'",
            reload_cmd="true",
            healthcheck_cmd="false",
        )
    )
    res = runner.run()
    assert not res.ok and "healthcheck failed" in (res.error or "")


def test_empty_healthcheck_blocks_suricata_update(tmp_path: Path) -> None:
    """G15: suricata-update must not report ok when healthcheck is unset."""
    reports = []
    runner = SuricataUpdateRunner(
        _config(
            tmp_path,
            update_cmd="echo '10 rules successfully loaded'",
            healthcheck_cmd="",
        ),
        report_callback=reports.append,
    )
    res = runner.run()
    assert not res.ok and "IDS_RULE_HEALTHCHECK_CMD" in (res.error or "")
    assert len(reports) == 1 and not reports[0].ok
