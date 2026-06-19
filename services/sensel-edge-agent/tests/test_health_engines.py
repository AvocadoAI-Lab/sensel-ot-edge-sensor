"""Tests for IDS engine probing surfaced to the Edge Console (engine health)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from src.config.settings import (
    AppConfig,
    NorthboundMqttConfig,
    SensorIdentity,
    SenselConfig,
)
from src.health.engines import (
    engines_runtime_summary,
    probe_engines,
)

_SNORT_RULES = """\
# header comment
alert tcp any any -> any 502 ( msg:"SENSEL Modbus TCP access observed"; sid:1000001; rev:1; )
# disabled rule below should not be counted
# alert tcp any any -> any 102 ( msg:"disabled"; sid:1000099; )
alert tcp any any -> any [102,502] ( msg:"SENSEL OT port probe"; sid:1000002; rev:1; )
"""


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="ot-edge-001", site_id="factory-lab-001"),
        sensel=SenselConfig(
            api_url="http://localhost:8081",
            api_key="k",
            verify_tls=False,
            events={
                "watch_path": str(tmp_path / "security-events.jsonl"),
                "offset_path": str(tmp_path / "events.offset"),
                "snort_watch_path": str(tmp_path / "snort-events.jsonl"),
                "snort_offset_path": str(tmp_path / "snort.offset"),
                "suricata_watch_path": str(tmp_path / "suricata-events.jsonl"),
                "suricata_offset_path": str(tmp_path / "suricata.offset"),
            },
        ),
        northbound_mqtt=NorthboundMqttConfig(tenant_id="sensel-platform"),
    )


def test_probe_engines_absent_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SNORT_SOURCE_ENABLED", raising=False)
    monkeypatch.delenv("SURICATA_SOURCE_ENABLED", raising=False)
    monkeypatch.setenv("SNORT_RULES_PATH", str(tmp_path / "missing-snort.rules"))
    monkeypatch.setenv("SURICATA_RULES_PATH", str(tmp_path / "missing-suricata.rules"))

    engines = probe_engines(_config(tmp_path))
    by_name = {e["name"]: e for e in engines}

    assert set(by_name) == {"snort", "suricata"}
    for eng in engines:
        assert eng["status"] == "absent"
        assert eng["active"] is False
        assert eng["configured"] is False  # no env flag, no events file
        assert eng["rule_version"] == "unknown"
        assert eng["rules_enabled_count"] == 0


def test_probe_engine_running_with_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Fresh snort events file => running.
    (tmp_path / "snort-events.jsonl").write_text("{}\n", encoding="utf-8")
    rules = tmp_path / "snort.rules"
    rules.write_text(_SNORT_RULES, encoding="utf-8")
    monkeypatch.setenv("SNORT_RULES_PATH", str(rules))
    monkeypatch.setenv("SNORT_RULE_VERSION", "2026.06.19")
    monkeypatch.setenv("SNORT_SOURCE_ENABLED", "true")
    monkeypatch.setenv("SURICATA_RULES_PATH", str(tmp_path / "missing.rules"))

    engines = {e["name"]: e for e in probe_engines(_config(tmp_path))}
    snort = engines["snort"]

    assert snort["status"] == "running"
    assert snort["active"] is True
    assert snort["configured"] is True
    assert snort["rule_version"] == "2026.06.19"
    assert snort["rules_enabled_count"] == 2  # commented rule excluded
    sids = {r["sid"] for r in snort["rules"]}
    assert sids == {"1000001", "1000002"}
    assert snort["rules_last_update"] is not None


def test_probe_engine_stale_when_events_old(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    events = tmp_path / "suricata-events.jsonl"
    events.write_text("{}\n", encoding="utf-8")
    old = time.time() - 10_000
    import os

    os.utime(events, (old, old))
    monkeypatch.setenv("SURICATA_RULES_PATH", str(tmp_path / "missing.rules"))
    monkeypatch.delenv("SURICATA_SOURCE_ENABLED", raising=False)

    engines = {e["name"]: e for e in probe_engines(_config(tmp_path))}
    suri = engines["suricata"]

    assert suri["status"] == "stale"
    assert suri["active"] is True
    # configured inferred from "has produced events" when flag absent.
    assert suri["configured"] is True


def test_engines_runtime_summary_drops_rule_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    rules = tmp_path / "snort.rules"
    rules.write_text(_SNORT_RULES, encoding="utf-8")
    monkeypatch.setenv("SNORT_RULES_PATH", str(rules))
    monkeypatch.setenv("SURICATA_RULES_PATH", str(tmp_path / "missing.rules"))

    summary = engines_runtime_summary(probe_engines(_config(tmp_path)))

    assert len(summary) == 2
    for eng in summary:
        assert "rules" not in eng  # per-rule list excluded from compact summary
        assert "rules_enabled_count" in eng
        assert "status" in eng
