"""IDS rule bundle edge apply: write / idempotency / reload-rollback / signing."""

from __future__ import annotations

import json
from pathlib import Path

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    PolicySyncConfig,
    SenselConfig,
    SensorIdentity,
)
from src.policy.feed_signing import sign_artifact, verify_artifact
from src.policy.ids_rule_sync import IdsRuleSync

SECRET = "edge-secret-xyz"
TENANT = "tenant-a"
RULES = (
    'alert tcp any any -> any 80 (msg:"x"; sid:1000001; rev:1;)\n'
    "# a comment\n"
    'alert tcp any any -> any 443 (msg:"y"; sid:1000002; rev:1;)\n'
)


def _config(tmp_path: Path, *, reload_cmd: str = "", healthcheck_cmd: str = "") -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="s1", site_id="factory-lab-001"),
        sensel=SenselConfig(api_url="http://127.0.0.1:8081", api_key="k"),
        policy_sync=PolicySyncConfig(
            feed_tenant_id=TENANT,
            ids_rule_enabled=True,
            ids_rule_engines=["suricata"],
            ids_rule_target_dir=str(tmp_path / "ids-rules"),
            ids_rule_status_path=str(tmp_path / "ids-rule-status.json"),
            ids_rule_signing_secret=SECRET,
            ids_rule_reload_cmd=reload_cmd,
            ids_rule_healthcheck_cmd=healthcheck_cmd,
        ),
        logging=LoggingConfig(),
    )


def test_signature_roundtrip() -> None:
    body = RULES.encode("utf-8")
    sig = sign_artifact(body, tenant_id=TENANT, base_secret=SECRET)
    assert verify_artifact(body, sig, tenant_id=TENANT, base_secret=SECRET)
    assert not verify_artifact(body + b"x", sig, tenant_id=TENANT, base_secret=SECRET)
    assert not verify_artifact(body, sig, tenant_id="other", base_secret=SECRET)
    assert not verify_artifact(body, "", tenant_id=TENANT, base_secret=SECRET)


def test_apply_writes_target_and_status(tmp_path: Path) -> None:
    sync = IdsRuleSync(_config(tmp_path, healthcheck_cmd="true"))
    res = sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    assert res.ok and res.changed
    assert res.rule_count == 2
    target = tmp_path / "ids-rules" / "suricata.rules"
    assert target.read_text(encoding="utf-8") == RULES
    status = json.loads((tmp_path / "ids-rule-status.json").read_text(encoding="utf-8"))
    assert status["engines"]["suricata"]["ok"] is True
    assert status["engines"]["suricata"]["version"] == "v1"


def test_apply_idempotent_same_version(tmp_path: Path) -> None:
    sync = IdsRuleSync(_config(tmp_path, healthcheck_cmd="true"))
    sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    again = sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    assert again.ok and not again.changed


def test_reload_failure_with_no_previous_rejects(tmp_path: Path) -> None:
    sync = IdsRuleSync(_config(tmp_path, reload_cmd="false", healthcheck_cmd="true"))
    res = sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    assert not res.ok
    assert not res.rolled_back
    target = tmp_path / "ids-rules" / "suricata.rules"
    assert not target.exists()
    status = json.loads((tmp_path / "ids-rule-status.json").read_text(encoding="utf-8"))
    assert status["engines"]["suricata"]["ok"] is False


def test_ack_callback_emitted_on_apply_and_rollback(tmp_path: Path) -> None:
    acks: list[dict] = []
    good = IdsRuleSync(
        _config(tmp_path, reload_cmd="true", healthcheck_cmd="true"),
        ack_callback=acks.append,
    )
    good.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    assert len(acks) == 1
    assert acks[0]["status"] == "ack"
    assert acks[0]["outcome"] == "applied"
    assert acks[0]["artifact_type"] == "ids_rule"
    assert acks[0]["engine"] == "suricata"

    # Idempotent re-apply → no new ACK.
    good.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    assert len(acks) == 1

    # Failing healthcheck → NACK / rolled_back.
    bad = IdsRuleSync(
        _config(tmp_path, reload_cmd="true", healthcheck_cmd="false"),
        ack_callback=acks.append,
    )
    bad.apply_artifact(RULES + "# more\n", engine="suricata", tenant_id=TENANT, version="v2")
    assert acks[-1]["status"] == "nack"
    assert acks[-1]["outcome"] == "rolled_back"
    assert acks[-1]["rolled_back"] is True


def test_healthcheck_failure_rolls_back_to_previous(tmp_path: Path) -> None:
    # First good apply (reload + healthcheck succeed).
    good = IdsRuleSync(_config(tmp_path, reload_cmd="true", healthcheck_cmd="true"))
    good.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")

    # New bundle fails healthcheck → rollback to v1 content.
    bad = IdsRuleSync(_config(tmp_path, reload_cmd="true", healthcheck_cmd="false"))
    new_rules = RULES + 'alert tcp any any -> any 22 (msg:"z"; sid:1000003; rev:1;)\n'
    res = bad.apply_artifact(new_rules, engine="suricata", tenant_id=TENANT, version="v2")
    assert not res.ok
    assert res.rolled_back
    target = tmp_path / "ids-rules" / "suricata.rules"
    assert target.read_text(encoding="utf-8") == RULES  # restored last-known-good
    status = json.loads((tmp_path / "ids-rule-status.json").read_text(encoding="utf-8"))
    entry = status["engines"]["suricata"]
    assert entry["ok"] is False
    assert entry["version"] == "v1"  # active version reverts to good one
    assert entry["rejected_version"] == "v2"


def test_empty_healthcheck_rejects_apply_without_writing(tmp_path: Path) -> None:
    """G15: empty IDS_RULE_HEALTHCHECK_CMD must not fake ACK."""
    acks: list[dict] = []
    sync = IdsRuleSync(_config(tmp_path, healthcheck_cmd=""), ack_callback=acks.append)
    res = sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    assert not res.ok
    assert "IDS_RULE_HEALTHCHECK_CMD" in (res.error or "")
    target = tmp_path / "ids-rules" / "suricata.rules"
    assert not target.exists()
    assert len(acks) == 1
    assert acks[0]["status"] == "nack"
    assert acks[0]["outcome"] == "rejected"


def test_empty_healthcheck_idempotent_still_ok(tmp_path: Path) -> None:
    """Already-applied version short-circuits before healthcheck guard."""
    sync = IdsRuleSync(_config(tmp_path, healthcheck_cmd="true"))
    sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    bare = IdsRuleSync(_config(tmp_path, healthcheck_cmd=""))
    again = bare.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    assert again.ok and not again.changed


def test_rejects_downgrade_version_without_writing(tmp_path: Path) -> None:
    """G12: late/old manifest must not downgrade active rules."""
    acks: list[dict] = []
    sync = IdsRuleSync(
        _config(tmp_path, reload_cmd="true", healthcheck_cmd="true"),
        ack_callback=acks.append,
    )
    sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v2")
    stale_rules = RULES + "# stale\n"
    res = sync.apply_artifact(stale_rules, engine="suricata", tenant_id=TENANT, version="v1")
    assert not res.ok and not res.changed
    assert "stale version rejected" in (res.error or "")
    target = tmp_path / "ids-rules" / "suricata.rules"
    assert target.read_text(encoding="utf-8") == RULES
    status = json.loads((tmp_path / "ids-rule-status.json").read_text(encoding="utf-8"))
    entry = status["engines"]["suricata"]
    assert entry["version"] == "v2"
    assert entry["rejected_version"] == "v1"
    assert acks[-1]["status"] == "nack"
    assert acks[-1]["outcome"] == "rejected"


def test_allows_newer_version_after_active(tmp_path: Path) -> None:
    sync = IdsRuleSync(_config(tmp_path, reload_cmd="true", healthcheck_cmd="true"))
    sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version="v1")
    newer = RULES + 'alert tcp any any -> any 22 (msg:"z"; sid:1000003; rev:1;)\n'
    res = sync.apply_artifact(newer, engine="suricata", tenant_id=TENANT, version="v2")
    assert res.ok and res.changed
    assert (tmp_path / "ids-rules" / "suricata.rules").read_text(encoding="utf-8") == newer


def test_version_monotonic_accepts_cp_timestamp_versions(tmp_path: Path) -> None:
    sync = IdsRuleSync(_config(tmp_path, reload_cmd="true", healthcheck_cmd="true"))
    older = "2026.06.20.090000.000000"
    newer = "2026.06.20.090133.000000"
    sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version=newer)
    res = sync.apply_artifact(RULES, engine="suricata", tenant_id=TENANT, version=older)
    assert not res.ok
    assert "stale version rejected" in (res.error or "")
