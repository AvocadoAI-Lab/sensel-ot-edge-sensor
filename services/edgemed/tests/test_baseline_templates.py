import json
import unittest
from pathlib import Path

from app.baseline_templates import (
    RESOLUTION_DEVICE_TYPE,
    RESOLUTION_GENERIC,
    bind_asset,
    list_templates,
    load_common_rules,
    load_fallback_template,
    load_template,
    resolve_profile_for_device_type,
)
from app.rag import KnowledgeBase, ReadOnlyToolBelt


ROOT = Path(__file__).resolve().parents[1]


class BaselineTemplateTests(unittest.TestCase):
    def test_catalog_lists_templates(self):
        items = list_templates()
        profile_ids = {str(item.get("profile_id")) for item in items}
        self.assertEqual(
            profile_ids,
            {
                "cic-template-medical-camera-v1",
                "cic-template-medical-pager-v1",
                "cic-template-bp-monitor-v1",
                "cic-template-baby-sensor-v1",
            },
        )

    def test_templates_have_required_fields(self):
        for profile_id in (
            "cic-template-medical-camera-v1",
            "cic-template-medical-pager-v1",
            "cic-template-bp-monitor-v1",
            "cic-template-baby-sensor-v1",
        ):
            template = load_template(profile_id)
            self.assertEqual(template.get("schema"), "sensel.baseline.profile.v1")
            self.assertTrue(template.get("profile_id"))
            device_template = template.get("device_template") or {}
            self.assertTrue(device_template.get("device_type"))
            observed = template.get("observed") or {}
            self.assertIn("iomt", observed)
            self.assertIn("thresholds", observed)

    def test_bind_asset_produces_edge_artifact(self):
        template = load_template("cic-template-medical-camera-v1")
        artifact = bind_asset(
            template,
            asset_id="blink-camera-01",
            sensor_id="ot-edge-pi4",
            site_id="factory-lab-pi",
        )
        self.assertEqual(artifact["profile_id"], "cic-template-medical-camera-v1")
        self.assertEqual(artifact["asset_id"], "blink-camera-01")
        self.assertEqual(artifact["sensor_id"], "ot-edge-pi4")
        self.assertEqual(artifact["device_type"], "medical_camera")

    def test_behavior_refs_resolve_in_kb(self):
        kb = KnowledgeBase(kb_dir=ROOT / "config" / "kb")
        tools = ReadOnlyToolBelt(kb, related_events_provider=lambda **_: [])
        for device_type, operating_state in (
            ("medical_camera", "idle"),
            ("medical_camera", "interaction"),
            ("medical_pager", "idle"),
            ("medical_pager", "interaction"),
            ("bp_monitor", "idle"),
            ("bp_monitor", "active"),
            ("baby_sensor", "idle"),
            ("baby_sensor", "interaction"),
        ):
            behavior = tools.get_behavior_baseline(device_type, operating_state)
            self.assertTrue(behavior.ok, msg=f"{device_type}:{operating_state} -> {behavior.error}")
            asset = tools.get_asset_profile(device_type)
            self.assertTrue(asset.ok, msg=f"asset {device_type} -> {asset.error}")

    def test_templates_enriched_with_profiling_stats(self):
        template = load_template("cic-template-medical-camera-v1")
        self.assertEqual(template.get("stats_source"), "cic_profiling")
        thresholds = (template.get("observed") or {}).get("thresholds") or {}
        self.assertIsNotNone(thresholds.get("rate_p50_hint"))
        self.assertIsNotNone(thresholds.get("rate_p95_hint"))

    def test_demo_preset_ids_exist(self):
        allowlist = json.loads(
            (ROOT / "config" / "devices" / "ciciomt_device_allowlist.json").read_text(encoding="utf-8")
        )
        preset_ids = {str(item.get("id")) for item in (allowlist.get("demo_presets") or [])}
        for profile_id in (
            "cic-template-medical-camera-v1",
            "cic-template-medical-pager-v1",
            "cic-template-bp-monitor-v1",
            "cic-template-baby-sensor-v1",
        ):
            template = load_template(profile_id)
            onboarding = template.get("onboarding") or {}
            preset_id = str(onboarding.get("demo_preset_id") or "")
            self.assertIn(preset_id, preset_ids, msg=f"{profile_id} preset {preset_id}")


class UnknownDeviceFallbackTests(unittest.TestCase):
    UNKNOWN_TYPE = "unknown_medical_device"

    def test_known_device_type_resolves_to_dedicated_template(self):
        template, resolution = resolve_profile_for_device_type("medical_camera")
        self.assertEqual(resolution, RESOLUTION_DEVICE_TYPE)
        self.assertEqual(template["profile_id"], "cic-template-medical-camera-v1")

    def test_unknown_device_type_falls_back_instead_of_raising(self):
        template, resolution = resolve_profile_for_device_type(self.UNKNOWN_TYPE)
        self.assertEqual(resolution, RESOLUTION_GENERIC)
        self.assertEqual(template["profile_id"], "generic-observe-only-v1")

    def test_fallback_carries_no_borrowed_traffic_statistics(self):
        template, _ = resolve_profile_for_device_type(self.UNKNOWN_TYPE)
        observed = template["observed"]
        thresholds = observed["thresholds"]
        self.assertNotIn("rate_p50_hint", thresholds)
        self.assertNotIn("rate_p95_hint", thresholds)
        self.assertNotIn("cic_profiling_stats", observed)
        self.assertIs(thresholds["assert_rate_thresholds"], False)
        self.assertEqual(load_fallback_template()["stats_source"], "none_observe_only")

    def test_fallback_seeded_with_common_rules_only(self):
        common_rules = load_common_rules()
        self.assertFalse(common_rules["derivation"]["uses_device_traffic_statistics"])
        template, _ = resolve_profile_for_device_type(self.UNKNOWN_TYPE)
        iomt = template["observed"]["iomt"]
        self.assertEqual(
            iomt["forbidden_patterns"],
            common_rules["forbidden_patterns"],
        )
        self.assertEqual(
            iomt["allowed_destination_categories"],
            common_rules["allowed_destination_categories"],
        )
        self.assertEqual(iomt["normal_destinations"], [])

    def test_common_rules_extend_device_type_templates(self):
        common_rules = load_common_rules()
        template, _ = resolve_profile_for_device_type("medical_camera")
        patterns = template["observed"]["iomt"]["forbidden_patterns"]
        self.assertIn("sustained_flood", patterns)
        for pattern in common_rules["forbidden_patterns"]:
            self.assertIn(pattern, patterns)
        thresholds = template["observed"]["thresholds"]
        self.assertIsNotNone(thresholds.get("rate_p95_hint"))
        self.assertNotIn("assert_rate_thresholds", thresholds)

    def test_bound_fallback_artifact_declares_provenance(self):
        common_rules = load_common_rules()
        template, resolution = resolve_profile_for_device_type(self.UNKNOWN_TYPE)
        artifact = bind_asset(
            template,
            asset_id="unknown-asset-01",
            sensor_id="ot-edge-pi4",
            site_id="factory-lab-pi",
            device_type=self.UNKNOWN_TYPE,
            resolution=resolution,
            common_rules_id=str(common_rules["rules_id"]),
        )
        provenance = artifact["observed"]["provenance"]
        self.assertEqual(provenance["resolution"], RESOLUTION_GENERIC)
        self.assertEqual(provenance["requested_device_type"], self.UNKNOWN_TYPE)
        self.assertEqual(provenance["stats_source"], "none_observe_only")
        self.assertEqual(provenance["common_rules_id"], "org-common-rules-v1")
        self.assertTrue(provenance["requires_local_learning"])
        self.assertEqual(artifact["device_type"], self.UNKNOWN_TYPE)

    def test_fallback_onboarding_requires_learning_before_detect(self):
        onboarding = load_fallback_template()["onboarding"]
        self.assertEqual(onboarding["initial_mode"], "learning")
        self.assertTrue(onboarding["require_learned_baseline_before_detect"])

    def test_fallback_rag_refs_resolve_in_kb(self):
        kb = KnowledgeBase(kb_dir=ROOT / "config" / "kb")
        tools = ReadOnlyToolBelt(kb, related_events_provider=lambda **_: [])
        self.assertTrue(tools.get_asset_profile("unknown_device").ok)
        self.assertTrue(tools.get_behavior_baseline("unknown_device", "unknown").ok)


if __name__ == "__main__":
    unittest.main()
