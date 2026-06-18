"""
Packet Sensor Agent entry point.
Sprint 1: capture loop. S1-02b: IEC 61850 GOOSE/MMS passive pipeline.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time

from src.baseline.snapshot import write_live_observed
from src.capture.interface import CaptureSession
from src.config.settings import load_config
from src.detection.external_engine.snort_source import SnortAlertSource
from src.detection.external_engine.suricata_source import SuricataEveSource
from src.live_stats import LiveStatsTracker, write_live_stats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("packet-sensor")

_shutdown = False


def _handle_signal(signum: int, _frame) -> None:
    global _shutdown
    logger.info("Received signal %s, shutting down", signum)
    _shutdown = True


def main() -> int:
    global _shutdown

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        config = load_config()
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    log_level = getattr(logging, config.logging.level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_level)

    logger.info(
        "SenseL Packet Sensor v%s starting (interface=%s backend=%s bpf=%r)",
        config.sensor.software_version,
        config.capture.interface,
        config.capture.backend,
        config.capture.bpf_filter or "",
    )

    session = CaptureSession(config)
    capture_error: list[Exception] = []

    def capture_loop() -> None:
        try:
            session.run(should_stop=lambda: _shutdown)
        except Exception as exc:
            capture_error.append(exc)
            logger.exception("Capture loop failed")

    thread = threading.Thread(target=capture_loop, name="capture", daemon=True)
    thread.start()

    # Optional external Snort 3 alert_json bridge. Off by default; when enabled
    # it tails Snort's NDJSON and writes mapped events to snort-events.jsonl in
    # the shared assets dir for the edge-agent to upload north.
    snort_source: SnortAlertSource | None = None
    if config.snort_source.enabled:
        snort_source = SnortAlertSource(
            alert_json_path=config.snort_source.alert_json_path,
            output_dir=config.features.assets_dir,
            offset_path=config.snort_source.offset_path,
            site_id=config.sensor.site_id,
            sensor_id=config.sensor.id,
        )
        logger.info(
            "Snort source enabled — alert_json=%s output=%s poll=%ss",
            config.snort_source.alert_json_path,
            snort_source.output_path,
            config.snort_source.poll_interval_sec,
        )
    snort_poll_interval = max(1, config.snort_source.poll_interval_sec)
    ticks_since_snort = 0

    # Optional external Suricata EVE JSON bridge (same pattern as Snort).
    suricata_source: SuricataEveSource | None = None
    if config.suricata_source.enabled:
        suricata_source = SuricataEveSource(
            eve_json_path=config.suricata_source.eve_json_path,
            output_dir=config.features.assets_dir,
            offset_path=config.suricata_source.offset_path,
            site_id=config.sensor.site_id,
            sensor_id=config.sensor.id,
        )
        logger.info(
            "Suricata source enabled — eve_json=%s output=%s poll=%ss",
            config.suricata_source.eve_json_path,
            suricata_source.output_path,
            config.suricata_source.poll_interval_sec,
        )
    suricata_poll_interval = max(1, config.suricata_source.poll_interval_sec)
    ticks_since_suricata = 0

    stats_interval = config.capture.stats_log_interval_sec
    live_interval = max(
        1,
        int(os.environ.get("LIVE_STATS_INTERVAL_SEC", "1")),
    )
    feature_interval = config.features.window_sec
    live_observe_window = max(0, int(os.environ.get("LIVE_OBSERVE_WINDOW_SEC", "900")))
    ticks_since_feature = 0
    ticks_since_log = 0
    live_tracker = LiveStatsTracker()

    try:
        while not _shutdown:
            if capture_error:
                return 1
            snap = session.snapshot()
            live_payload = live_tracker.enrich(snap)
            live_payload["sensor_id"] = config.sensor.id
            live_payload["site_id"] = config.sensor.site_id
            write_live_stats(live_payload, config.features.assets_dir)

            ticks_since_log += live_interval
            if ticks_since_log >= stats_interval:
                ticks_since_log = 0
                logger.info(
                    "Capture stats — backend=%s total=%d rate=%.1f/s instant=%.1f/s goose=%d mms_writes=%d sessions=%d elapsed=%.0fs",
                    snap.get("capture_backend", "?"),
                    snap["total_packets"],
                    snap["packet_rate"],
                    live_payload.get("instant_rate", 0),
                    snap["goose_messages"],
                    snap["mms_writes"],
                    snap["mms_sessions"],
                    snap["elapsed_sec"],
                )

            if snort_source is not None:
                ticks_since_snort += live_interval
                if ticks_since_snort >= snort_poll_interval:
                    ticks_since_snort = 0
                    try:
                        written = snort_source.poll_once()
                        if written:
                            logger.info("Snort source ingested %d alert(s)", written)
                    except Exception:
                        logger.debug("Snort source poll failed", exc_info=True)

            if suricata_source is not None:
                ticks_since_suricata += live_interval
                if ticks_since_suricata >= suricata_poll_interval:
                    ticks_since_suricata = 0
                    try:
                        written = suricata_source.poll_once()
                        if written:
                            logger.info("Suricata source ingested %d alert(s)", written)
                    except Exception:
                        logger.debug("Suricata source poll failed", exc_info=True)

            ticks_since_feature += live_interval
            if ticks_since_feature >= feature_interval:
                session.pipeline.flush_features()
                try:
                    write_live_observed(
                        session.pipeline.live_baseline_snapshot(
                            window_sec=live_observe_window or None
                        ),
                        config.features.assets_dir,
                    )
                except Exception:
                    logger.debug("live baseline snapshot write failed", exc_info=True)
                ticks_since_feature = 0
            for _ in range(live_interval):
                if _shutdown or capture_error:
                    break
                time.sleep(1)
    finally:
        _shutdown = True
        thread.join(timeout=5)
        session.close()

    logger.info("Packet Sensor stopped — %s", session.snapshot())
    return 1 if capture_error else 0


if __name__ == "__main__":
    sys.exit(main())
