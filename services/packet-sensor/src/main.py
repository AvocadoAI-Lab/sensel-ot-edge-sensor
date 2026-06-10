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
