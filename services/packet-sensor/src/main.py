"""
Packet Sensor Agent entry point.
Sprint 1: capture loop. S1-02b: IEC 61850 GOOSE/MMS passive pipeline.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time

from src.capture.interface import CaptureSession
from src.config.settings import load_config

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
        "SenseL Packet Sensor v%s starting (interface=%s bpf=%r)",
        config.sensor.software_version,
        config.capture.interface,
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
    feature_interval = config.features.window_sec
    ticks_since_feature = 0

    try:
        while not _shutdown:
            if capture_error:
                return 1
            snap = session.snapshot()
            logger.info(
                "Capture stats — total=%d rate=%.1f/s goose=%d mms_writes=%d sessions=%d elapsed=%.0fs",
                snap["total_packets"],
                snap["packet_rate"],
                snap["goose_messages"],
                snap["mms_writes"],
                snap["mms_sessions"],
                snap["elapsed_sec"],
            )
            ticks_since_feature += stats_interval
            if ticks_since_feature >= feature_interval:
                session.pipeline.flush_features()
                ticks_since_feature = 0
            for _ in range(stats_interval):
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
