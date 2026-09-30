"""Long-running Site ingress process."""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
from datetime import datetime, timezone

from sensel_site.config import SiteConfig
from sensel_site.mqtt_ingress import SiteEpisodeIngress, SiteMqttSubscriber
from sensel_site.store import SiteStore

logger = logging.getLogger("sensel-site")


def _atomic_health(config: SiteConfig, payload: dict) -> None:
    path = config.data_dir / "health.json"
    temporary = path.with_suffix(f".tmp.{os.getpid()}")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)


def run() -> None:
    logging.basicConfig(
        level=os.getenv("SENSEL_SITE_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = SiteConfig.from_env()
    config.data_dir.mkdir(parents=True, mode=0o750, exist_ok=True)
    store = SiteStore(config.db_path)
    subscriber = SiteMqttSubscriber(config, SiteEpisodeIngress(config, store))
    stopping = threading.Event()

    def stop(signum, frame) -> None:
        del signum, frame
        stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    subscriber.start()
    logger.info(
        "SenseL Site started tenant=%s site=%s node=%s",
        config.tenant_id,
        config.site_id,
        config.node_id,
    )
    try:
        while not stopping.wait(10):
            storage = store.production_status(
                maximum_database_bytes=int(
                    os.getenv("SENSEL_SITE_MAX_DATABASE_BYTES", str(10 * 1024**3))
                ),
                maximum_wal_bytes=int(
                    os.getenv("SENSEL_SITE_MAX_WAL_BYTES", str(512 * 1024**2))
                ),
            )
            _atomic_health(
                config,
                {
                    "status": "ok" if storage["ready"] else "degraded",
                    "tenant_id": config.tenant_id,
                    "site_id": config.site_id,
                    "node_id": config.node_id,
                    "mqtt_connected": subscriber.connected,
                    "counts": store.counts(),
                    "storage": storage,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
            )
    finally:
        subscriber.stop()
        store.close()


if __name__ == "__main__":
    run()
