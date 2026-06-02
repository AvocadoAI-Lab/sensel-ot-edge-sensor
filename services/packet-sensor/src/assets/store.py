"""Persistent learned-state store (SQLite).

The detector's first-seen memory (known MACs/IPs/pairs/ports, MAC<->IP bindings,
observed GOOSE keys and MMS client->IED pairs) normally lives only in RAM, so a
restart makes everything look "new" again and replays a storm of novelty alerts.
Persisting it across restarts fixes that and also seeds the candidate baseline
exported during commissioning.

Load/save are idempotent and tolerant of a missing/partial DB.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


class StateStore:
    def __init__(self, db_path: str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS learned_set (
                category TEXT NOT NULL,
                value    TEXT NOT NULL,
                PRIMARY KEY (category, value)
            );
            CREATE TABLE IF NOT EXISTS learned_map (
                kind TEXT NOT NULL,
                k    TEXT NOT NULL,
                v    TEXT NOT NULL,
                PRIMARY KEY (kind, k)
            );
            """
        )
        self._conn.commit()

    def load(self, inventory, iec) -> None:
        """Populate in-memory detector state from the DB (additive)."""
        try:
            set_rows = self._conn.execute("SELECT category, value FROM learned_set").fetchall()
            map_rows = self._conn.execute("SELECT kind, k, v FROM learned_map").fetchall()
        except sqlite3.Error:
            logger.exception("Failed to load learned state")
            return

        targets = {
            "mac": inventory.known_macs,
            "ip": inventory.known_ips,
            "pair": inventory.known_pairs,
            "port": inventory.known_dst_ports,
            "goose": iec.known_goose,
            "mms_pair": iec.known_mms_pairs,
        }
        for category, value in set_rows:
            bucket = targets.get(category)
            if bucket is not None:
                bucket.add(value)
        for kind, k, v in map_rows:
            if kind == "mac_to_ip":
                inventory.mac_to_ip[k] = v
            elif kind == "ip_to_mac":
                inventory.ip_to_mac[k] = v

        logger.info(
            "Loaded learned state: %d macs, %d ips, %d pairs, %d ports, %d goose, %d mms pairs",
            len(inventory.known_macs), len(inventory.known_ips), len(inventory.known_pairs),
            len(inventory.known_dst_ports), len(iec.known_goose), len(iec.known_mms_pairs),
        )

    def save(self, inventory, iec) -> None:
        """Upsert current detector state to the DB."""
        sets: list[tuple[str, str]] = []
        sets += [("mac", v) for v in inventory.known_macs]
        sets += [("ip", v) for v in inventory.known_ips]
        sets += [("pair", v) for v in inventory.known_pairs]
        sets += [("port", v) for v in inventory.known_dst_ports]
        sets += [("goose", v) for v in iec.known_goose]
        sets += [("mms_pair", v) for v in iec.known_mms_pairs]

        maps: list[tuple[str, str, str]] = []
        maps += [("mac_to_ip", k, v) for k, v in inventory.mac_to_ip.items()]
        maps += [("ip_to_mac", k, v) for k, v in inventory.ip_to_mac.items()]

        try:
            self._conn.executemany(
                "INSERT OR IGNORE INTO learned_set (category, value) VALUES (?, ?)", sets
            )
            self._conn.executemany(
                "INSERT OR REPLACE INTO learned_map (kind, k, v) VALUES (?, ?, ?)", maps
            )
            self._conn.commit()
        except sqlite3.Error:
            logger.exception("Failed to save learned state")

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
