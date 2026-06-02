"""IEC 61850 detection rules OT-011 ~ OT-018."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.detection.models import SecurityEvent, utc_now_iso
from src.parser.l7.iec61850.goose import GooseFrame
from src.parser.l7.iec61850.mms import MmsObservation

# GOOSE stNum is an Unsigned32; a legitimate roll-over wraps modulo 2**32.
_STNUM_MOD = 1 << 32


def _utc_now_iso() -> str:
    return utc_now_iso()


@dataclass
class Iec61850Detector:
    site_id: str
    sensor_id: str
    policy: dict
    known_goose: set[str] = field(default_factory=set)
    known_mms_pairs: set[str] = field(default_factory=set)
    alerted_unauthorized_mms: set[str] = field(default_factory=set)
    last_stnum: dict[str, int] = field(default_factory=dict)
    last_goose_seen: dict[str, float] = field(default_factory=dict)
    alerted_goose_silence: set[str] = field(default_factory=set)
    _mms_session_times: list[float] = field(default_factory=list)
    _alerted_mms_rate_until: float = 0.0
    _event_seq: int = 0

    def _next_event_id(self) -> str:
        self._event_seq += 1
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"evt-{day}-61850-{self._event_seq:05d}"

    def _goose_publishers(self) -> list[dict]:
        return self.policy.get("iec61850", {}).get("goose_publishers", [])

    def _mms_ieds(self) -> list[dict]:
        return self.policy.get("iec61850", {}).get("mms_ieds", [])

    def _threshold(self, key: str, default: int) -> int:
        return int(self.policy.get("iec61850", {}).get("thresholds", {}).get(key, default))

    def _match_goose_baseline(self, frame: GooseFrame) -> dict | None:
        for entry in self._goose_publishers():
            mac = entry.get("publisher_mac", "").lower()
            appid = int(entry.get("appid", -1))
            gocb = entry.get("gocb_ref", "")
            if mac and mac != frame.publisher_mac.lower():
                continue
            if appid >= 0 and appid != frame.appid:
                continue
            if gocb and gocb != frame.gocb_ref:
                continue
            return entry
        return None

    def evaluate_goose(self, frame: GooseFrame) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        key = f"{frame.publisher_mac}|{frame.appid}|{frame.gocb_ref}"
        baseline = self._match_goose_baseline(frame)
        if baseline is not None:
            aid = str(baseline.get("asset_id") or baseline.get("gocb_ref") or key)
            self.last_goose_seen[aid] = time.time()

        if key not in self.known_goose:
            self.known_goose.add(key)
            if baseline is None:
                events.append(
                    SecurityEvent(
                        event_id=self._next_event_id(),
                        site_id=self.site_id,
                        sensor_id=self.sensor_id,
                        event_type="GOOSE_NEW_PUBLISHER",
                        severity="medium",
                        rule_id="OT-011",
                        protocol="iec61850-goose",
                        description="New GOOSE publisher observed on mirror port",
                        evidence={
                            "goose_appid": frame.appid,
                            "goose_gocb_ref": frame.gocb_ref,
                            "goose_publisher_mac": frame.publisher_mac,
                            "goose_stnum": frame.st_num,
                            "goose_sqnum": frame.sq_num,
                        },
                    )
                )

        if frame.test and (baseline is None or baseline.get("production", True)):
            events.append(
                SecurityEvent(
                    event_id=self._next_event_id(),
                    site_id=self.site_id,
                    sensor_id=self.sensor_id,
                    event_type="GOOSE_TEST_MODE",
                    severity="high",
                    rule_id="OT-012",
                    protocol="iec61850-goose",
                    asset_id=str(baseline.get("asset_id", "")) if baseline else "",
                    description="GOOSE test bit set on production publisher",
                    risk_score=86,
                    evidence={
                        "goose_appid": frame.appid,
                        "goose_gocb_ref": frame.gocb_ref,
                        "goose_test": True,
                        "goose_stnum": frame.st_num,
                    },
                )
            )

        prev = self.last_stnum.get(key)
        if prev is not None and frame.st_num != prev:
            # Forward distance modulo 2**32: a normal +1 step (and a legitimate
            # Unsigned32 wrap, e.g. 2**32-1 -> 0) stays small, while a replay
            # (rollback to a lower value) shows up as a large forward distance.
            forward = (frame.st_num - prev) % _STNUM_MOD
            threshold = self._threshold("goose_stnum_jump_max", 100)
            if forward > threshold:
                anomaly = "rollback" if frame.st_num < prev else "forward_jump"
                events.append(
                    SecurityEvent(
                        event_id=self._next_event_id(),
                        site_id=self.site_id,
                        sensor_id=self.sensor_id,
                        event_type="GOOSE_STNUM_ANOMALY",
                        severity="medium",
                        rule_id="OT-013",
                        protocol="iec61850-goose",
                        description="GOOSE stNum anomaly detected",
                        evidence={
                            "goose_appid": frame.appid,
                            "goose_gocb_ref": frame.gocb_ref,
                            "goose_stnum": frame.st_num,
                            "previous_stnum": prev,
                            "forward_delta": forward,
                            "anomaly": anomaly,
                        },
                    )
                )
        self.last_stnum[key] = frame.st_num
        return events

    def evaluate_goose_silence(self, now: float | None = None) -> list[SecurityEvent]:
        """OT-017 — a baselined production GOOSE publisher that was being seen
        stops publishing for longer than its max_silence_sec (IED offline).

        Absence-based: call once per feature window. Only publishers seen at
        least once are tracked, so an entirely absent baseline entry does not
        raise noise. The alert clears (and can re-fire) when traffic resumes.
        """
        events: list[SecurityEvent] = []
        now = now if now is not None else time.time()
        for entry in self._goose_publishers():
            if not entry.get("production", True):
                continue
            max_silence = float(entry.get("max_silence_sec", 0) or 0)
            if max_silence <= 0:
                continue
            aid = str(entry.get("asset_id") or entry.get("gocb_ref") or "")
            last = self.last_goose_seen.get(aid)
            if last is None:
                continue
            if (now - last) <= max_silence:
                self.alerted_goose_silence.discard(aid)
                continue
            if aid in self.alerted_goose_silence:
                continue
            self.alerted_goose_silence.add(aid)
            events.append(
                SecurityEvent(
                    event_id=self._next_event_id(),
                    site_id=self.site_id,
                    sensor_id=self.sensor_id,
                    event_type="GOOSE_SILENCE",
                    severity="high",
                    rule_id="OT-017",
                    protocol="iec61850-goose",
                    asset_id=aid,
                    description="GOOSE publisher silent beyond max_silence_sec (IED offline)",
                    risk_score=88,
                    evidence={
                        "asset_id": aid,
                        "goose_gocb_ref": entry.get("gocb_ref", ""),
                        "silence_sec": round(now - last, 1),
                        "max_silence_sec": max_silence,
                    },
                )
            )
        return events

    def evaluate_mms(self, obs: MmsObservation) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        ied_ip = obs.dst_ip if obs.dst_port == 102 else obs.src_ip
        client_ip = obs.src_ip if obs.dst_port == 102 else obs.dst_ip
        pair = f"{client_ip}->{ied_ip}:102"

        if pair not in self.known_mms_pairs:
            self.known_mms_pairs.add(pair)

            # OT-015 — burst of new MMS sessions per minute (scan / brute / storm).
            now = time.time()
            self._mms_session_times.append(now)
            cutoff = now - 60.0
            self._mms_session_times = [t for t in self._mms_session_times if t >= cutoff]
            rate_threshold = self._threshold("mms_new_sessions_per_min", 20)
            if len(self._mms_session_times) > rate_threshold and now >= self._alerted_mms_rate_until:
                self._alerted_mms_rate_until = now + 60.0
                events.append(
                    SecurityEvent(
                        event_id=self._next_event_id(),
                        site_id=self.site_id,
                        sensor_id=self.sensor_id,
                        event_type="MMS_SESSION_RATE_ANOMALY",
                        severity="medium",
                        rule_id="OT-015",
                        protocol="iec61850-mms",
                        src_ip=client_ip,
                        dst_ip=ied_ip,
                        dst_port=102,
                        description="Abnormal rate of new MMS sessions",
                        evidence={
                            "new_sessions_last_min": len(self._mms_session_times),
                            "threshold_per_min": rate_threshold,
                        },
                    )
                )

            if not self._is_known_mms_pair(client_ip, ied_ip):
                events.append(
                    SecurityEvent(
                        event_id=self._next_event_id(),
                        site_id=self.site_id,
                        sensor_id=self.sensor_id,
                        event_type="MMS_NEW_CLIENT",
                        severity="medium",
                        rule_id="OT-014",
                        protocol="iec61850-mms",
                        src_ip=client_ip,
                        dst_ip=ied_ip,
                        dst_port=102,
                        description="New MMS client observed connecting to IED",
                        evidence={"ied_ip": ied_ip, "mms_pdu_type": obs.pdu_type},
                    )
                )

        if obs.pdu_type == "write" and not self._is_allowed_mms_client(client_ip, ied_ip):
            events.append(
                SecurityEvent(
                    event_id=self._next_event_id(),
                    site_id=self.site_id,
                    sensor_id=self.sensor_id,
                    event_type="MMS_WRITE_ANOMALY",
                    severity="high",
                    rule_id="OT-016",
                    protocol="iec61850-mms",
                    src_ip=client_ip,
                    dst_ip=ied_ip,
                    dst_port=102,
                    description="Unexpected MMS write from non-baselined client",
                    risk_score=88,
                    evidence={"ied_ip": ied_ip, "mms_pdu_type": "write"},
                )
            )

        if (
            not self._is_allowed_mms_client(client_ip, ied_ip)
            and self._ied_in_baseline(ied_ip)
            and pair not in self.alerted_unauthorized_mms
        ):
            self.alerted_unauthorized_mms.add(pair)
            events.append(
                SecurityEvent(
                    event_id=self._next_event_id(),
                    site_id=self.site_id,
                    sensor_id=self.sensor_id,
                    event_type="MMS_UNAUTHORIZED_CLIENT",
                    severity="high",
                    rule_id="OT-018",
                    protocol="iec61850-mms",
                    src_ip=client_ip,
                    dst_ip=ied_ip,
                    dst_port=102,
                    description="Unauthorized host accessing relay IED over MMS",
                    risk_score=90,
                    evidence={"ied_ip": ied_ip, "mms_pdu_type": obs.pdu_type},
                )
            )
        return events

    def _ied_in_baseline(self, ied_ip: str) -> bool:
        return any(entry.get("ied_ip") == ied_ip for entry in self._mms_ieds())

    def _is_known_mms_pair(self, client_ip: str, ied_ip: str) -> bool:
        for entry in self._mms_ieds():
            if entry.get("ied_ip") != ied_ip:
                continue
            if client_ip in entry.get("allowed_mms_clients", []):
                return True
        return False

    def _is_allowed_mms_client(self, client_ip: str, ied_ip: str) -> bool:
        for entry in self._mms_ieds():
            if entry.get("ied_ip") != ied_ip:
                continue
            return client_ip in entry.get("allowed_mms_clients", [])
        return False
