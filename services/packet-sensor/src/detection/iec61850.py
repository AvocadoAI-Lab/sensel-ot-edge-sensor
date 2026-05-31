"""IEC 61850 detection rules OT-011 ~ OT-018."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.detection.models import SecurityEvent, utc_now_iso
from src.parser.l7.iec61850.goose import GooseFrame
from src.parser.l7.iec61850.mms import MmsObservation


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
        if prev is not None:
            jump = abs(frame.st_num - prev)
            if frame.st_num < prev or jump > self._threshold("goose_stnum_jump_max", 100):
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
                        },
                    )
                )
        self.last_stnum[key] = frame.st_num
        return events

    def evaluate_mms(self, obs: MmsObservation) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        ied_ip = obs.dst_ip if obs.dst_port == 102 else obs.src_ip
        client_ip = obs.src_ip if obs.dst_port == 102 else obs.dst_ip
        pair = f"{client_ip}->{ied_ip}:102"

        if pair not in self.known_mms_pairs:
            self.known_mms_pairs.add(pair)
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
