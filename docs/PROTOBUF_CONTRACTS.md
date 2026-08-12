# SenseL Edge Protobuf Contracts

Tier 1 與 Tier 2 共用此 repository。跨層 canonical `.proto` 由 `AvocadoAI-Lab/AristaConnector` 的 `contracts/proto` 管理；此處的 `sensel` package 是 contract version `0.3.0` 的 Python bindings。

## 🏗️ P0 整合狀態

- `src/contracts/security_event_codec.py` 可將既有 security event dictionary 編碼為 `sensel.security.v1.SecurityEvent`。
- `sensel/CONTRACT_MANIFEST.json` 與 canonical golden fixture 會驗證 descriptor 及 Edge encoder 的 byte-level compatibility。
- Security event 保留既有 JSON；Trust Episode 已支援 JSON／dual／protobuf 與 rollback，P2-A device-management topics 固定使用 protobuf。
- `sensel.device.v1` 提供 EdgeX inventory，以及帶 asset routing、command/report identity、expiry 與 reconcile status 的 desired/observed state reconciliation。
- `sensel.federation.v1` 只承載 round policy 與 artifact manifest；Flower 維持 training transport。

## 🧠 P1-A Feature 與 Episode Foundation

- `config/model/feature-contract.ot-window-v1.json` 固定 11 個 OT window features 的順序、dtype、missing-value policy、`log1p` normalization、60-frame sequence 與 checksum。
- packet-sensor 的 `FeatureSequenceBuilder` 以 sensor/asset/flow entity 分桶，拒絕逆序 timestamp/sequence，並產生 deterministic sequence SHA-256。
- `RiskFusionPolicy` 將可用 detection signals 做 deterministic、versioned fusion；不可用模型會被明確記錄，不會以 `None` 靜默混入分數。
- `TrustEpisode` 將 asset identity、feature sequence、規則/模型 signal、fusion、evidence、supply-chain 與 policy context 封裝成 SLM-independent investigation unit。
- Edge Agent encoder 與 Tier 3 decoder 共用 `trust_episode.v1.bin` golden wire，保證跨 repository byte compatibility。
- Production MQTT 仍維持既有 JSON；protobuf dual-publish、ACK/retry 與 rollback flag 留在後續切片。

> [!WARNING]
> 不要直接編輯 `sensel/**/**_pb2.py`。先修改 AristaConnector canonical proto，完成 breaking check，再以固定工具版本重新產碼。

## 🧪 本地驗證

從 `services/sensel-edge-agent` 執行 codec 測試：

```bash
pytest -q \
  tests/test_contract_manifest.py \
  tests/test_security_event_codec.py \
  tests/test_trust_episode_codec.py
```

測試涵蓋 typed evidence、stable event identity、deterministic serialization、descriptor checksum 與跨層 golden wire。
