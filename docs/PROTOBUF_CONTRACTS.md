# SenseL Edge Protobuf Contracts

Tier 1 與 Tier 2 共用此 repository。跨層 canonical `.proto` 由 `AvocadoAI-Lab/AristaConnector` 的 `contracts/proto` 管理；此處的 `sensel` package 是 contract version `0.1.0` 的 Python bindings。

## 🏗️ P0 整合狀態

- `src/contracts/security_event_codec.py` 可將既有 security event dictionary 編碼為 `sensel.security.v1.SecurityEvent`。
- `sensel/CONTRACT_MANIFEST.json` 與 canonical golden fixture 會驗證 descriptor 及 Edge encoder 的 byte-level compatibility。
- 目前 MQTT publisher 仍只送既有 JSON，production behavior 未改變。
- 下一階段才加入 v2 protobuf topic、content type、dual-publish parity 與 rollback flag。
- `sensel.device.v1` 預留 EdgeX inventory 與 desired/observed state reconciliation。
- `sensel.federation.v1` 只承載 round policy 與 artifact manifest；Flower 維持 training transport。

> [!WARNING]
> 不要直接編輯 `sensel/**/**_pb2.py`。先修改 AristaConnector canonical proto，完成 breaking check，再以固定工具版本重新產碼。

## 🧪 本地驗證

從 `services/sensel-edge-agent` 執行 codec 測試：

```bash
pytest -q tests/test_security_event_codec.py
```

測試涵蓋 typed evidence、stable event identity、deterministic serialization 與風險分數邊界。
