# SenseL Tier 2 Site Node

`sensel-site` 是與 R2C Edge Agent 分開部署、分開 process 的 Tier 2 service。它接收同一 site 多台 Edge 的 `TrustEpisode` protobuf，保存可重播 receipt，建立 immutable dataset lineage，並只透過簽章後的 trainer inbox 交付訓練資料。

P3-A 不執行 Flower round、沒有 federated network client，也不訓練 Tiny LSTM。現階段 trainer boundary 只允許 XGBoost tabular candidate；Isolation Forest 維持 Edge local baseline，Tiny LSTM 等完整 sequence materialization 後再開放。

## Required environment

| Variable | Purpose |
|---|---|
| `SENSEL_SITE_TENANT_ID` | 固定 tenant scope |
| `SENSEL_SITE_ID` | 固定 site scope |
| `SENSEL_SITE_NODE_ID` | Site node identity |
| `SENSEL_SITE_MQTT_*` | MQTT v5 broker、mTLS 與 persistent session |
| `SENSEL_SITE_SIGNING_KEY_PATH` | Ed25519 private key secret mount |
| `SENSEL_SITE_SIGNING_KEY_ID` | 可稽核 key identity |

Production 預設要求 MQTT mTLS。Lab 若需停用 TLS，必須同時設定 `SENSEL_SITE_ENV=lab`；production 不接受 insecure TLS。

Broker ACL 以 client certificate CN 作 username。每台 Edge certificate 使用獨立 CN，ACL 必須逐 sensor 明列唯一 write topic；Site subscriber 使用獨立 CN 與明確 tenant/site read ACL。部署前從 `mosquitto.acl.example` 產生 secret `site.acl`，不可直接以 wildcard cross-tenant ACL 上線。

Site signing private key 必須是 Ed25519、不可為 symlink，權限必須為 `0600` 或更嚴格，且容器 UID `10001` 必須可讀。Dataset manifest 同時保存 feature contract ID、version 與 canonical definition SHA-256。

## Dataset workflow

```text
python -m sensel_site.cli dataset-create \
  --feature-contract ot-window-v1 \
  --label-source fusion_decision \
  --retention training-short

python -m sensel_site.cli dataset-export <dataset-id>

python -m sensel_site.cli trainer-prepare <dataset-id> \
  --algorithm xgboost \
  --model-id ot-xgb \
  --base-model-version 0.1.0 \
  --feature-contract ot-window-v1
```

Dataset export 包含 `manifest.json`、`manifest.sig` 與 `samples.jsonl`。Trainer inbox 只取得這三個 read-only 檔案和 signed request，不掛載 Site SQLite、EdgeX、PCAP 或 Tier 1 runtime data。
