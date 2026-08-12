# SenseL Tier 2 Site Node

`sensel-site` 是與 R2C Edge Agent 分開部署、分開 process 的 Tier 2 service。它接收同一 site 多台 Edge 的 `TrustEpisode` protobuf，保存可重播 receipt，建立 immutable dataset lineage，並只透過簽章後的 trainer inbox 交付訓練資料。

P3-B 提供隔離的 XGBoost trainer、trainer-key signed UBJSON candidate 與獨立 validator /
quarantine。它仍不執行 Flower round、不訓練 Tiny LSTM，也沒有 candidate activation path。
Isolation Forest 維持 Edge local baseline，Tiny LSTM 等完整 sequence materialization 後再開放。

## Required environment

| Variable | Purpose |
|---|---|
| `SENSEL_SITE_TENANT_ID` | 固定 tenant scope |
| `SENSEL_SITE_ID` | 固定 site scope |
| `SENSEL_SITE_NODE_ID` | Site node identity |
| `SENSEL_SITE_MQTT_*` | MQTT v5 broker、mTLS 與 persistent session |
| `SENSEL_SITE_SIGNING_KEY_PATH` | Ed25519 private key secret mount |
| `SENSEL_SITE_SIGNING_KEY_ID` | 可稽核 key identity |
| `SENSEL_SITE_TRAINER_SIGNING_KEY_ID` | 與 Site key 分離的 candidate signer identity |

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

## P3-B worker workflow

建立 job 後執行：

```text
make train-site JOB_ID=trainer-<sha256>
make validate-site JOB_ID=trainer-<sha256>
```

Trainer 只讀獨立 inbox volume、只寫 candidate volume；validator 只讀 inbox/candidate、只寫
validated/quarantine volume。兩者均使用 `network_mode=none`。Validated result 只是 audit
decision，不會寫入 artifact cache 的 active state，也不會觸發 Edge 或 Control Plane distribution。

完整邊界與 key provisioning 見 `docs/sensel-p3b-xgboost-candidate.md`。
